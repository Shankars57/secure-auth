import fs from "fs/promises";
import path from "path";
import crypto from "crypto";
import base32 from "hi-base32";

export const DATA_DIR = path.resolve(process.env.DATA_DIR || "./data");
export const PRIVATE_KEY_PATH = path.join(DATA_DIR, "student_private.pem");
export const PUBLIC_KEY_PATH = path.join(DATA_DIR, "student_public.pem");
export const SEED_PATH = path.join(DATA_DIR, "seed.txt");

export async function ensureKeys() {
  try {
    await fs.access(PRIVATE_KEY_PATH);
    await fs.access(PUBLIC_KEY_PATH);
    return;
  } catch {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 4096,
      publicExponent: 0x10001,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    await fs.mkdir(DATA_DIR, { recursive: true });
    await fs.writeFile(PRIVATE_KEY_PATH, privateKey, { mode: 0o600 });
    await fs.writeFile(PUBLIC_KEY_PATH, publicKey, { mode: 0o644 });
  }
}

export async function decryptSeedAndStore(base64Encrypted) {
  const priv = await fs.readFile(PRIVATE_KEY_PATH, "utf8");
  const encBuf = Buffer.from(base64Encrypted, "base64");
  let decrypted;
  try {
    decrypted = crypto.privateDecrypt(
      {
        key: priv,
        oaepHash: "sha256",
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      encBuf
    );
  } catch (err) {
    throw new Error("decryption_failed: " + err.message);
  }

  let plain = decrypted.toString("utf8").trim();

  if (/^[0-9a-fA-F]{64}$/.test(plain)) {
    const buf = Buffer.from(plain, "hex");
    let b32 = base32.encode(buf).replace(/=+$/g, "");
    b32 = b32.toUpperCase();
    plain = b32;
  }

  await fs.writeFile(SEED_PATH, plain, { mode: 0o600 });
  return plain;
}

export async function signCommitHash(hashHex) {
  if (!/^[0-9a-fA-F]+$/.test(hashHex)) {
    throw new Error("invalid_commit_hash");
  }

  const priv = await fs.readFile(PRIVATE_KEY_PATH, "utf8");
  const buf = Buffer.from(hashHex, "hex");

  const signature = crypto.sign("sha256", buf, {
    key: priv,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  });

  return signature;
}

export function encryptWithPubPem(pubPem, bufferToEncrypt) {
  try {
    return crypto.publicEncrypt(
      {
        key: pubPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      bufferToEncrypt
    );
  } catch (err) {
    throw new Error("public_encrypt_failed: " + err.message);
  }
}

export async function readPublicKey() {
  return fs.readFile(PUBLIC_KEY_PATH, "utf8");
}
