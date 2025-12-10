import express from "express";
import dotenv from "dotenv";
import fs from "fs/promises";
import path from "path";
import fetch from "node-fetch";
import {
  ensureKeys,
  decryptSeedAndStore,
  readPublicKey,
  signCommitHash,
  encryptWithPubPem,
  DATA_DIR,
  PUBLIC_KEY_PATH,
  PRIVATE_KEY_PATH,
} from "./crypto-utils.js";
import { generateOTP, verifyOTP } from "./totp.js";
import { generateHex64Seed } from "./seed-utils.js";
import { encryptWithPublicPem } from "./client-send-seed.js";

dotenv.config();

const app = express();
app.use(express.json({ limit: "1mb" }));

const PORT = Number(process.env.PORT || 8080);
const CRON_DIR = process.env.CRON_DIR || path.resolve("./cron");

app.get("/public-key", async (req, res) => {
  try {
    const pub = await readPublicKey();
    res.type("text/plain").send(pub);
  } catch (err) {
    res.status(500).json({ error: "could_not_read_public_key" });
  }
});

app.post("/decrypt-seed", async (req, res) => {
  try {
    const enc = req.body?.encrypted_seed;
    if (!enc || typeof enc !== "string") {
      return res.status(400).json({ error: "missing_seed" });
    }
    const stored = await decryptSeedAndStore(enc);
    return res.json({
      status: "ok",
      stored_seed_preview: stored.slice(0, 8) + "...",
    });
  } catch (err) {
    console.error("decrypt-seed error:", err.message);
    return res
      .status(500)
      .json({ error: "decryption_failed", details: err.message });
  }
});

app.get("/generate-2fa", async (req, res) => {
  try {
    const obj = await generateOTP();
    return res.json({ code: obj.code, valid_for: obj.valid_for });
  } catch (err) {
    if (err.message === "seed_missing") {
      return res.status(500).json({ error: "seed_unavailable" });
    }
    return res.status(500).json({ error: "internal_error" });
  }
});

app.post("/verify-2fa", async (req, res) => {
  try {
    const code = req.body?.code;
    if (!code) {
      return res.status(400).json({ error: "missing_code" });
    }
    const valid = await verifyOTP(code);
    return res.json({ valid });
  } catch (err) {
    if (err.message === "invalid_code") {
      return res.status(400).json({ error: "invalid_code" });
    }
    console.error("verify-2fa error:", err);
    return res.status(500).json({ error: "internal_error" });
  }
});

app.post("/sign-commit", async (req, res) => {
  try {
    const commitHash = req.body?.commit_hash;
    const instrPubPem = req.body?.instructor_public_key;
    if (!commitHash || typeof commitHash !== "string") {
      return res.status(400).json({ error: "missing_commit_hash" });
    }
    if (!/^[0-9a-fA-F]+$/.test(commitHash)) {
      return res.status(400).json({ error: "invalid_commit_hash" });
    }
    const sig = await signCommitHash(commitHash);
    const signature_b64 = sig.toString("base64");

    if (instrPubPem && typeof instrPubPem === "string") {
      const enc = await encryptWithPubPem(instrPubPem, sig);
      return res.json({
        signature_b64,
        encrypted_signature_b64: enc.toString("base64"),
      });
    }

    return res.json({ signature_b64 });
  } catch (err) {
    console.error("sign-commit error:", err.message);
    return res
      .status(500)
      .json({ error: "signing_failed", details: err.message });
  }
});

app.get("/req-seed", async (req, res) => {
  try {
    const publicPemKey = await readPublicKey();
    const genSeed = generateHex64Seed();
    const seed = encryptWithPublicPem(publicPemKey, genSeed);
    res.status(200).json({ seed });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

async function getEncryptedKey() {
  const publicKey = await fs.readFile(PUBLIC_KEY_PATH, "utf8");
  const payload = {
    student_id: "22MH1A4204",
    github_repo_url: "https://github.com/Shankars57/secure-auth",
    public_key: `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqFAokSnywT1c34lAVz5m
vmaRHzyukGXQytBVNUJH4s2Gn/99PPlbdXo65IGu87drCIDjrFL9LvUj9ROEQIrS
5+6s0K2+KAKQgRxznjcbJj1ppfWn2KHjo7huKm9AhnpxRAZbJkDwu87e3IeMkWYH
Y9C2Y/Gv9Y+K7X5Gk01GMMAg2Nr8J9QxdmTHrm63EiBkXsjiyeEjDZ2YOy0OHgKF
/GylhMXyXK0+aeo09WKCiKI6uSoR+nspws9TgtBJyajF4g17eQjJ1XLi+X+4Q2aB
44uk6GB/dihDEjM1PEmpSr5kOWHpNTdjFgyvzZuCKdz1Oeb6OVWadZI1AjTJ/YX7
4tmf2G3G7sQ23PTgNv9HGSWIwe8kjGpKF4jJ0aHc0NQDJjNFu7oIbctScnXd86cV
Sy+JCwmCCPIocbde2UlOAvTxAJCX9ogYWtuA0F0MjZ3NL6ZUeHi/h4F5PgwY8C8v
eh+GeBoxXQrcWFYBCrKCYN60plMb5HITu0PQuhcpzCcSOslfPF2LxFmI5UWNH4um
C4YPyQDjkicWYhMzGLig/aFdLYkJxEK5ysf09+jArPWOblOamHnRZSvyTCcOn66E
8fQzjSszqT44tP1gTYvvPfe1aFJmy2h2rdEqToeBHE/uGzCzrOv4onDSRWigcA/t
C4aaeHSjTrNfEIIyISBcQC8CAwEAAQ==
-----END PUBLIC KEY-----`,
  };

  const resp = await fetch(
    "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws/",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }
  );
 
  

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`HTTP ${resp.status} - ${text}`);
  }

  const encryptSeed = await resp.json();
  await fs.writeFile(
    path.join(DATA_DIR, "encrypted_seed.txt"),
    encryptSeed.encrypted_seed
  );
  return encryptSeed;
}

app.get("/", (req, res) => {
  res.send("<h1>Hello there server is already running</h1>");
});

(async () => {
  try {
    await ensureKeys();
    await fs.mkdir(DATA_DIR, { recursive: true });
    await fs.mkdir(CRON_DIR, { recursive: true });
    await getEncryptedKey();
    app.listen(PORT, () => {
      console.log("Server is running on the port: " + PORT);
    });
  } catch (err) {
    console.error("Server startup failed:", err);
    process.exit(1);
  }
})();
