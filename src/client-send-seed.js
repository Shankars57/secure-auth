import fetch from "node-fetch";
import crypto from "crypto";
import dotenv from "dotenv";
import { generateHex64Seed } from "./seed-utils.js";
dotenv.config();
async function getServerPublicKey(urlBase) {
  const r = await fetch(`${urlBase}/public-key`);
  if (!r.ok) throw new Error("could_not_get_public_key");
  return r.text();
}

export function encryptWithPublicPem(publicPem, plaintext) {
  const enc = crypto.publicEncrypt(
    {
      key: publicPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(plaintext, "utf8")
  );
  return enc.toString("base64");
}






export async function sendSeed(urlBase, doPost = true) {
  const seed = generateHex64Seed();
  const pub = await getServerPublicKey(urlBase);
  const encryptedB64 = encryptWithPublicPem(pub, seed);
  const body = { seed: encryptedB64 };
 // console.log("JSON body to send:", JSON.stringify(body));
  if (doPost) {
    const resp = await fetch(`${urlBase}/decrypt-seed`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await resp.json().catch(() => ({ status: resp.status }));
    return data;
  }
  return body;
}
(async () => {
  try {
    
    const urlBase =  "http://localhost:8080";
    await sendSeed(urlBase, true);
  } catch (err) {
    console.error(err);
  }
})();
