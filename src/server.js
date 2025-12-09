import express from "express";
import dotenv from "dotenv";
import fs from "fs/promises";
import path from "path";
import {
  ensureKeys,
  decryptSeedAndStore,
  readPublicKey,
  signCommitHash,
  encryptWithPubPem,
  DATA_DIR,
} from "./crypto-utils.js";

import { generateOTP, verifyOTP } from "./totp.js";
import { generateHex64Seed } from "./seed-utils.js";
import { sendSeed, encryptWithPublicPem } from "./client-send-seed.js";
dotenv.config();

const app = express();

app.use(express.json({ limit: "1mb" }));

const PORT = Number(process.env.PORT || 8080);

const CRON_DIR = process.env.CRON_DIR || path.resolve("./cron");

(async () => {
  await ensureKeys();
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.mkdir(CRON_DIR, { recursive: true });
})();

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
    const enc = req.body?.seed;
    if (!enc || typeof enc !== "string")
      return res.status(400).json({ error: "missing_seed" });
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
    if (err.message === "seed_missing")
      return res.status(500).json({ error: "seed_unavailable" });
    return res.status(500).json({ error: "internal_error" });
  }
});
app.post("/verify-2fa", async (req, res) => {
  try {
    const code = req.body?.code;
    if (!code) return res.status(400).json({ error: "missing_code" });
    const valid = await verifyOTP(code);
    return res.json({ valid });
  } catch (err) {
    //return res.status(500).json({ error: "seed_unavailable" });
    if (err.message === "invalid_code")
      return res.status(400).json({ error: "invalid_code" });
    console.error("verify-2fa error:", err);
    return res.status(500).json({ error: "internal_error" });
  }
});
app.post("/sign-commit", async (req, res) => {
  try {
    const commitHash = req.body?.commit_hash;
    const instrPubPem = req.body?.instructor_public_key;
    if (!commitHash || typeof commitHash !== "string")
      return res.status(400).json({ error: "missing_commit_hash" });
    if (!/^[0-9a-fA-F]+$/.test(commitHash))
      return res.status(400).json({ error: "invalid_commit_hash" });
    const sig = await signCommitHash(commitHash);
    const signature_b64 = sig.toString("base64");

    if (instrPubPem && typeof instrPubPem === "string") {
      const enc = await encryptWithPubPem(instrPubPem, sig);
      return res.json({
        signature_b64,
        encrypted_signature_b64: enc.toString("base64"),
      });
    } else {
      return res.json({ signature_b64 });
    }
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
    res.json(error.message);
  }
});

app.get("/", (req, res) => {
  res.write(`<h1>Hello there server is already running</h1>`);
  res.send();
});

app.listen(PORT, (req, res) => {
  console.log("Server is running on the port: " + PORT);
});
