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

async function getEncryptedKey() {
  try {
    const payload = {
      student_id: "22MH1A4204",
      github_repo_url: "https://github.com/Shankars57/secure-auth",
      public_key:
        "-----BEGIN PUBLIC KEY-----MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAs4q63j2t2D+NQFFMP2iTLhzdVv7We8RDJO0hQFiLJSxKIy2eNPsCoEg/EH6Q2G3rzdWnKPyhhodo+P+fU+OaTite+3CSrimqSfGIO5RBZTaNymkFuFE2a+NhfSL4SZlsTVppPdCLuEDPSCRqvlTxOi2qVee8lr28D4nJExyXFrxH6l0iJ7Lw0D7lI3ehTmPzuEj0/+xVbeMNz1c0AYD+ouFNUTG/oYS/rcmyZCc5j7Ny+c6md2XFjtFipsqypgDo4r5w1om/fh9JXarr7V78hTOhWW8gMUYlkGbheF8BXoI5VSnCTVkZnA9FgHOl//+XWhst+sQucIVBXH41M4Wrn5M8vsPMBtbFZNE1amjQLgcWiulOjeVJhQABV0ouWLDU5jJllSCBYQfXwhyDEb8bY8kcT+ofSzj9QigNrzRvSkJ60rn1ycCdhkgMwaFrAgoaH7bSxkYN/l+luMbTlU7Uv1k5fI6SHhPoGY3AQZH/qSICeVNks0Pby+IBI2YYHGezOZ1qOBzZxVIFaRggMY9A7ZVEkr1Y3+ke9+F+wxG2c5YncaBSm469wiZ3S0x3Qqe5iltCUa6NsLCx5fWSzUKuxphHaauZMXuNeAYusntPX9hWGuUg3Xm3aYcvroOF4G53XZVReDoem5MXJluTjrBCm2XKYIgPxvOOg/ko24TuO7kCAwEAAQ==-----END PUBLIC KEY-----",
    };

    const resp = await fetch(
      "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws/",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload)
      }
    );

    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new Error(`HTTP ${resp.status} - ${text}`);
    }

    const encryptSeed = await resp.json();
    await fs.writeFile(
      path.join(DATA_DIR, "seed.txt"),
      encryptSeed.encrypted_seed
    );
    return encryptSeed;
  } catch (err) {
    console.error("request failed:", err);
    throw err;
  }
}

getEncryptedKey();

app.get("/", (req, res) => {
  res.write(`<h1>Hello there server is already running</h1>`);
  res.send();
});

app.listen(PORT, (req, res) => {
  console.log("Server is running on the port: " + PORT);
});
