# secure-auth (Node.js) - Full Submission

This project implements an authentication microservice that meets the assignment requirements:

- RSA-4096 key generation with public exponent 65537
- RSA-OAEP (SHA-256) seed decryption (base64 input)
- Convert 64-character hex seed to base32 before TOTP generation
- TOTP (SHA-1, 30s, 6-digit) generation and verification (±1 period)
- RSA-PSS (SHA-256) signing of commit hashes and optional encryption of signature with instructor public key (OAEP SHA-256)
- Docker multi-stage build with cron installation, UTC timezone, ports, and persistent volumes
- Cron job running every minute that writes current TOTP to `/cron/last_code.txt`

## Project layout

```
secure-auth/
├─ package.json
├─ Dockerfile
├─ docker-compose.yml
├─ crontab
├─ README.md
├─ src/
│  ├─ server.js
│  ├─ crypto-utils.js
│  ├─ totp-utils.js
│  ├─ cron_runner.js
|  ├─ client-send-seed.js (Run separately for seed generation for testing (nodemon client-send-seed.js))
|  ├─ seed-utils.js (Seed generating function)
├─ data/    (volume)
└─ cron/    (volume)
```

## Quick local run (WSL / Ubuntu)

1. Install Node 20 (use NodeSource) and required tools.
2. `npm ci`
3. `mkdir data cron`
4. `DATA_DIR=./data CRON_DIR=./cron PORT=8080 node src/server.js`

## Docker build & run

```bash
docker build -t secure-auth:latest .
docker run --rm -p 8080:8080 -v $(pwd)/data:/data -v $(pwd)/cron:/cron secure-auth:latest
```

## Endpoints

- GET /public-key
- GET /req-seed 
- POST /decrypt-seed { "seed": "<base64>" }
- GET /generate-2fa
- POST /verify-2fa { "code": "123456" }
- POST /sign-commit { "commit_hash":"<hex>", "instructor_public_key":"<PEM>" }

## Notes

- The server stores student keys at `/data/student_private.pem` and `/data/student_public.pem` and the decrypted seed at `/data/seed.txt`.
- Cron writes to `/cron/last_code.txt` every minute in UTC ISO format.
- Ensure `crontab` file uses LF endings before building the Docker image.
