# Abuse-Resistant OTP System

Live deployment: https://sailaxman-nestack-submission.onrender.com. Open https://sailaxman-nestack-submission.onrender.com/docs to try the API in the browser.

## Overview

OTP login backend with POST /auth/send and POST /auth/verify. Python + FastAPI. In-memory storage. No auth, JWT or rate-limit libraries; security logic uses only the standard library. Runtime dependencies: fastapi and uvicorn. pytest and httpx are for tests.

## Setup and run

To set up the project locally:

1. Clone the repository.
2. Create and activate a virtual environment.
3. Run `pip install -r requirements.txt`.
4. Copy `.env.example` to `.env` (Windows: `copy .env.example .env`, macOS/Linux: `cp .env.example .env`).
5. Generate a secret using `python -c "import secrets; print(secrets.token_hex(32))"` and put it in `OTP_SECRET` in the `.env` file.
6. Run the server using `uvicorn app.main:app`.
7. Run the tests using `python -m pytest -v`.

Note: The application refuses to start if `OTP_SECRET` is missing. A small built-in reader loads the `.env` file for local use.

## OTP delivery

OTPs are printed to the server console (via `deliver_otp` in `app/main.py`) instead of sent by SMS/email, as the assignment allows. On the deployed version, read them in the hosting platform's logs. The live service runs on a free tier that sleeps when idle. The first request after a pause can take up to a minute, and a restart clears all in-memory OTPs and rate limits. A real provider would replace `deliver_otp` only. To see OTPs on the live service, open the Render Logs tab, turn Live tail on, and search for DELIVER_OTP.

## Deployment

The app is hosted with the start command `uvicorn app.main:app --host 0.0.0.0 --port $PORT` and `OTP_SECRET` is set as an environment variable on the host (never committed). Run a single instance with a single worker.

## API

### POST /auth/send

Request body:
```json
{
  "identifier": "user@example.com"
}
```

Example `curl`:
```bash
curl -X POST https://sailaxman-nestack-submission.onrender.com/auth/send \
  -H "Content-Type: application/json" \
  -d '{"identifier": "user@example.com"}'
```
In Windows PowerShell, put the JSON in a file and use -d @file.json, or use the /docs page.

Example responses:
- 200 OK: `{"message": "OTP sent to user@example.com"}`
- 400 Bad Request: `{"message": "Invalid identifier"}`
- 429 Too Many Requests: `{"message": "Too many requests, try again later"}`

### POST /auth/verify

Request body:
```json
{
  "identifier": "user@example.com",
  "code": "123456"
}
```

Example `curl`:
```bash
curl -X POST https://sailaxman-nestack-submission.onrender.com/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"identifier": "user@example.com", "code": "123456"}'
```
In Windows PowerShell, put the JSON in a file and use -d @file.json, or use the /docs page.

Example responses:
- 200 OK: `{"message": "Verified", "session_token": "<token>"}`
- 400 Bad Request: `{"message": "Invalid or expired code", "attempts_remaining": 4}`
- 400 Bad Request: `{"message": "Invalid or expired code"}`
- 429 Too Many Requests: `{"message": "Too many failed attempts. Request a new code."}`

## CSPRNG

OTP generation uses `secrets.randbelow(1_000_000)`, zero-padded to 6 digits. The `random` module is not used.

## Hashing

The OTP hash is an HMAC-SHA256 keyed with `OTP_SECRET`, using the message `identifier:code`, and compared with `hmac.compare_digest`. Why: a 6-digit code has only 1,000,000 values, so a plain SHA-256 or bcrypt of it can be brute-forced offline from a leaked table. HMAC with a secret kept outside the data store stops that. Measured on my laptop in pure Python: plain SHA-256 over all 1,000,000 codes took 1.21 s, HMAC took 3.53 s (attacker who has the secret). `OTP_SECRET` is a server-side pepper; it is hashing, not encryption. Only the server ever holds the secret.

## Rate limits

Both limits are per identifier (not per IP), in memory, guarded by one `threading.Lock`. 
- Send limit: max 3 per 600 s sliding window, timestamps in `send_log`, kept separate from the OTP record so a resend never resets it. Entries leave the list only when older than 600 s; rejected requests are not recorded. 
- Attempt limit: 5 wrong attempts per OTP locks it (429), checked before the code is compared, so a correct code after lockout still fails.

## Verification rules

Verification is checked in this exact order: no record, used, expired, locked, compare. Expiry 600 s, rejected when `now >= expires_at`. `used` set true on success, so reuse returns 400. Session token: `secrets.token_urlsafe(32)`, only its SHA-256 is stored.

## Decisions

- The 5th wrong attempt returns 429, and so does everything after.
- Expired returns 400 even if the OTP was already locked.
- A new OTP resets the attempt counter (the spec ties the counter to the current OTP; this is my interpretation). Each OTP is a fresh random code, so earlier guesses give no information. With 3 sends per window the chance of guessing a code in one window is about 0.0015% (3 independent tries of 5 guesses). Carrying attempts across resends was rejected because it lets an attacker lock a victim out.
- A successful verify does not reset the send limit.
- Window boundary: timestamps up to 600 s old still count (<=).
- Same message for unknown identifier, wrong code, used, expired.

## Leaked table analysis

Table only: attacker reads identifiers (personal data), `created_at`, `expires_at`, `used`, `attempts` and the HMAC hashes. They cannot recover codes because `OTP_SECRET` is not in the table, so they cannot compute candidate hashes to compare.

Table plus `OTP_SECRET`: they can compute the HMAC for all 1,000,000 codes and find the match offline (about 3.5 s in my benchmark). The attempt lockout and send limit do not apply because this never touches the API. A recovered code is still valid only until `expires_at` and works only once.

Session tokens: only SHA-256 hashes are stored, and tokens are 256-bit random values, so a leak does not allow logging in.

## Tests

14 pytest tests, one per rule, time patched not slept. I also checked them by temporarily breaking the code (lockout at 6, removing `used=True`, `>=` changed to `>`, removing pruning) and each change made a test fail.

## Known limitations

In-memory state is lost on restart and never cleaned up; single instance and single worker only (production would use Redis with TTLs); the send limit is a rolling window, so a sustained attacker can obtain up to 432 OTPs per identifier per day with 5 guesses each (about 0.2% chance of one success per day), and production would add per-IP limits, CAPTCHA, longer cooldowns and alerting; no secret rotation; +91... vs 91... and a+1@x.com vs a@x.com count as different identifiers; delivery risks (SIM swap, email takeover, phishing) are out of scope; missing JSON fields return FastAPI's default 422. (a) printing the OTP to the console is a development stand-in; a real deployment must never log OTPs. (b) Session tokens have no expiry and no endpoint validates them; this is outside the assignment's scope.
