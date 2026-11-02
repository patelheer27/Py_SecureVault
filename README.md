# SecureVault: CSCL Security Project

A Flask web application that combines three security components:

| # | Component | What it protects against |
|---|-----------|--------------------------|
| 1 | **Multi-Factor Authentication (MFA)** | Stolen or guessed passwords |
| 2 | **Video Metadata Sanitizer** | Leaking location, device and time data when sharing videos |
| 3 | **File Integrity Checker (SHA-256)** | Undetected modification of files, and of the stored hashes themselves |

---

## 1. Setup

**Requirements:** Python 3.9+ and ffmpeg.

### Install ffmpeg (needed for the sanitizer)
- **Windows:** `winget install ffmpeg`, then close and reopen the terminal
- **macOS:** `brew install ffmpeg`
- **Ubuntu/Debian:** `sudo apt install ffmpeg`

Check it worked: `ffmpeg -version`

### Install and run
```bash
cd SecureVault
python -m venv venv
# Windows:  venv\Scripts\activate
# Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open **http://127.0.0.1:5000** in your browser.

On first run the app creates `instance/` containing the SQLite database and three secret keys. Never submit or share that folder. Delete it to reset everything.

You need an authenticator app on your phone: Google Authenticator, Microsoft Authenticator or Authy.

---

## 2. Demo script (for presentation / viva)

**MFA**
1. Click *Create account*. Try a weak password like `hello123` to show the password policy rejecting it.
2. Register with a strong password. Scan the QR code with your phone and enter the 6-digit code.
3. Show the 8 recovery codes. Point out that they're stored only as hashes.
4. Sign out, then sign in: password first, then the code from the phone. Point out the countdown bar.
5. **Replay attack:** sign out and sign in again, reusing the same code within 30 s. It is rejected.
6. **Brute force:** enter a wrong password 5 times. The account locks for 5 minutes. All of it shows in the audit log on the Overview page.

**Video Metadata Sanitizer**
1. Run `python make_sample_video.py`. It creates `demo_phone_video.mp4` with fake GPS (India Gate), iPhone make/model, recording time, author and comment.
2. Upload it on the *Metadata Sanitizer* page. The before/after table highlights every sensitive tag in red and shows it as REMOVED.
3. Download the clean video. It plays identically, since no re-encoding happens.
4. Optional proof outside the app: `ffprobe demo_phone_video.mp4` vs `ffprobe sanitized_demo_phone_video.mp4`.
5. Also try a real video from your phone. Videos shared through WhatsApp have usually been stripped already, so transfer the original by cable or Google Drive instead.

**File Integrity Checker**
1. Create `report.txt` with some text. Register it on the *Register baseline* tab.
2. Note *Upload in transit: VERIFIED*: your browser computed SHA-256 itself and it matched the server's hash.
3. Verify the same file: result is **INTACT**.
4. Change **one character** in the file, save and verify again: result is **MODIFIED**. Compare the two hashes: one character changed in the file, yet the hash is completely different (the avalanche effect).
5. Rename the file and verify it: the app recognises the same content under a different name.
6. **Database attack:** click *Simulate DB attack* on a record. This overwrites the stored hash the way an attacker with database access would. The seal now shows **tampered**, and verifying gives **RECORD TAMPERED**. Plain SHA-256 alone cannot detect this; the HMAC seal can.
7. *Check against a known hash:* paste a published SHA-256 checksum (e.g. from a Python or Ubuntu download page) to verify a download.
8. *Export manifest* downloads a JSON list of all fingerprints.

---

## 3. How each component works

### Component 1: MFA
- **Factor 1, something you know:** password hashed with **scrypt** (Werkzeug default; salted and memory-hard). Policy: 10+ characters, mixed case, digit, symbol, must not contain the username.
- **Factor 2, something you have:** **TOTP (RFC 6238)**. Server and phone share a random 160-bit secret. Every 30 s both compute `HMAC-SHA1(secret, time/30)` and truncate it to 6 digits.
- TOTP secret **encrypted at rest** with Fernet (AES-128-CBC + HMAC-SHA256). A database leak alone does not reveal it.
- **Replay protection:** the last used time step is stored; a code can't be used twice.
- **Clock drift:** accepts ±1 time step (±30 s).
- **Recovery codes:** 8 single-use codes, stored only as salted hashes, shown once.
- **Account lockout:** 5 failed password *or* MFA attempts lock the account for 5 minutes.
- **No user enumeration:** unknown usernames get the same error message and the same hashing time.
- The password step expires after 5 minutes if the code isn't entered.
- MFA is **mandatory**: no page is reachable without both factors.

### Component 2: Video Metadata Sanitizer
- `ffprobe` reads all container tags, per-stream tags and chapters, and confirms the upload really contains a video stream (rejects fake files).
- `ffmpeg` remuxes with `-c copy` (lossless, no quality loss) and:
  - `-map_metadata -1` removes global tags (GPS, make, model, creation time, author…)
  - `-map_metadata:s -1` removes per-stream tags (stream creation time, encoder)
  - `-map_chapters -1` removes chapters
  - maps only video/audio/subtitle streams, dropping **hidden data tracks** (e.g. GPS telemetry tracks in action cams and drones, timecode tracks, cover-art attachments)
  - `bitexact` flags stop ffmpeg from writing its own version tag
- The report compares before vs after and flags sensitive keys (location, GPS, make, model, dates, author, software…).
- SHA-256 of the original and sanitized files is shown.
- Uploads are stored under random, unguessable folder names; user filenames never touch the filesystem path. The original is deleted immediately. The clean file is downloadable only by its owner and auto-deleted after 30 minutes.

### Component 3: File Integrity Checker
- SHA-256 is computed in 1 MB chunks (streaming), so large files don't fill memory.
- **HMAC seal:** each record stores `HMAC-SHA256(server_key, user|filename|size|hash|time)`. An attacker who edits the database to make a modified file "match" can't produce a valid seal without the key.
- **Transit check:** the browser computes SHA-256 locally (Web Crypto API) before upload and the server compares it with its own result.
- Hash comparisons use **constant-time** `hmac.compare_digest` (prevents timing attacks).
- Shows the position of the first differing character and the size difference.

### Platform hardening (applies to all components)
- CSRF token on every form
- Strict **Content-Security-Policy** (no inline scripts), `X-Frame-Options: DENY` (clickjacking), `nosniff`, `no-referrer`
- Session cookie: `HttpOnly`, `SameSite=Lax`, 30-minute lifetime, session cleared at login (prevents session fixation)
- Parameterised SQL everywhere (no SQL injection); Jinja auto-escaping (no XSS)
- 500 MB upload limit; file-type allow-list
- Audit log of every security event

---

## 4. Threat → control table (good for the report)

| Threat | Control |
|--------|---------|
| Password stolen by phishing or leak | TOTP second factor |
| Online brute force | Lockout after 5 failures |
| Intercepted OTP reused | Time-step replay protection |
| Database dump | scrypt password hashes, encrypted TOTP secrets, hashed recovery codes |
| Lost phone | Single-use recovery codes |
| Location/identity leak via shared video | Metadata + data-track stripping |
| Malicious "video" upload | ffprobe validation, extension allow-list, random storage names |
| File tampered after storage | SHA-256 baseline comparison |
| Attacker edits the stored hash too | HMAC-SHA256 seal |
| Upload altered in transit | Browser vs server hash comparison |
| CSRF / XSS / clickjacking | CSRF tokens, CSP, auto-escaping, frame-deny |

---

## 5. Limitations (state these honestly; examiners respect it)
- **Runs over HTTP locally.** In production it must be behind HTTPS; then set `SV_HTTPS=1` so cookies are marked Secure.
- **Keys sit on the same disk as the database.** A full server compromise exposes both. Production would use a key vault or HSM.
- **The sanitizer removes metadata, not content.** Faces, number plates, street signs or audio in the video itself are untouched. Some encoders (e.g. x264) also embed a settings string inside the video bitstream that a lossless remux can't remove without re-encoding.
- **SHA-256 detects change but can't say who changed the file or restore it.** That needs digital signatures (e.g. RSA/ECDSA) and backups.
- **TOTP can be phished in real time** by a proxy site. FIDO2/WebAuthn passkeys resist that.
- Lockout is per account, not per IP, so an attacker could deliberately lock someone out (a small denial-of-service risk). Per-IP rate limiting would help.
- SQLite and the Flask dev server are fine for a project, not for many concurrent users.

## 6. Future work
WebAuthn/passkeys, digital signatures for files, per-IP rate limiting, image (EXIF) sanitizing, optional re-encode mode to scrub bitstream metadata, deployment with HTTPS (nginx + gunicorn).

---

## 7. Project structure
```
SecureVault/
├── app.py                  # all backend logic (3 components + hardening)
├── make_sample_video.py    # generates a demo video with fake GPS/device metadata
├── requirements.txt
├── templates/              # Jinja2 HTML pages
│   ├── base.html, auth_base.html, error.html
│   ├── login.html, register.html, mfa_setup.html, mfa_verify.html, recovery_codes.html
│   ├── dashboard.html, sanitizer.html, integrity.html
├── static/
│   ├── style.css
│   └── app.js              # browser SHA-256, tabs, OTP countdown, password meter
└── instance/               # created at runtime: database + secret keys (do not share)
```
