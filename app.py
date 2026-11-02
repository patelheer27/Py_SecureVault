"""
SecureVault - CSCL Security Project
===================================
Three security components in one Flask web application:

  1. Multi-Factor Authentication (MFA)  - password + TOTP (RFC 6238) with
     authenticator app, encrypted TOTP secrets, replay protection,
     one-time recovery codes and account lockout.
  2. Video Metadata Sanitizer           - strips GPS/location, device make &
     model, timestamps, encoder info, chapters and hidden data tracks
     using ffmpeg (lossless stream copy), with a before/after report.
  3. File Integrity Checker (SHA-256)   - registers file fingerprints,
     verifies files later, detects tampering of both the file AND the
     stored hash record (HMAC-SHA256 seal), and checks that the upload
     itself was not altered in transit (browser hash vs server hash).

Run:  python app.py   then open http://127.0.0.1:5000
"""

import functools
import hashlib
import hmac
import io
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import base64
import time
import uuid
from datetime import datetime, timezone, timedelta

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# --------------------------------------------------------------------------
# Paths & keys
# --------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
WORK_DIR = os.path.join(INSTANCE_DIR, "work")
DB_PATH = os.path.join(INSTANCE_DIR, "securevault.db")
os.makedirs(WORK_DIR, exist_ok=True)

APP_NAME = "SecureVault"
HASH_CHUNK = 1024 * 1024            # stream files in 1 MB chunks
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 5
SANITIZED_FILE_TTL = 30 * 60        # delete sanitized output after 30 min
ALLOWED_VIDEO_EXT = {".mp4", ".mov", ".m4v", ".mkv", ".webm", ".avi"}

# Tag names that can identify a person, a device, a place or a time
SENSITIVE_KEYWORDS = ("location", "gps", "iso6709", "make", "model", "creation_time",
                      "date", "author", "artist", "comment", "encoder", "software",
                      "copyright", "title", "description", "com.apple", "com.android",
                      "xyz", "owner", "serial", "lens", "camera")


def _load_or_create_key(filename, generator):
    """Keys live in instance/ (never in source code) and are created on first run."""
    path = os.path.join(INSTANCE_DIR, filename)
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(generator())
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    with open(path, "rb") as f:
        return f.read()


FLASK_SECRET = _load_or_create_key("flask_secret.key", lambda: secrets.token_bytes(32))
TOTP_FERNET = Fernet(_load_or_create_key("totp_encryption.key", Fernet.generate_key))
INTEGRITY_HMAC_KEY = _load_or_create_key("integrity_hmac.key", lambda: secrets.token_bytes(32))

FFMPEG = shutil.which("ffmpeg")
FFPROBE = shutil.which("ffprobe")

# --------------------------------------------------------------------------
# App config (secure defaults)
# --------------------------------------------------------------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=FLASK_SECRET,
    SESSION_COOKIE_HTTPONLY=True,       # JS cannot read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",      # basic CSRF mitigation
    SESSION_COOKIE_SECURE=os.environ.get("SV_HTTPS") == "1",  # set when served over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,  # 500 MB upload limit
)


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT UNIQUE NOT NULL,
    pw_hash          TEXT NOT NULL,
    totp_secret_enc  BLOB,
    mfa_enabled      INTEGER NOT NULL DEFAULT 0,
    last_totp_step   INTEGER,
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until     TEXT,
    created_at       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    code_hash  TEXT NOT NULL,
    used_at    TEXT
);
CREATE TABLE IF NOT EXISTS file_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    filename    TEXT NOT NULL,
    size        INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    seal        TEXT NOT NULL,
    note        TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    username  TEXT,
    event     TEXT NOT NULL,
    detail    TEXT,
    ip        TEXT
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA)


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def audit(event, detail="", username=None):
    if username is None and "uid" in session:
        username = session.get("username")
    db = get_db()
    db.execute("INSERT INTO audit_log (ts, username, event, detail, ip) VALUES (?,?,?,?,?)",
               (now_iso(), username, event, detail[:300], request.remote_addr))
    db.commit()


# --------------------------------------------------------------------------
# Security middleware: CSRF tokens + security headers + housekeeping
# --------------------------------------------------------------------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token
app.jinja_env.globals["APP_NAME"] = APP_NAME


@app.before_request
def before_request():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not sent or not hmac.compare_digest(sent, session.get("_csrf", "")):
            abort(400, description="Invalid or missing CSRF token. Refresh the page and try again.")
    cleanup_old_outputs()


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "object-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.endpoint not in ("static",):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(413)
def too_large(_e):
    flash("File is larger than the 500 MB limit.", "error")
    return redirect(request.referrer or url_for("dashboard"))


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message=e.description), 400


def login_required(view):
    """Full access only after BOTH factors are verified."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("uid") or not session.get("mfa_ok"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    return get_db().execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()


# --------------------------------------------------------------------------
# Component 1: Multi-Factor Authentication
# --------------------------------------------------------------------------
def password_problems(pw, username):
    problems = []
    if len(pw) < 10:
        problems.append("at least 10 characters")
    if not any(c.islower() for c in pw) or not any(c.isupper() for c in pw):
        problems.append("upper and lower case letters")
    if not any(c.isdigit() for c in pw):
        problems.append("a digit")
    if not any(not c.isalnum() for c in pw):
        problems.append("a symbol")
    if username and username.lower() in pw.lower():
        problems.append("must not contain the username")
    return problems


def encrypt_secret(secret):
    return TOTP_FERNET.encrypt(secret.encode())


def decrypt_secret(blob):
    return TOTP_FERNET.decrypt(blob).decode()


def verify_totp(secret, code, last_step):
    """Returns the matched 30-second time step, or None.
    Accepts +/- one step for clock drift; rejects any step already used (replay)."""
    code = (code or "").replace(" ", "").strip()
    if len(code) != 6 or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    current = int(time.time()) // 30
    for step in (current - 1, current, current + 1):
        if hmac.compare_digest(totp.at(step * 30), code):
            if last_step is not None and step <= last_step:
                return None          # code was already used -> replay attempt
            return step
    return None


def qr_data_uri(text):
    img = qrcode.make(text, box_size=6, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def make_recovery_codes(user_id, count=8):
    db = get_db()
    db.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(5).upper()
        code = f"{raw[:5]}-{raw[5:]}"
        codes.append(code)
        db.execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?,?)",
                   (user_id, generate_password_hash(code)))
    db.commit()
    return codes


def use_recovery_code(user_id, code):
    code = (code or "").strip().upper()
    db = get_db()
    rows = db.execute("SELECT * FROM recovery_codes WHERE user_id=? AND used_at IS NULL",
                      (user_id,)).fetchall()
    for row in rows:
        if check_password_hash(row["code_hash"], code):
            db.execute("UPDATE recovery_codes SET used_at=? WHERE id=?", (now_iso(), row["id"]))
            db.commit()
            return True
    return False


def is_locked(user):
    if user["locked_until"]:
        until = datetime.fromisoformat(user["locked_until"])
        if until > datetime.now(timezone.utc):
            return until
    return None


def register_failure(user, stage):
    db = get_db()
    failed = user["failed_attempts"] + 1
    locked_until = None
    if failed >= MAX_FAILED_LOGINS:
        locked_until = (datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        failed = 0
        audit("ACCOUNT_LOCKED", f"{MAX_FAILED_LOGINS} failed {stage} attempts", user["username"])
    db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
               (failed, locked_until, user["id"]))
    db.commit()


def reset_failures(user_id):
    db = get_db()
    db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user_id,))
    db.commit()


# Dummy hash so unknown usernames take the same time as real ones (no user enumeration)
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


@app.route("/")
def index():
    if session.get("uid") and session.get("mfa_ok"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if not (3 <= len(username) <= 32) or not username.replace("_", "").isalnum():
            flash("Username: 3-32 letters, digits or underscore.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif problems := password_problems(password, username):
            flash("Password needs: " + ", ".join(problems) + ".", "error")
        else:
            db = get_db()
            try:
                cur = db.execute(
                    "INSERT INTO users (username, pw_hash, created_at) VALUES (?,?,?)",
                    (username, generate_password_hash(password), now_iso()))
                db.commit()
            except sqlite3.IntegrityError:
                flash("That username is taken.", "error")
                return render_template("register.html")
            session.clear()
            session["setup_uid"] = cur.lastrowid
            session["username"] = username
            audit("REGISTER", "account created, MFA enrollment pending", username)
            return redirect(url_for("mfa_setup"))
    return render_template("register.html")


@app.route("/mfa/setup", methods=["GET", "POST"])
def mfa_setup():
    uid = session.get("setup_uid")
    if not uid:
        return redirect(url_for("login"))
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if user is None or user["mfa_enabled"]:
        session.clear()
        return redirect(url_for("login"))

    # Secret is generated once per enrollment and kept encrypted at rest
    if not user["totp_secret_enc"]:
        db.execute("UPDATE users SET totp_secret_enc=? WHERE id=?",
                   (encrypt_secret(pyotp.random_base32()), uid))
        db.commit()
        user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    secret = decrypt_secret(user["totp_secret_enc"])

    if request.method == "POST":
        step = verify_totp(secret, request.form.get("code"), None)
        if step is None:
            flash("That code didn't match. Check the time on your phone and try again.", "error")
        else:
            db.execute("UPDATE users SET mfa_enabled=1, last_totp_step=? WHERE id=?", (step, uid))
            db.commit()
            codes = make_recovery_codes(uid)
            session.clear()
            session.permanent = True
            session["uid"] = uid
            session["username"] = user["username"]
            session["mfa_ok"] = True
            session["fresh_codes"] = codes
            audit("MFA_ENROLLED", "TOTP verified, 8 recovery codes issued")
            return redirect(url_for("recovery_codes"))

    uri = pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name=APP_NAME)
    pretty = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return render_template("mfa_setup.html", qr=qr_data_uri(uri), secret=pretty)


@app.route("/mfa/recovery-codes")
@login_required
def recovery_codes():
    codes = session.pop("fresh_codes", None)
    if not codes:
        return redirect(url_for("dashboard"))
    return render_template("recovery_codes.html", codes=codes)


@app.route("/mfa/regenerate", methods=["POST"])
@login_required
def regenerate_codes():
    session["fresh_codes"] = make_recovery_codes(session["uid"])
    audit("RECOVERY_CODES_REGENERATED", "old codes invalidated")
    return redirect(url_for("recovery_codes"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user is None:
            check_password_hash(_DUMMY_HASH, password)
            audit("LOGIN_FAIL", "unknown user", username or "-")
            flash("Invalid username or password.", "error")
            return render_template("login.html")
        if (until := is_locked(user)):
            mins = max(1, int((until - datetime.now(timezone.utc)).total_seconds() // 60) + 1)
            audit("LOGIN_BLOCKED", "account locked", username)
            flash(f"Account temporarily locked after too many failed attempts. Try again in ~{mins} min.", "error")
            return render_template("login.html")
        if not check_password_hash(user["pw_hash"], password):
            register_failure(user, "password")
            audit("LOGIN_FAIL", "wrong password (factor 1)", username)
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        session.clear()                     # prevent session fixation
        session["username"] = username
        if not user["mfa_enabled"]:         # registered but never finished enrollment
            session["setup_uid"] = user["id"]
            return redirect(url_for("mfa_setup"))
        session["pending_uid"] = user["id"]
        session["pending_since"] = int(time.time())
        audit("LOGIN_FACTOR1_OK", "password accepted, awaiting TOTP", username)
        return redirect(url_for("mfa_verify"))
    return render_template("login.html")


@app.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    uid = session.get("pending_uid")
    # the password step is only valid for 5 minutes
    if not uid or int(time.time()) - session.get("pending_since", 0) > 300:
        session.clear()
        flash("Please sign in again.", "error")
        return redirect(url_for("login"))
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

    if request.method == "POST":
        if is_locked(user):
            session.clear()
            flash("Account temporarily locked after too many failed attempts.", "error")
            return redirect(url_for("login"))
        method = request.form.get("method", "totp")
        ok = False
        if method == "recovery":
            ok = use_recovery_code(uid, request.form.get("code"))
            detail = "recovery code used"
        else:
            try:
                secret = decrypt_secret(user["totp_secret_enc"])
            except InvalidToken:
                abort(500)
            step = verify_totp(secret, request.form.get("code"), user["last_totp_step"])
            if step is not None:
                db.execute("UPDATE users SET last_totp_step=? WHERE id=?", (step, uid))
                db.commit()
                ok = True
            detail = "TOTP code verified"
        if ok:
            reset_failures(uid)
            username = user["username"]
            session.clear()
            session.permanent = True
            session["uid"] = uid
            session["username"] = username
            session["mfa_ok"] = True
            audit("LOGIN_SUCCESS", detail)
            return redirect(url_for("dashboard"))
        register_failure(user, "MFA")
        audit("MFA_FAIL", f"invalid {method} code (factor 2)", user["username"])
        flash("Invalid or already-used code.", "error")
    return render_template("mfa_verify.html", username=user["username"])


@app.route("/logout", methods=["POST"])
def logout():
    if session.get("uid"):
        audit("LOGOUT", "")
    session.clear()
    flash("Signed out.", "ok")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid = session["uid"]
    codes_left = db.execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL",
                            (uid,)).fetchone()[0]
    files = db.execute("SELECT COUNT(*) FROM file_records WHERE user_id=?", (uid,)).fetchone()[0]
    events = db.execute("SELECT * FROM audit_log WHERE username=? ORDER BY id DESC LIMIT 15",
                        (session["username"],)).fetchall()
    sanitized = db.execute("SELECT COUNT(*) FROM audit_log WHERE username=? AND event='VIDEO_SANITIZED'",
                           (session["username"],)).fetchone()[0]
    return render_template("dashboard.html", codes_left=codes_left, files=files, events=events,
                           sanitized=sanitized, ffmpeg_ok=bool(FFMPEG and FFPROBE))


# --------------------------------------------------------------------------
# Shared helper: streaming SHA-256
# --------------------------------------------------------------------------
def sha256_stream(fileobj):
    h = hashlib.sha256()
    size = 0
    while True:
        chunk = fileobj.read(HASH_CHUNK)
        if not chunk:
            break
        h.update(chunk)
        size += len(chunk)
    return h.hexdigest(), size


def sha256_path(path):
    with open(path, "rb") as f:
        return sha256_stream(f)


# --------------------------------------------------------------------------
# Component 2: Video Metadata Sanitizer
# --------------------------------------------------------------------------
def ffprobe_json(path):
    proc = subprocess.run(
        [FFPROBE, "-v", "error", "-show_format", "-show_streams", "-show_chapters", "-of", "json", path],
        capture_output=True, timeout=120)
    if proc.returncode != 0:
        raise ValueError(proc.stderr.decode(errors="replace")[:300] or "ffprobe failed")
    return json.loads(proc.stdout or b"{}")


def collect_metadata(info):
    """Flatten container + per-stream tags into a list of rows."""
    rows = []
    fmt = info.get("format", {})
    for k, v in (fmt.get("tags") or {}).items():
        rows.append({"scope": "Container", "key": k, "value": str(v)})
    for s in info.get("streams", []):
        scope = f"Stream #{s.get('index')} ({s.get('codec_type', '?')})"
        for k, v in (s.get("tags") or {}).items():
            rows.append({"scope": scope, "key": k, "value": str(v)})
    for i, ch in enumerate(info.get("chapters", [])):
        title = (ch.get("tags") or {}).get("title", "")
        rows.append({"scope": "Chapter", "key": f"chapter {i + 1}", "value": title or "(untitled)"})
    for r in rows:
        key = r["key"].lower()
        r["sensitive"] = any(word in key for word in SENSITIVE_KEYWORDS)
    return rows


def stream_summary(info):
    kinds = {}
    for s in info.get("streams", []):
        t = s.get("codec_type", "unknown")
        kinds[t] = kinds.get(t, 0) + 1
    return kinds


def sanitize_video(src, dst):
    """Lossless remux that keeps only video/audio/subtitle streams and drops:
       - global metadata          (-map_metadata -1)
       - per-stream metadata      (-map_metadata:s -1)
       - chapters                 (-map_chapters -1)
       - data/attachment streams  (GPS tracks, timecode, cover art: not mapped)
       - muxer/encoder version    (bitexact flags)"""
    cmd = [FFMPEG, "-hide_banner", "-loglevel", "error", "-y", "-i", src,
           "-map", "0:v?", "-map", "0:a?", "-map", "0:s?",
           "-map_metadata", "-1", "-map_metadata:s", "-1", "-map_chapters", "-1",
           "-c", "copy", "-fflags", "+bitexact", "-flags:v", "+bitexact", "-flags:a", "+bitexact",
           dst]
    proc = subprocess.run(cmd, capture_output=True, timeout=600)
    if proc.returncode != 0:
        raise ValueError(proc.stderr.decode(errors="replace")[:400] or "ffmpeg failed")


def cleanup_old_outputs():
    cutoff = time.time() - SANITIZED_FILE_TTL
    try:
        for name in os.listdir(WORK_DIR):
            path = os.path.join(WORK_DIR, name)
            if os.path.isdir(path) and os.path.getmtime(path) < cutoff:
                shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass


@app.route("/sanitizer", methods=["GET", "POST"])
@login_required
def sanitizer():
    ffmpeg_ok = bool(FFMPEG and FFPROBE)
    if request.method == "GET" or not ffmpeg_ok:
        return render_template("sanitizer.html", ffmpeg_ok=ffmpeg_ok, report=None)

    upload = request.files.get("video")
    if not upload or not upload.filename:
        flash("Choose a video file first.", "error")
        return redirect(url_for("sanitizer"))
    original_name = secure_filename(upload.filename) or "video"
    ext = os.path.splitext(original_name)[1].lower()
    if ext not in ALLOWED_VIDEO_EXT:
        flash("Unsupported type. Allowed: " + ", ".join(sorted(ALLOWED_VIDEO_EXT)), "error")
        return redirect(url_for("sanitizer"))

    # Each job gets an unguessable folder; user-supplied names never touch the filesystem path
    token = secrets.token_urlsafe(24)
    job_dir = os.path.join(WORK_DIR, token)
    os.makedirs(job_dir)
    src = os.path.join(job_dir, "input" + ext)
    dst = os.path.join(job_dir, "clean" + ext)
    upload.save(src)

    try:
        before = ffprobe_json(src)       # also validates that it really is a media file
        if not any(s.get("codec_type") == "video" for s in before.get("streams", [])):
            raise ValueError("No video stream found - the file may be fake or corrupted.")
        sanitize_video(src, dst)
        after = ffprobe_json(dst)
    except (ValueError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        shutil.rmtree(job_dir, ignore_errors=True)
        audit("VIDEO_SANITIZE_FAIL", f"{original_name}: {e}")
        flash(f"Could not process this video: {e}", "error")
        return redirect(url_for("sanitizer"))

    before_rows, after_rows = collect_metadata(before), collect_metadata(after)
    after_keys = {(r["scope"], r["key"]) for r in after_rows}
    for r in before_rows:
        r["removed"] = (r["scope"], r["key"]) not in after_keys
    removed_streams = {k: v - stream_summary(after).get(k, 0)
                       for k, v in stream_summary(before).items()
                       if v - stream_summary(after).get(k, 0) > 0}
    hash_before, size_before = sha256_path(src)
    hash_after, size_after = sha256_path(dst)
    os.remove(src)                       # never keep the original (it contains the private data)

    meta = {"uid": session["uid"], "name": "sanitized_" + original_name}
    with open(os.path.join(job_dir, "job.json"), "w") as f:
        json.dump(meta, f)

    report = {
        "token": token,
        "filename": original_name,
        "out_name": meta["name"],
        "before": before_rows,
        "after": after_rows,
        "removed_count": sum(1 for r in before_rows if r["removed"]),
        "sensitive_removed": sum(1 for r in before_rows if r["removed"] and r["sensitive"]),
        "removed_streams": removed_streams,
        "hash_before": hash_before, "hash_after": hash_after,
        "size_before": size_before, "size_after": size_after,
        "duration": before.get("format", {}).get("duration"),
    }
    audit("VIDEO_SANITIZED", f"{original_name}: {report['removed_count']} tags removed "
                             f"({report['sensitive_removed']} sensitive)")
    return render_template("sanitizer.html", ffmpeg_ok=True, report=report)


@app.route("/sanitizer/download/<token>")
@login_required
def sanitizer_download(token):
    if not token.replace("-", "").replace("_", "").isalnum():
        abort(404)
    job_dir = os.path.join(WORK_DIR, token)
    job_file = os.path.join(job_dir, "job.json")
    if not os.path.isfile(job_file):
        abort(404)
    with open(job_file) as f:
        meta = json.load(f)
    if meta["uid"] != session["uid"]:          # users can only download their own output
        abort(404)
    clean = [n for n in os.listdir(job_dir) if n.startswith("clean")]
    if not clean:
        abort(404)
    audit("VIDEO_DOWNLOADED", meta["name"])
    return send_file(os.path.join(job_dir, clean[0]), as_attachment=True, download_name=meta["name"])


# --------------------------------------------------------------------------
# Component 3: File Integrity Checker (SHA-256 + HMAC seal)
# --------------------------------------------------------------------------
def make_seal(user_id, filename, size, digest, created_at):
    """HMAC-SHA256 over the record. If someone edits the database to make a
    tampered file look valid, the seal no longer matches (they lack the key)."""
    msg = f"{user_id}|{filename}|{size}|{digest}|{created_at}".encode()
    return hmac.new(INTEGRITY_HMAC_KEY, msg, hashlib.sha256).hexdigest()


def seal_ok(rec):
    expected = make_seal(rec["user_id"], rec["filename"], rec["size"], rec["sha256"], rec["created_at"])
    return hmac.compare_digest(expected, rec["seal"])


def is_hex64(s):
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def first_diff(a, b):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return None


def hash_upload(field="file"):
    upload = request.files.get(field)
    if not upload or not upload.filename:
        return None
    digest, size = sha256_stream(upload.stream)
    client = (request.form.get("client_hash") or "").strip().lower()
    transit = None
    if is_hex64(client):
        transit = hmac.compare_digest(client, digest)
    return {"name": secure_filename(upload.filename) or "file", "sha256": digest,
            "size": size, "client_hash": client if is_hex64(client) else None, "transit_ok": transit}


def integrity_records(uid):
    rows = get_db().execute("SELECT * FROM file_records WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall()
    return [dict(r, seal_valid=seal_ok(r)) for r in rows]


@app.route("/integrity")
@login_required
def integrity():
    return render_template("integrity.html", records=integrity_records(session["uid"]), result=None)


@app.route("/integrity/register", methods=["POST"])
@login_required
def integrity_register():
    up = hash_upload()
    if up is None:
        flash("Choose a file to register.", "error")
        return redirect(url_for("integrity"))
    created = now_iso()
    note = (request.form.get("note") or "").strip()[:120]
    seal = make_seal(session["uid"], up["name"], up["size"], up["sha256"], created)
    db = get_db()
    db.execute("INSERT INTO file_records (user_id, filename, size, sha256, seal, note, created_at) "
               "VALUES (?,?,?,?,?,?,?)", (session["uid"], up["name"], up["size"], up["sha256"], seal, note, created))
    db.commit()
    audit("FILE_REGISTERED", f"{up['name']} sha256={up['sha256'][:16]}...")
    result = {"mode": "register", "upload": up}
    return render_template("integrity.html", records=integrity_records(session["uid"]), result=result)


@app.route("/integrity/verify", methods=["POST"])
@login_required
def integrity_verify():
    up = hash_upload()
    if up is None:
        flash("Choose a file to verify.", "error")
        return redirect(url_for("integrity"))
    db = get_db()
    rec_id = request.form.get("record_id", "auto")
    if rec_id == "auto":
        rec = db.execute("SELECT * FROM file_records WHERE user_id=? AND filename=? ORDER BY id DESC LIMIT 1",
                         (session["uid"], up["name"])).fetchone()
    else:
        rec = db.execute("SELECT * FROM file_records WHERE user_id=? AND id=?",
                         (session["uid"], rec_id)).fetchone()
    result = {"mode": "verify", "upload": up, "record": None}
    if rec is None:
        same = db.execute("SELECT filename FROM file_records WHERE user_id=? AND sha256=? LIMIT 1",
                          (session["uid"], up["sha256"])).fetchone()
        result["status"] = "NO_RECORD"
        result["renamed_from"] = same["filename"] if same else None
        audit("FILE_VERIFY", f"{up['name']}: no baseline record")
    else:
        valid_seal = seal_ok(rec)
        match = hmac.compare_digest(rec["sha256"], up["sha256"])
        if not valid_seal:
            status = "RECORD_TAMPERED"
        elif match:
            status = "INTACT"
        else:
            status = "MODIFIED"
        result.update(record=dict(rec), status=status, seal_valid=valid_seal,
                      diff_at=None if match else first_diff(rec["sha256"], up["sha256"]),
                      size_delta=up["size"] - rec["size"])
        audit("FILE_VERIFY", f"{up['name']} vs record #{rec['id']}: {status}")
    return render_template("integrity.html", records=integrity_records(session["uid"]), result=result)


@app.route("/integrity/compare", methods=["POST"])
@login_required
def integrity_compare():
    expected = (request.form.get("expected") or "").strip().lower().replace(" ", "")
    if not is_hex64(expected):
        flash("Expected hash must be 64 hexadecimal characters (a SHA-256 digest).", "error")
        return redirect(url_for("integrity"))
    up = hash_upload()
    if up is None:
        flash("Choose a file to check.", "error")
        return redirect(url_for("integrity"))
    match = hmac.compare_digest(expected, up["sha256"])
    result = {"mode": "compare", "upload": up, "expected": expected, "status": "INTACT" if match else "MODIFIED",
              "diff_at": None if match else first_diff(expected, up["sha256"])}
    audit("FILE_COMPARE", f"{up['name']}: {result['status']}")
    return render_template("integrity.html", records=integrity_records(session["uid"]), result=result)


@app.route("/integrity/delete/<int:rec_id>", methods=["POST"])
@login_required
def integrity_delete(rec_id):
    db = get_db()
    db.execute("DELETE FROM file_records WHERE id=? AND user_id=?", (rec_id, session["uid"]))
    db.commit()
    audit("FILE_RECORD_DELETED", f"record #{rec_id}")
    flash("Record deleted.", "ok")
    return redirect(url_for("integrity"))


@app.route("/integrity/simulate-tamper/<int:rec_id>", methods=["POST"])
@login_required
def integrity_simulate_tamper(rec_id):
    """DEMO ONLY: plays the attacker who edits the database directly, replacing
    the stored hash without knowing the HMAC key. The seal check will catch it."""
    db = get_db()
    rec = db.execute("SELECT * FROM file_records WHERE id=? AND user_id=?", (rec_id, session["uid"])).fetchone()
    if rec:
        fake = hashlib.sha256(secrets.token_bytes(16)).hexdigest()
        db.execute("UPDATE file_records SET sha256=? WHERE id=?", (fake, rec_id))
        db.commit()
        audit("DEMO_DB_TAMPER", f"record #{rec_id} hash overwritten (attack simulation)")
        flash(f"Attack simulated: record #{rec_id}'s stored hash was overwritten directly in the database.", "warn")
    return redirect(url_for("integrity"))


@app.route("/integrity/manifest")
@login_required
def integrity_manifest():
    recs = integrity_records(session["uid"])
    manifest = {
        "generated_at": now_iso(),
        "generated_by": session["username"],
        "algorithm": "SHA-256",
        "files": [{"filename": r["filename"], "size": r["size"], "sha256": r["sha256"],
                   "registered_at": r["created_at"], "seal_valid": r["seal_valid"]} for r in recs],
    }
    buf = io.BytesIO(json.dumps(manifest, indent=2).encode())
    audit("MANIFEST_EXPORTED", f"{len(recs)} records")
    return send_file(buf, mimetype="application/json", as_attachment=True,
                     download_name="integrity_manifest.json")


# --------------------------------------------------------------------------
# Template helpers
# --------------------------------------------------------------------------
@app.template_filter("filesize")
def filesize(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


@app.template_filter("when")
def when(iso):
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%d %b %Y, %H:%M")
    except (TypeError, ValueError):
        return iso


init_db()

if __name__ == "__main__":
    if not (FFMPEG and FFPROBE):
        print("WARNING: ffmpeg/ffprobe not found on PATH - the Video Sanitizer will be disabled.")
    print(f"{APP_NAME} running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
