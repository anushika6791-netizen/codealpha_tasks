"""
NoteVault — remediated version.

Every fix below is annotated with the Finding ID it addresses from
SECURE_CODING_REVIEW_REPORT.docx, so it can be cross-referenced during
re-testing.
"""

import os
import re
import sqlite3
import ipaddress
import socket
import secrets
from urllib.parse import urlparse

from flask import Flask, request, redirect, session, render_template, make_response, abort
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape

app = Flask(__name__)

# --- FIX (F4): secret loaded from environment, never committed to source.
# Fails loudly instead of silently falling back to a guessable default.
app.secret_key = os.environ["NOTEVAULT_SECRET_KEY"]

# --- FIX (F12): CSRF protection on every state-changing (POST/PUT/DELETE)
# route. Templates must include {{ csrf_token() }} as a hidden field in
# each <form> — see templates/*.html.
csrf = CSRFProtect(app)

# --- FIX (F14): harden session cookie attributes.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,      # requires HTTPS in production
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,  # 30 min idle timeout
)

DB_PATH = os.path.join(os.path.dirname(__file__), "notevault.db")
UPLOAD_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

# --- FIX (F4): service credentials also come from environment / secrets manager.
REPORTING_DB_USER = os.environ.get("REPORTING_DB_USER")
REPORTING_DB_PASSWORD = os.environ.get("REPORTING_DB_PASSWORD")

ALLOWED_UPLOAD_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
ALLOWED_PING_HOSTS = {"127.0.0.1", "localhost"}  # F7: explicit allowlist, no free-form input


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            is_admin INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            body TEXT
        );
        """
    )
    conn.commit()
    conn.close()


# --- FIX (F5): salted, slow hash (Werkzeug's default is PBKDF2-SHA256;
# swap for argon2/bcrypt via a library like argon2-cffi if preferred).
def hash_password(password):
    return generate_password_hash(password)


def verify_password(password, stored_hash):
    return check_password_hash(stored_hash, password)


# --- FIX (F6): reusable auth decorators instead of ad-hoc session checks. ---
def login_required(view):
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


def admin_required(view):
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        if not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


# --- FIX (F15): baseline security headers on every response. ---
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        # Minimal input validation — reject empty/absurdly long values.
        if not username or not (8 <= len(password) <= 128):
            return "Invalid username or password does not meet length requirements", 400

        conn = get_db()
        # --- FIX (F1): parameterized query — the driver handles escaping,
        # so untrusted input can never change the query structure.
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hash_password(password)),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already taken", 409
        finally:
            conn.close()
        return redirect("/login")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_db()
        # --- FIX (F1): parameterized query removes the SQLi / auth-bypass vector.
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        # --- FIX (F5): compare against the salted hash, not plaintext/MD5.
        if user and verify_password(password, user["password_hash"]):
            # --- FIX (F14): clear any pre-existing session data before
            # establishing a new one, mitigating session fixation.
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            session.permanent = True
            return redirect("/dashboard")
        # --- Same generic error for bad username and bad password, so the
        # response doesn't reveal which one was wrong (prevents user enumeration).
        return "Invalid credentials", 401
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    notes = conn.execute(
        "SELECT * FROM notes WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    conn.close()
    return render_template("dashboard.html", username=session["username"], notes=notes)


@app.route("/notes/new", methods=["GET", "POST"])
@login_required
def new_note():
    if request.method == "POST":
        title = request.form["title"][:200]
        body = request.form["body"][:10000]
        conn = get_db()
        conn.execute(
            "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
            (session["user_id"], title, body),
        )
        conn.commit()
        conn.close()
        return redirect("/dashboard")
    return render_template("new_note.html")


@app.route("/notes/<int:note_id>")
@login_required
def view_note(note_id):
    conn = get_db()
    # --- FIX (F6/IDOR): ownership is enforced in the query itself, not
    # just checked after the fact — a user can only ever fetch their own note.
    note = conn.execute(
        "SELECT * FROM notes WHERE id = ? AND user_id = ?",
        (note_id, session["user_id"]),
    ).fetchone()
    conn.close()
    if not note:
        abort(404)
    # --- FIX (F3): render_template with Jinja's autoescaping turned on
    # (the default) instead of interpolating raw HTML — note title/body
    # are escaped automatically. escape() shown explicitly for clarity.
    return render_template("note.html", title=escape(note["title"]), body=escape(note["body"]))


@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "")[:200]
    conn = get_db()
    # --- FIX (F1): parameterized LIKE query; '%' wildcards are passed as
    # bound data, not concatenated into the SQL string.
    results = conn.execute(
        "SELECT * FROM notes WHERE user_id = ? AND title LIKE ?",
        (session["user_id"], f"%{q}%"),
    ).fetchall()
    conn.close()
    return render_template("search.html", results=results)


def _allowed_upload(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_UPLOAD_EXTENSIONS


@app.route("/profile/upload", methods=["POST"])
@login_required
def upload_avatar():
    f = request.files.get("avatar")
    if f is None or f.filename == "":
        return "No file provided", 400

    # --- FIX (F11): extension allowlist + size cap.
    if not _allowed_upload(f.filename):
        return "Unsupported file type", 400

    f.seek(0, os.SEEK_END)
    if f.tell() > MAX_UPLOAD_BYTES:
        return "File too large", 400
    f.seek(0)

    # --- FIX (F11/F10): sanitize the filename and give it a random prefix
    # tied to the user, so one user can't overwrite another's file and a
    # crafted filename can't escape the upload directory.
    safe_name = secure_filename(f.filename)
    unique_name = f"{session['user_id']}_{secrets.token_hex(8)}_{safe_name}"
    save_path = os.path.join(UPLOAD_DIR, unique_name)
    f.save(save_path)
    return {"saved_as": unique_name}


@app.route("/download")
@login_required
def download():
    filename = request.args.get("file", "")
    # --- FIX (F10): sanitize, then resolve the real path and verify it is
    # still inside UPLOAD_DIR before opening — blocks ../ traversal and
    # symlink tricks.
    safe_name = secure_filename(filename)
    candidate = os.path.realpath(os.path.join(UPLOAD_DIR, safe_name))
    if not candidate.startswith(UPLOAD_DIR + os.sep):
        abort(400)
    if not os.path.isfile(candidate):
        abort(404)
    with open(candidate, "rb") as fh:
        data = fh.read()
    resp = make_response(data)
    resp.headers["Content-Disposition"] = f"attachment; filename={safe_name}"
    resp.headers["Content-Type"] = "application/octet-stream"
    return resp


@app.route("/admin/ping")
@admin_required
def admin_ping():
    # --- FIX (F7/F6): restricted to admins, and the host must match a
    # strict allowlist — no shell, no string interpolation into a command.
    host = request.args.get("host", "127.0.0.1")
    if host not in ALLOWED_PING_HOSTS:
        abort(400)
    import subprocess
    result = subprocess.run(
        ["ping", "-c", "1", host], capture_output=True, timeout=5, check=False
    )
    return {"output": result.stdout.decode(errors="ignore")}


ALLOWED_FETCH_HOSTS = {"api.internal-partner.example.com"}


@app.route("/fetch")
@login_required
def fetch_url():
    # --- FIX (F8): allowlist destination hosts, block link-local / private /
    # loopback ranges, and refuse redirects to unapproved targets instead of
    # blindly fetching whatever URL the client supplies.
    url = request.args.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme not in ("https",) or parsed.hostname not in ALLOWED_FETCH_HOSTS:
        abort(400)
    try:
        resolved_ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(resolved_ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            abort(400)
    except socket.gaierror:
        abort(400)

    import requests  # scoped import; add `requests` to requirements.txt
    resp = requests.get(url, timeout=5, allow_redirects=False)
    return resp.content, resp.status_code


@app.route("/api/preferences", methods=["GET", "POST"])
@login_required
def preferences():
    # --- FIX (F9): plain JSON instead of pickle — no arbitrary object graph,
    # no code execution on load, and the value is validated against a
    # known-safe set before use.
    import json
    ALLOWED_THEMES = {"light", "dark"}

    if request.method == "POST":
        theme = request.form.get("theme", "light")
        if theme not in ALLOWED_THEMES:
            return "Invalid theme", 400
        resp = make_response(redirect("/dashboard"))
        resp.set_cookie(
            "prefs", json.dumps({"theme": theme}), httponly=True, samesite="Lax"
        )
        return resp

    cookie = request.cookies.get("prefs")
    if cookie:
        try:
            prefs = json.loads(cookie)
        except (ValueError, TypeError):
            prefs = {}
        return prefs
    return {}


@app.route("/admin/users")
@admin_required
def admin_users():
    # --- FIX (F6): now gated by admin_required, which checks the actual
    # is_admin flag rather than mere session presence.
    conn = get_db()
    users = conn.execute("SELECT id, username, is_admin FROM users").fetchall()
    conn.close()
    return {"users": [dict(u) for u in users]}


if __name__ == "__main__":
    init_db()
    # --- FIX (F13): debug mode and bind address driven by environment,
    # defaulting to the safe option.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    bind_host = os.environ.get("FLASK_BIND_HOST", "127.0.0.1")
    app.run(host=bind_host, port=5000, debug=debug_mode)
