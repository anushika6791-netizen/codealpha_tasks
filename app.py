"""
NoteVault — a small internal notes-sharing app.

*** THIS CODE IS INTENTIONALLY VULNERABLE ***
It exists as an audit target for a secure-coding review. Do not deploy it.
"""

import os
import sqlite3
import hashlib
import pickle
import base64
import subprocess

from flask import Flask, request, redirect, session, render_template_string, make_response
import urllib.request

app = Flask(__name__)

# --- VULN: hardcoded secret key checked into source control ---
app.secret_key = "sk_live_9f3a1c4e2b7d4a5e9c0b1f2d3e4f5a6b"

DB_PATH = os.path.join(os.path.dirname(__file__), "notevault.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# --- VULN: hardcoded credentials for an "internal" admin/report DB ---
REPORTING_DB_USER = "svc_reporting"
REPORTING_DB_PASSWORD = "R3porting!2024"


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
            password TEXT,
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


# --- VULN: weak, unsalted password hashing (MD5) ---
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_db()
        # --- VULN: SQL injection via string formatting ---
        conn.execute(
            "INSERT INTO users (username, password) VALUES ('%s', '%s')"
            % (username, hash_password(password))
        )
        conn.commit()
        conn.close()
        return redirect("/login")
    return """
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <button type="submit">Register</button>
        </form>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_db()
        # --- VULN: SQL injection via string formatting (classic auth bypass) ---
        query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
            username,
            hash_password(password),
        )
        user = conn.execute(query).fetchone()
        conn.close()
        if user:
            # --- VULN: session fixation risk — no session.regenerate/new id on login ---
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = user["is_admin"]
            return redirect("/dashboard")
        return "Invalid credentials", 401
    return """
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <button type="submit">Login</button>
        </form>
    """


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    conn = get_db()
    notes = conn.execute(
        "SELECT * FROM notes WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    conn.close()
    rows = "".join(f'<li><a href="/notes/{n["id"]}">{n["title"]}</a></li>' for n in notes)
    return f"<h1>Welcome {session['username']}</h1><ul>{rows}</ul>"


@app.route("/notes/new", methods=["GET", "POST"])
def new_note():
    if "user_id" not in session:
        return redirect("/login")
    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        conn = get_db()
        conn.execute(
            "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
            (session["user_id"], title, body),
        )
        conn.commit()
        conn.close()
        return redirect("/dashboard")
    return """
        <form method="post">
            Title: <input name="title"><br>
            Body:<br><textarea name="body"></textarea><br>
            <button type="submit">Save</button>
        </form>
    """


@app.route("/notes/<note_id>")
def view_note(note_id):
    if "user_id" not in session:
        return redirect("/login")
    conn = get_db()
    # --- VULN: IDOR — no check that this note belongs to session user ---
    note = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    conn.close()
    if not note:
        return "Not found", 404
    # --- VULN: stored XSS — note body rendered without escaping ---
    template = f"""
        <h1>{note['title']}</h1>
        <div>{note['body']}</div>
    """
    return render_template_string(template)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    # --- VULN: SQL injection in search endpoint ---
    query = "SELECT * FROM notes WHERE title LIKE '%%%s%%'" % q
    results = conn.execute(query).fetchall()
    conn.close()
    rows = "".join(f"<li>{r['title']}</li>" for r in results)
    return f"<ul>{rows}</ul>"


@app.route("/profile/upload", methods=["POST"])
def upload_avatar():
    if "user_id" not in session:
        return redirect("/login")
    f = request.files["avatar"]
    # --- VULN: no extension/content-type allowlist — arbitrary file upload ---
    # --- VULN: filename taken from user input, no sanitization (path traversal) ---
    save_path = os.path.join(UPLOAD_DIR, f.filename)
    f.save(save_path)
    return f"Saved to {save_path}"


@app.route("/download")
def download():
    # --- VULN: path traversal — filename comes straight from query string ---
    filename = request.args.get("file")
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, "rb") as fh:
        data = fh.read()
    resp = make_response(data)
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


@app.route("/admin/ping")
def admin_ping():
    # --- VULN: no authorization check — should be admin-only ---
    # --- VULN: OS command injection — host goes straight into a shell command ---
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return f"<pre>{result.decode(errors='ignore')}</pre>"


@app.route("/fetch")
def fetch_url():
    # --- VULN: SSRF — server fetches any attacker-supplied URL, including
    #           internal/metadata addresses (e.g. 169.254.169.254) ---
    url = request.args.get("url")
    with urllib.request.urlopen(url) as resp:
        content = resp.read()
    return content


@app.route("/api/preferences", methods=["GET", "POST"])
def preferences():
    # --- VULN: insecure deserialization — untrusted cookie deserialized with pickle ---
    if request.method == "POST":
        prefs = {"theme": request.form.get("theme", "light")}
        raw = base64.b64encode(pickle.dumps(prefs)).decode()
        resp = make_response(redirect("/dashboard"))
        resp.set_cookie("prefs", raw)
        return resp

    cookie = request.cookies.get("prefs")
    if cookie:
        prefs = pickle.loads(base64.b64decode(cookie))
        return prefs
    return {}


@app.route("/admin/users")
def admin_users():
    # --- VULN: broken access control — checks session presence, not admin flag ---
    if "user_id" not in session:
        return redirect("/login")
    conn = get_db()
    users = conn.execute("SELECT id, username, is_admin FROM users").fetchall()
    conn.close()
    return {"users": [dict(u) for u in users]}


if __name__ == "__main__":
    init_db()
    # --- VULN: debug mode + bind to all interfaces in what looks like a run config ---
    app.run(host="0.0.0.0", port=5000, debug=True)
