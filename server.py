"""Local BHT & BAT student portal server. Run: py server.py"""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import base64
import re
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DATABASE = ROOT / "portal.db"
UPLOADS = ROOT / "uploads"
SESSIONS = {}


def db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 150_000)
    return f"{salt}${digest.hex()}"


def verify_password(password, stored):
    salt, digest = stored.split("$", 1)
    return hmac.compare_digest(password_hash(password, salt).split("$", 1)[1], digest)


def initialise_database():
    UPLOADS.mkdir(exist_ok=True)
    con = db()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, student_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
          password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student', programme TEXT
        );
        CREATE TABLE IF NOT EXISTS notices (
          id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL,
          published_on TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS downloads (
          id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT, file_url TEXT,
          file_type TEXT DEFAULT 'PDF'
        );
        CREATE TABLE IF NOT EXISTS messages (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, subject TEXT,
          message TEXT NOT NULL, created_on TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)
    if not con.execute("SELECT 1 FROM users WHERE student_id = ?", ("admin",)).fetchone():
        con.execute("INSERT INTO users (student_id,name,password_hash,role,programme) VALUES (?,?,?,?,?)",
                    ("admin", "Portal Administrator", password_hash("admin123"), "admin", "Administration"))
        con.execute("INSERT INTO users (student_id,name,password_hash,role,programme) VALUES (?,?,?,?,?)",
                    ("BHT2026001", "Aarav Sharma", password_hash("student123"), "student", "BHT"))
        con.execute("INSERT INTO users (student_id,name,password_hash,role,programme) VALUES (?,?,?,?,?)",
                    ("BAT2026001", "Zoya Khan", password_hash("student123"), "student", "BAT"))
    if not con.execute("SELECT 1 FROM notices").fetchone():
        con.executemany("INSERT INTO notices(title,body) VALUES (?,?)", [
            ("Semester registration is now open", "Complete registration before 5 August 2026."),
            ("Updated examination timetable", "View dates and instructions for final assessments."),
            ("New digital library resources", "Access journals, e-books and research databases."),
        ])
    con.commit()
    con.close()


class PortalHandler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        # Limit all static-file requests to this project folder.
        path = urlparse(path).path.lstrip("/") or "index.html"
        candidate = (ROOT / path).resolve()
        return str(candidate if ROOT in candidate.parents or candidate == ROOT else ROOT / "index.html")

    def read_json(self):
        size = int(self.headers.get("Content-Length", "0"))
        try:
            return json.loads(self.rfile.read(size).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    def send_json(self, data, status=HTTPStatus.OK, cookie=None):
        raw = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

    def current_user(self):
        cookies = SimpleCookie(self.headers.get("Cookie"))
        token = cookies.get("portal_session")
        return SESSIONS.get(token.value) if token else None

    def do_GET(self):
        route = urlparse(self.path).path
        if route == "/api/notices":
            con = db(); rows = [dict(row) for row in con.execute("SELECT * FROM notices ORDER BY id DESC")]; con.close()
            return self.send_json(rows)
        if route == "/api/downloads":
            con = db(); rows = [dict(row) for row in con.execute("SELECT * FROM downloads ORDER BY id DESC")]; con.close()
            return self.send_json(rows)
        if route == "/api/session":
            return self.send_json({"user": self.current_user()})
        if route == "/api/admin/notices":
            user = self.current_user()
            if not user or user["role"] != "admin": return self.send_json({"error": "Administrator access required."}, HTTPStatus.FORBIDDEN)
            con = db(); rows = [dict(row) for row in con.execute("SELECT * FROM notices ORDER BY id DESC")]; con.close()
            return self.send_json(rows)
        if route == "/api/admin/downloads":
            user = self.current_user()
            if not user or user["role"] != "admin": return self.send_json({"error": "Administrator access required."}, HTTPStatus.FORBIDDEN)
            con = db(); rows = [dict(row) for row in con.execute("SELECT * FROM downloads ORDER BY id DESC")]; con.close()
            return self.send_json(rows)
        return super().do_GET()

    def do_POST(self):
        route, data = urlparse(self.path).path, self.read_json()
        if route == "/api/login":
            student_id = str(data.get("student_id", "")).strip()
            password = str(data.get("password", ""))
            con = db(); row = con.execute("SELECT * FROM users WHERE lower(student_id)=lower(?)", (student_id,)).fetchone(); con.close()
            if not row or not verify_password(password, row["password_hash"]):
                return self.send_json({"error": "Incorrect Student ID or password."}, HTTPStatus.UNAUTHORIZED)
            token = secrets.token_urlsafe(32)
            user = {"student_id": row["student_id"], "name": row["name"], "role": row["role"], "programme": row["programme"]}
            SESSIONS[token] = user
            return self.send_json({"user": user}, cookie=f"portal_session={token}; HttpOnly; SameSite=Lax; Path=/")
        if route == "/api/logout":
            cookies = SimpleCookie(self.headers.get("Cookie")); token = cookies.get("portal_session")
            if token: SESSIONS.pop(token.value, None)
            return self.send_json({"ok": True}, cookie="portal_session=; Max-Age=0; Path=/")
        if route == "/api/contact":
            if not all(data.get(key, "").strip() for key in ("name", "email", "message")):
                return self.send_json({"error": "Please complete your name, email and message."}, HTTPStatus.BAD_REQUEST)
            con = db(); con.execute("INSERT INTO messages(name,email,subject,message) VALUES (?,?,?,?)", (data["name"].strip(), data["email"].strip(), data.get("subject", ""), data["message"].strip())); con.commit(); con.close()
            return self.send_json({"message": "Thank you — your message has been sent."})
        if route == "/api/admin/notices":
            user = self.current_user()
            if not user or user["role"] != "admin": return self.send_json({"error": "Administrator access required."}, HTTPStatus.FORBIDDEN)
            if not data.get("title", "").strip() or not data.get("body", "").strip(): return self.send_json({"error": "Title and message are required."}, HTTPStatus.BAD_REQUEST)
            con = db(); con.execute("INSERT INTO notices(title,body) VALUES (?,?)", (data["title"].strip(), data["body"].strip())); con.commit(); con.close()
            return self.send_json({"message": "Notice published."})
        if route == "/api/admin/downloads":
            user = self.current_user()
            if not user or user["role"] != "admin": return self.send_json({"error": "Administrator access required."}, HTTPStatus.FORBIDDEN)
            title = str(data.get("title", "")).strip()
            description = str(data.get("description", "")).strip()
            file_name = str(data.get("file_name", "")).strip()
            file_data = str(data.get("file_data", ""))
            if not title or not file_name or not file_data:
                return self.send_json({"error": "Document title and PDF file are required."}, HTTPStatus.BAD_REQUEST)
            if not file_name.lower().endswith(".pdf") or not file_data.startswith("data:application/pdf;base64,"):
                return self.send_json({"error": "Please upload a PDF file."}, HTTPStatus.BAD_REQUEST)
            try:
                raw = base64.b64decode(file_data.split(",", 1)[1], validate=True)
            except (ValueError, base64.binascii.Error):
                return self.send_json({"error": "The uploaded file could not be read."}, HTTPStatus.BAD_REQUEST)
            if len(raw) > 10 * 1024 * 1024:
                return self.send_json({"error": "PDF files must be 10 MB or smaller."}, HTTPStatus.BAD_REQUEST)
            if not raw.startswith(b"%PDF-"):
                return self.send_json({"error": "The uploaded file is not a valid PDF."}, HTTPStatus.BAD_REQUEST)
            safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(file_name).name)
            stored_name = f"{secrets.token_hex(8)}-{safe_name}"
            (UPLOADS / stored_name).write_bytes(raw)
            con = db()
            con.execute("INSERT INTO downloads(title,description,file_url,file_type) VALUES (?,?,?,?)", (title, description, f"uploads/{stored_name}", "PDF"))
            con.commit(); con.close()
            return self.send_json({"message": "PDF uploaded and published."})
        return self.send_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)


if __name__ == "__main__":
    initialise_database()
    server = ThreadingHTTPServer(("127.0.0.1", 8000), PortalHandler)
    print("BHT & BAT portal is running at http://127.0.0.1:8000")
    server.serve_forever()
