"""Small, dependency-free backend for the Campus Placement Portal demo."""

from contextlib import contextmanager
from hashlib import pbkdf2_hmac, sha256
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("PLACEMENT_DB", ROOT / "placement.db")).resolve()
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
ADMIN_INVITE_CODE = os.environ.get("ADMIN_INVITE_CODE", "")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "").lower() in {"1", "true", "yes"}
SESSION_SECONDS = 7 * 24 * 60 * 60
PASSWORD_ITERATIONS = 600_000
STATUSES = {"APPLIED", "SHORTLISTED", "SELECTED", "REJECTED"}


@contextmanager
def database():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with database() as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('STUDENT', 'ADMIN'))
            );
            CREATE TABLE IF NOT EXISTS companies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                location TEXT NOT NULL,
                package TEXT NOT NULL,
                eligibility TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
                status TEXT NOT NULL DEFAULT 'APPLIED'
                    CHECK (status IN ('APPLIED', 'SHORTLISTED', 'SELECTED', 'REJECTED')),
                created_at INTEGER NOT NULL,
                UNIQUE(student_id, company_id)
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
            """
        )
        if db.execute("SELECT COUNT(*) FROM companies").fetchone()[0] == 0:
            db.executemany(
                "INSERT INTO companies (name, role, location, package, eligibility) VALUES (?, ?, ?, ?, ?)",
                [
                    ("TCS", "Software Developer", "Noida", "7", "60% or above"),
                    ("Infosys", "Systems Engineer", "Bangalore", "6.5", "No active backlogs"),
                    ("Wipro", "Project Engineer", "Gurugram", "5.5", "60% or above"),
                ],
            )


def public_user(row):
    return {"id": row["id"], "name": row["name"], "email": row["email"], "role": row["role"]}


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class PlacementHandler(BaseHTTPRequestHandler):
    server_version = "CampusPlacementDemo/1.0"

    def log_message(self, format_string, *args):
        # Avoid putting email addresses or other request data in default access logs.
        print(f"{self.client_address[0]} - {self.command} {self.path.split('?')[0]}")

    def send_json(self, status, payload=None, extra_headers=None):
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Invalid request body.")
        if length < 1 or length > 32_768:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Request body must be between 1 byte and 32 KB.")
        try:
            value = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Request body must be valid JSON.")
        if not isinstance(value, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Request body must be a JSON object.")
        return value

    def check_origin(self):
        origin = self.headers.get("Origin")
        scheme = "https" if COOKIE_SECURE else "http"
        expected = f"{scheme}://{self.headers.get('Host', '')}"
        if not origin or not hmac.compare_digest(origin.rstrip("/"), expected.rstrip("/")):
            raise ApiError(HTTPStatus.FORBIDDEN, "Request origin was not accepted. Reload the page and try again.")

    def session_user(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return None
        morsel = cookie.get("placement_session")
        if morsel is None:
            return None
        token_hash = sha256(morsel.value.encode("ascii", "ignore")).hexdigest()
        now = int(time.time())
        with database() as db:
            row = db.execute(
                "SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id "
                "WHERE sessions.token_hash = ? AND sessions.expires_at > ?",
                (token_hash, now),
            ).fetchone()
        return row

    def require_user(self, admin=False):
        user = self.session_user()
        if user is None:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "Please log in and try again.")
        if admin and user["role"] != "ADMIN":
            raise ApiError(HTTPStatus.FORBIDDEN, "Admin access is required for this action.")
        return user

    def set_session(self, user_id):
        token = secrets.token_urlsafe(32)
        token_hash = sha256(token.encode("ascii")).hexdigest()
        expires = int(time.time()) + SESSION_SECONDS
        with database() as db:
            db.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
            db.execute("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)", (token_hash, user_id, expires))
        cookie = f"placement_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_SECONDS}"
        if COOKIE_SECURE:
            cookie += "; Secure"
        return {"Set-Cookie": cookie}

    def clear_session(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            cookie = SimpleCookie()
        morsel = cookie.get("placement_session")
        if morsel:
            digest = sha256(morsel.value.encode("ascii", "ignore")).hexdigest()
            with database() as db:
                db.execute("DELETE FROM sessions WHERE token_hash = ?", (digest,))
        return {"Set-Cookie": "placement_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0" + ("; Secure" if COOKIE_SECURE else "")}

    def do_GET(self):
        path = urlsplit(self.path).path
        try:
            if path == "/api/session":
                user = self.session_user()
                self.send_json(HTTPStatus.OK, {"user": public_user(user) if user else None})
                return
            if path == "/api/companies":
                with database() as db:
                    rows = db.execute("SELECT * FROM companies ORDER BY id").fetchall()
                self.send_json(HTTPStatus.OK, [dict(row) for row in rows])
                return
            if path == "/api/applications":
                user = self.require_user()
                query = (
                    "SELECT applications.id, applications.status, applications.created_at, "
                    "users.name AS student_name, companies.name AS company_name, "
                    "applications.company_id, applications.student_id "
                    "FROM applications JOIN users ON users.id = applications.student_id "
                    "JOIN companies ON companies.id = applications.company_id "
                )
                with database() as db:
                    if user["role"] == "ADMIN":
                        rows = db.execute(query + "ORDER BY applications.created_at DESC").fetchall()
                        result = [{"id": r["id"], "status": r["status"], "studentName": r["student_name"], "companyName": r["company_name"], "companyId": r["company_id"]} for r in rows]
                    else:
                        rows = db.execute(query + "WHERE applications.student_id = ? ORDER BY applications.created_at DESC", (user["id"],)).fetchall()
                        result = [{"id": r["id"], "status": r["status"], "companyName": r["company_name"], "companyId": r["company_id"]} for r in rows]
                self.send_json(HTTPStatus.OK, result)
                return
            if path in {"/", "/index.html"}:
                content = (ROOT / "index.html").read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
                self.end_headers()
                self.wfile.write(content)
                return
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
        except ApiError as error:
            self.send_json(error.status, {"error": str(error)})

    def do_POST(self):
        path = urlsplit(self.path).path
        try:
            self.check_origin()
            data = self.read_json()
            if path == "/api/register":
                name = str(data.get("name", "")).strip()
                email = str(data.get("email", "")).strip().lower()
                password = data.get("password", "")
                role = str(data.get("role", "STUDENT")).upper()
                if not name or len(name) > 100:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Enter a name of 1 to 100 characters.")
                if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Enter a valid email address.")
                if not isinstance(password, str) or len(password) < 8 or len(password.encode("utf-8")) > 1024:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Password must be at least 8 characters and no more than 1024 bytes.")
                if role not in {"STUDENT", "ADMIN"}:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Choose Student or Admin.")
                if role == "ADMIN":
                    supplied = data.get("adminCode", "")
                    if not ADMIN_INVITE_CODE or not isinstance(supplied, str) or not hmac.compare_digest(supplied, ADMIN_INVITE_CODE):
                        raise ApiError(HTTPStatus.FORBIDDEN, "A valid admin invite code is required to create an admin account.")
                salt = secrets.token_bytes(16)
                password_hash = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS).hex()
                try:
                    with database() as db:
                        cursor = db.execute(
                            "INSERT INTO users (name, email, password_salt, password_hash, role) VALUES (?, ?, ?, ?, ?)",
                            (name, email, salt.hex(), password_hash, role),
                        )
                        user_id = cursor.lastrowid
                except sqlite3.IntegrityError:
                    raise ApiError(HTTPStatus.CONFLICT, "That email address is already registered.")
                with database() as db:
                    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                self.send_json(HTTPStatus.CREATED, public_user(user), self.set_session(user_id))
                return
            if path == "/api/login":
                email = str(data.get("email", "")).strip().lower()
                password = data.get("password", "")
                if not isinstance(password, str) or len(password.encode("utf-8")) > 1024:
                    raise ApiError(HTTPStatus.UNAUTHORIZED, "Email or password is incorrect.")
                with database() as db:
                    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
                if user is None:
                    # Do comparable password work for unknown email addresses.
                    pbkdf2_hmac("sha256", password.encode("utf-8"), b"placement-demo-salt", PASSWORD_ITERATIONS)
                    raise ApiError(HTTPStatus.UNAUTHORIZED, "Email or password is incorrect.")
                actual = pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(user["password_salt"]), PASSWORD_ITERATIONS).hex()
                if not hmac.compare_digest(actual, user["password_hash"]):
                    raise ApiError(HTTPStatus.UNAUTHORIZED, "Email or password is incorrect.")
                self.send_json(HTTPStatus.OK, public_user(user), self.set_session(user["id"]))
                return
            if path == "/api/logout":
                self.send_json(HTTPStatus.OK, {"ok": True}, self.clear_session())
                return
            if path == "/api/applications":
                user = self.require_user()
                if user["role"] != "STUDENT":
                    raise ApiError(HTTPStatus.FORBIDDEN, "Only student accounts can apply.")
                try:
                    company_id = int(data.get("companyId"))
                except (TypeError, ValueError):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Choose a valid placement.")
                try:
                    with database() as db:
                        if db.execute("SELECT 1 FROM companies WHERE id = ?", (company_id,)).fetchone() is None:
                            raise ApiError(HTTPStatus.NOT_FOUND, "That placement no longer exists.")
                        db.execute("INSERT INTO applications (student_id, company_id, created_at) VALUES (?, ?, ?)", (user["id"], company_id, int(time.time())))
                except sqlite3.IntegrityError:
                    raise ApiError(HTTPStatus.CONFLICT, "You have already applied to this placement.")
                self.send_json(HTTPStatus.CREATED, {"ok": True})
                return
            if path == "/api/companies":
                self.require_user(admin=True)
                values = [str(data.get(key, "")).strip() for key in ("name", "role", "location", "package", "eligibility")]
                if any(not value or len(value) > 200 for value in values):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Fill in all placement fields (up to 200 characters each).")
                with database() as db:
                    cursor = db.execute("INSERT INTO companies (name, role, location, package, eligibility) VALUES (?, ?, ?, ?, ?)", values)
                    company_id = cursor.lastrowid
                self.send_json(HTTPStatus.CREATED, {"id": company_id})
                return
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
        except ApiError as error:
            self.send_json(error.status, {"error": str(error)})

    def do_DELETE(self):
        self._mutate_company("DELETE")

    def _mutate_company(self, method):
        try:
            self.check_origin()
            self.require_user(admin=True)
            match = re.fullmatch(r"/api/companies/(\d+)", urlsplit(self.path).path)
            if not match:
                raise ApiError(HTTPStatus.NOT_FOUND, "Not found.")
            with database() as db:
                cursor = db.execute("DELETE FROM companies WHERE id = ?", (int(match.group(1)),))
                if cursor.rowcount == 0:
                    raise ApiError(HTTPStatus.NOT_FOUND, "Placement not found.")
            self.send_json(HTTPStatus.NO_CONTENT)
        except ApiError as error:
            self.send_json(error.status, {"error": str(error)})

    def do_PATCH(self):
        try:
            self.check_origin()
            self.require_user(admin=True)
            match = re.fullmatch(r"/api/applications/(\d+)", urlsplit(self.path).path)
            if not match:
                raise ApiError(HTTPStatus.NOT_FOUND, "Not found.")
            data = self.read_json()
            status = str(data.get("status", "")).upper()
            if status not in STATUSES:
                raise ApiError(HTTPStatus.BAD_REQUEST, "Choose a valid application status.")
            with database() as db:
                cursor = db.execute("UPDATE applications SET status = ? WHERE id = ?", (status, int(match.group(1))))
                if cursor.rowcount == 0:
                    raise ApiError(HTTPStatus.NOT_FOUND, "Application not found.")
            self.send_json(HTTPStatus.OK, {"ok": True})
        except ApiError as error:
            self.send_json(error.status, {"error": str(error)})


if __name__ == "__main__":
    initialize_database()
    print(f"Campus Placement Portal running at http://{HOST}:{PORT}")
    if not ADMIN_INVITE_CODE:
        print("Admin signup is disabled: set ADMIN_INVITE_CODE to a private value before creating an admin account.")
    ThreadingHTTPServer((HOST, PORT), PlacementHandler).serve_forever()
