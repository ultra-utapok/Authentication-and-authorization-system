import json
import os
import sqlite3
import uuid
import time
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

HOST = "127.0.0.1"
PORT = 8000
DB_FILE = "app.db"

TOKEN_TTL_SECONDS = 60 * 60  # 1 час


# Работа с БД

def db_connect():
    return sqlite3.connect(DB_FILE)


def init_db():
    con = db_connect()
    cur = con.cursor()

    # Пользователи
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT UNIQUE NOT NULL,
            pass_hash TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            role TEXT NOT NULL
        )
    """)

    # Сессии (токены)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expire_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    con.commit()

    # Создание админа
    cur.execute("SELECT id FROM users WHERE login = ?", ("admin",))
    row = cur.fetchone()
    if row is None:
        admin_hash = make_pass_hash("admin123")
        cur.execute(
            "INSERT INTO users (login, pass_hash, first_name, last_name, role) VALUES (?, ?, ?, ?, ?)",
            ("admin", admin_hash, "Admin", "Root", "admin")
        )
        con.commit()

    con.close()


# Пароли: PBKDF2

def make_pass_hash(password: str) -> str:
    # соль для каждого пароля своя
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    # храним "salt:hash" в hex
    return salt.hex() + ":" + dk.hex()


def verify_pass(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
        return dk == expected
    except Exception:
        return False


# Токены (сессии)

def create_session(user_id: int) -> str:
    token = str(uuid.uuid4())
    expire_at = int(time.time()) + TOKEN_TTL_SECONDS

    con = db_connect()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO sessions (token, user_id, expire_at) VALUES (?, ?, ?)",
        (token, user_id, expire_at)
    )
    con.commit()
    con.close()

    return token


def delete_session(token: str):
    con = db_connect()
    cur = con.cursor()
    cur.execute("DELETE FROM sessions WHERE token = ?", (token,))
    con.commit()
    con.close()


def get_user_by_token(token: str):
    now = int(time.time())

    con = db_connect()
    cur = con.cursor()
    cur.execute("""
        SELECT u.id, u.login, u.first_name, u.last_name, u.role, s.expire_at
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ?
    """, (token,))
    row = cur.fetchone()
    con.close()

    if row is None:
        return None

    user_id, login, first_name, last_name, role, expire_at = row
    if expire_at < now:
        # сессия протухла
        delete_session(token)
        return None

    return {
        "id": user_id,
        "login": login,
        "first_name": first_name,
        "last_name": last_name,
        "role": role
    }


# HTTP helper

class Handler(BaseHTTPRequestHandler):
    def send_json(self, code: int, data):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return None
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw)

    def get_token_from_headers(self) -> str:
        auth = self.headers.get("Authorization", "")
        if not auth:
            return ""

        parts = auth.split()
        if len(parts) == 2 and parts[0].lower() in ("token", "bearer"):
            return parts[1]
        return ""

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            return self.send_json(200, {
                "message": "Server is running",
                "endpoints": [
                    "POST /register",
                    "POST /login",
                    "POST /logout",
                    "GET  /me",
                    "GET  /admin/users (admin only)"
                ]
            })

        if path == "/me":
            token = self.get_token_from_headers()
            user = get_user_by_token(token)
            if not user:
                return self.send_json(401, {"error": "Unauthorized"})
            return self.send_json(200, {"user": user})

        if path == "/admin/users":
            token = self.get_token_from_headers()
            user = get_user_by_token(token)
            if not user:
                return self.send_json(401, {"error": "Unauthorized"})

            if user["role"] != "admin":
                return self.send_json(403, {"error": "Forbidden (admin only)"})

            con = db_connect()
            cur = con.cursor()
            cur.execute("SELECT id, login, first_name, last_name, role FROM users ORDER BY id")
            rows = cur.fetchall()
            con.close()

            users = []
            for r in rows:
                users.append({
                    "id": r[0],
                    "login": r[1],
                    "first_name": r[2],
                    "last_name": r[3],
                    "role": r[4],
                })
            return self.send_json(200, {"users": users})


        return self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/register":
            data = self.read_json() or {}
            login = (data.get("login") or "").strip()
            password = data.get("password") or ""
            password2 = data.get("password2") or ""
            first_name = (data.get("first_name") or "").strip()
            last_name = (data.get("last_name") or "").strip()

            if not login or not password:
                return self.send_json(400, {"error": "login and password are required"})
            if password != password2:
                return self.send_json(400, {"error": "passwords do not match"})
            if len(password) < 6:
                return self.send_json(400, {"error": "password too short (min 6)"})

            con = db_connect()
            cur = con.cursor()

            cur.execute("SELECT id FROM users WHERE login = ?", (login,))
            if cur.fetchone() is not None:
                con.close()
                return self.send_json(400, {"error": "login already exists"})

            pass_hash = make_pass_hash(password)
            cur.execute(
                "INSERT INTO users (login, pass_hash, first_name, last_name, role) VALUES (?, ?, ?, ?, ?)",
                (login, pass_hash, first_name, last_name, "user")
            )
            con.commit()
            user_id = cur.lastrowid
            con.close()

            return self.send_json(200, {"ok": True, "user_id": user_id})

        if path == "/login":
            data = self.read_json() or {}
            login = (data.get("login") or "").strip()
            password = data.get("password") or ""

            if not login or not password:
                return self.send_json(400, {"error": "login and password are required"})

            con = db_connect()
            cur = con.cursor()
            cur.execute("SELECT id, pass_hash, role, first_name, last_name FROM users WHERE login = ?", (login,))
            row = cur.fetchone()
            con.close()

            if row is None:
                return self.send_json(401, {"error": "Invalid credentials"})

            user_id, pass_hash, role, first_name, last_name = row
            if not verify_pass(password, pass_hash):
                return self.send_json(401, {"error": "Invalid credentials"})

            token = create_session(user_id)
            return self.send_json(200, {
                "token": token,
                "user": {
                    "id": user_id,
                    "login": login,
                    "first_name": first_name,
                    "last_name": last_name,
                    "role": role
                }
            })

        if path == "/logout":
            token = self.get_token_from_headers()
            if not token:
                return self.send_json(401, {"error": "Unauthorized"})
            delete_session(token)
            return self.send_json(200, {"ok": True})

        return self.send_json(404, {"error": "Not found"})


def main():
    init_db()
    server = HTTPServer((HOST, PORT), Handler)
    print(f"Server started: http://{HOST}:{PORT}")
    print("Admin user: login=admin password=admin123")
    server.serve_forever()


if __name__ == "__main__":
    main()
