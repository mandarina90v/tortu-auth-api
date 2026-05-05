import os
import datetime
import hashlib
import secrets

import psycopg
from fastapi import FastAPI, Header, HTTPException, Request


DATABASE_URL = os.environ["DATABASE_URL"]
ADMIN_API_KEY = os.environ["ADMIN_API_KEY"]

app = FastAPI()


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def pbkdf2_hash(password: str, salt_hex: str, iters: int) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
    return dk.hex()


def init_db():
    with psycopg.connect(DATABASE_URL) as con:
        with con.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users(
                  id SERIAL PRIMARY KEY,
                  username TEXT UNIQUE,
                  email TEXT UNIQUE,
                  salt_hex TEXT NOT NULL,
                  pwd_hash_hex TEXT NOT NULL,
                  iterations INT NOT NULL,
                  active BOOLEAN NOT NULL DEFAULT TRUE,
                  expires_at TIMESTAMPTZ NULL,
                  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions(
                  token_hash TEXT PRIMARY KEY,
                  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                  expires_at TIMESTAMPTZ NOT NULL,
                  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )
            con.commit()


@app.on_event("startup")
def _startup():
    init_db()


def require_admin(x_admin_key: str | None):
    if not x_admin_key or x_admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="admin")


@app.post("/admin/users")
async def admin_create_user(req: Request, x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)
    body = await req.json()
    username = (body.get("username") or "").strip() or None
    email = (body.get("email") or "").strip() or None
    password = body.get("password") or ""
    active = bool(body.get("active", True))
    expires_at = body.get("expires_at")

    if not (username or email):
        raise HTTPException(400, "need username or email")
    if not password:
        raise HTTPException(400, "need password")

    salt = secrets.token_bytes(16).hex()
    iters = 200_000
    pwd_hash = pbkdf2_hash(password, salt, iters)

    with psycopg.connect(DATABASE_URL) as con:
        with con.cursor() as cur:
            cur.execute(
                "INSERT INTO users(username,email,salt_hex,pwd_hash_hex,iterations,active,expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (username, email, salt, pwd_hash, iters, active, expires_at),
            )
            user_id = cur.fetchone()[0]
            con.commit()
    return {"id": user_id}


@app.patch("/admin/users/{user_id}")
async def admin_update_user(user_id: int, req: Request, x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)
    body = await req.json()
    active = body.get("active")
    expires_at = body.get("expires_at")

    sets = []
    vals = []
    if active is not None:
        sets.append("active=%s")
        vals.append(bool(active))
    if "expires_at" in body:
        sets.append("expires_at=%s")
        vals.append(expires_at)
    if not sets:
        return {"ok": True}

    vals.append(user_id)
    with psycopg.connect(DATABASE_URL) as con:
        with con.cursor() as cur:
            cur.execute(f"UPDATE users SET {','.join(sets)} WHERE id=%s", vals)
            con.commit()
    return {"ok": True}


@app.post("/auth/login")
async def login(req: Request):
    body = await req.json()
    identifier = (body.get("identifier") or "").strip()
    password = body.get("password") or ""
    if not identifier or not password:
        raise HTTPException(401, "bad")

    is_email = "@" in identifier
    with psycopg.connect(DATABASE_URL) as con:
        with con.cursor() as cur:
            if is_email:
                cur.execute("SELECT id,salt_hex,pwd_hash_hex,iterations,active,expires_at FROM users WHERE email=%s", (identifier,))
            else:
                cur.execute(
                    "SELECT id,salt_hex,pwd_hash_hex,iterations,active,expires_at FROM users WHERE username=%s OR email=%s",
                    (identifier, identifier),
                )
            row = cur.fetchone()
            if not row:
                raise HTTPException(401, "bad")

            user_id, salt, pwd_hash, iters, active, expires_at = row
            if not active:
                raise HTTPException(403, "revoked")
            if expires_at is not None and expires_at <= now_utc():
                raise HTTPException(403, "expired")

            calc = pbkdf2_hash(password, salt, int(iters))
            if not secrets.compare_digest(calc, pwd_hash):
                raise HTTPException(401, "bad")

            session_token = secrets.token_urlsafe(32)
            token_hash = sha256(session_token)
            exp = now_utc() + datetime.timedelta(minutes=30)

            cur.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES (%s,%s,%s)", (token_hash, user_id, exp))
            con.commit()

    return {"session_token": session_token, "expires_in": 1800}


@app.get("/auth/check")
def check(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "no token")
    token = authorization.split(" ", 1)[1].strip()
    th = sha256(token)

    with psycopg.connect(DATABASE_URL) as con:
        with con.cursor() as cur:
            cur.execute(
                """
                SELECT u.active,u.expires_at,s.expires_at
                FROM sessions s
                JOIN users u ON u.id=s.user_id
                WHERE s.token_hash=%s
                """,
                (th,),
            )
            row = cur.fetchone()
            if not row:
                return {"ok": False}
            active, uexp, sexp = row
            if not active:
                return {"ok": False}
            if uexp is not None and uexp <= now_utc():
                return {"ok": False}
            if sexp is not None and sexp <= now_utc():
                return {"ok": False}
    return {"ok": True}