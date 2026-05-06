import os
import datetime
import hashlib
import secrets

import psycopg
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel


DATABASE_URL = os.environ["DATABASE_URL"]
ADMIN_API_KEY = os.environ["ADMIN_API_KEY"]

app = FastAPI()


class AdminUserCreate(BaseModel):
    username: str | None = None
    email: str | None = None
    password: str
    active: bool = True
    expires_at: datetime.datetime | None = None


class AdminUserUpdate(BaseModel):
    active: bool | None = None
    expires_at: datetime.datetime | None = None


class AuthChangePassword(BaseModel):
    old_password: str
    new_password: str


def _model_dict(model: BaseModel) -> dict:
    if hasattr(model, "model_dump"):
        return model.model_dump(exclude_unset=True)  # pydantic v2
    return model.dict(exclude_unset=True)  # pydantic v1



def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def pbkdf2_hash(password: str, salt_hex: str, iters: int) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
    return dk.hex()


def normalize_mac(value: str | None) -> str:
    raw = (value or "").strip().upper()
    hex_only = "".join([c for c in raw if c in "0123456789ABCDEF"])
    if len(hex_only) == 12:
        return hex_only
    return ""


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
                  bound_mac TEXT NULL,
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
                  device_mac TEXT NULL,
                  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_mac TEXT NULL")
            cur.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_mac TEXT NULL")
            con.commit()


@app.on_event("startup")
def _startup():
    init_db()


def require_admin(x_admin_key: str | None):
    if not x_admin_key or x_admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="admin")


@app.post("/admin/users")
async def admin_create_user(payload: AdminUserCreate, x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)
    username = (payload.username or "").strip() or None
    email = (payload.email or "").strip() or None
    password = payload.password or ""
    active = bool(payload.active)
    expires_at = payload.expires_at

    if not (username or email):
        raise HTTPException(400, "need username or email")
    if not password:
        raise HTTPException(400, "need password")

    salt = secrets.token_bytes(16).hex()
    iters = 200_000
    pwd_hash = pbkdf2_hash(password, salt, iters)

    with psycopg.connect(DATABASE_URL) as con:
        with con.cursor() as cur:
            try:
                cur.execute(
                    "INSERT INTO users(username,email,salt_hex,pwd_hash_hex,iterations,active,expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                    (username, email, salt, pwd_hash, iters, active, expires_at),
                )
                user_id = cur.fetchone()[0]
                con.commit()
            except Exception as e:
                try:
                    sqlstate = getattr(e, "sqlstate", None)
                except Exception:
                    sqlstate = None
                if sqlstate == "23505":
                    raise HTTPException(status_code=409, detail="username or email already exists")
                raise
    return {"id": user_id}


@app.patch("/admin/users/{user_id}")
async def admin_update_user(user_id: int, payload: AdminUserUpdate, x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)
    body = _model_dict(payload)
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


@app.get("/admin/users")
def admin_list_users(x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)
    with psycopg.connect(DATABASE_URL) as con:
        with con.cursor() as cur:
            cur.execute("SELECT id,username,email,active,expires_at,created_at FROM users ORDER BY id DESC")
            rows = cur.fetchall()
    users = []
    for row in rows:
        user_id, username, email, active, expires_at, created_at = row
        users.append(
            {
                "id": user_id,
                "username": username,
                "email": email,
                "active": bool(active),
                "expires_at": expires_at,
                "created_at": created_at,
            }
        )
    return {"users": users}


@app.get("/admin/dbinfo")
def admin_dbinfo(x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)
    with psycopg.connect(DATABASE_URL) as con:
        with con.cursor() as cur:
            cur.execute("SELECT current_database(), current_user, current_schema()")
            db, user, schema = cur.fetchone()
            cur.execute("SELECT COUNT(*) FROM users")
            users_count = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM sessions")
            sessions_count = int(cur.fetchone()[0])
    return {
        "database": db,
        "user": user,
        "schema": schema,
        "users_count": users_count,
        "sessions_count": sessions_count,
    }


@app.post("/auth/login")
async def login(req: Request):
    body = await req.json()
    identifier = (body.get("identifier") or "").strip()
    password = body.get("password") or ""
    device_mac = normalize_mac(body.get("device_mac"))
    if not identifier or not password:
        raise HTTPException(401, "bad")
    if not device_mac:
        raise HTTPException(400, "device")

    is_email = "@" in identifier
    with psycopg.connect(DATABASE_URL) as con:
        with con.cursor() as cur:
            if is_email:
                cur.execute(
                    "SELECT id,salt_hex,pwd_hash_hex,iterations,active,expires_at,bound_mac FROM users WHERE email=%s",
                    (identifier,),
                )
            else:
                cur.execute(
                    "SELECT id,salt_hex,pwd_hash_hex,iterations,active,expires_at,bound_mac FROM users WHERE username=%s OR email=%s",
                    (identifier, identifier),
                )
            row = cur.fetchone()
            if not row:
                raise HTTPException(401, "bad")

            user_id, salt, pwd_hash, iters, active, expires_at, bound_mac = row
            if not active:
                raise HTTPException(403, "revoked")
            if expires_at is not None and expires_at <= now_utc():
                raise HTTPException(403, "expired")

            calc = pbkdf2_hash(password, salt, int(iters))
            if not secrets.compare_digest(calc, pwd_hash):
                raise HTTPException(401, "bad")

            if bound_mac:
                if normalize_mac(bound_mac) != device_mac:
                    raise HTTPException(403, "device")
            else:
                cur.execute("UPDATE users SET bound_mac=%s WHERE id=%s", (device_mac, user_id))

            session_token = secrets.token_urlsafe(32)
            token_hash = sha256(session_token)
            exp = now_utc() + datetime.timedelta(minutes=30)

            cur.execute(
                "INSERT INTO sessions(token_hash,user_id,expires_at,device_mac) VALUES (%s,%s,%s,%s)",
                (token_hash, user_id, exp, device_mac),
            )
            con.commit()

    return {"session_token": session_token, "expires_in": 1800}


@app.get("/auth/check")
def check(
    authorization: str | None = Header(default=None),
    x_device_mac: str | None = Header(default=None),
):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "no token")
    token = authorization.split(" ", 1)[1].strip()
    th = sha256(token)
    device_mac = normalize_mac(x_device_mac)
    if not device_mac:
        return {"ok": False}

    with psycopg.connect(DATABASE_URL) as con:
        with con.cursor() as cur:
            cur.execute(
                """
                SELECT u.active,u.expires_at,s.expires_at,u.bound_mac,s.device_mac
                FROM sessions s
                JOIN users u ON u.id=s.user_id
                WHERE s.token_hash=%s
                """,
                (th,),
            )
            row = cur.fetchone()
            if not row:
                return {"ok": False}
            active, uexp, sexp, bound_mac, session_mac = row
            if not active:
                return {"ok": False}
            if uexp is not None and uexp <= now_utc():
                return {"ok": False}
            if sexp is not None and sexp <= now_utc():
                return {"ok": False}
            if normalize_mac(bound_mac) != device_mac:
                return {"ok": False}
            if session_mac and normalize_mac(session_mac) != device_mac:
                return {"ok": False}
    return {"ok": True}


@app.post("/auth/change_password")
async def change_password(
    payload: AuthChangePassword,
    authorization: str | None = Header(default=None),
    x_device_mac: str | None = Header(default=None),
):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "no token")
    token = authorization.split(" ", 1)[1].strip()
    th = sha256(token)
    device_mac = normalize_mac(x_device_mac)
    if not device_mac:
        raise HTTPException(401, "device")

    old_password = payload.old_password or ""
    new_password = payload.new_password or ""
    if not old_password or not new_password:
        raise HTTPException(400, "bad")
    if len(new_password) < 4:
        raise HTTPException(400, "password too short")

    with psycopg.connect(DATABASE_URL) as con:
        with con.cursor() as cur:
            cur.execute(
                """
                SELECT u.id,u.salt_hex,u.pwd_hash_hex,u.iterations,u.active,u.expires_at,s.expires_at,u.bound_mac,s.device_mac
                FROM sessions s
                JOIN users u ON u.id=s.user_id
                WHERE s.token_hash=%s
                """,
                (th,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(401, "no token")
            user_id, salt, pwd_hash, iters, active, uexp, sexp, bound_mac, session_mac = row
            if not active:
                raise HTTPException(403, "revoked")
            if uexp is not None and uexp <= now_utc():
                raise HTTPException(403, "expired")
            if sexp is not None and sexp <= now_utc():
                raise HTTPException(403, "expired")
            if normalize_mac(bound_mac) != device_mac:
                raise HTTPException(403, "device")
            if session_mac and normalize_mac(session_mac) != device_mac:
                raise HTTPException(403, "device")

            calc = pbkdf2_hash(old_password, salt, int(iters))
            if not secrets.compare_digest(calc, pwd_hash):
                raise HTTPException(401, "bad")

            new_salt = secrets.token_bytes(16).hex()
            new_iters = 200_000
            new_hash = pbkdf2_hash(new_password, new_salt, new_iters)

            cur.execute(
                "UPDATE users SET salt_hex=%s,pwd_hash_hex=%s,iterations=%s WHERE id=%s",
                (new_salt, new_hash, int(new_iters), int(user_id)),
            )
            cur.execute("DELETE FROM sessions WHERE user_id=%s AND token_hash<>%s", (int(user_id), th))
            con.commit()

    return {"ok": True}
