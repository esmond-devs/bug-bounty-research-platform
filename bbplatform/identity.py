"""Local authenticated researcher accounts. Requires HTTPS/reverse-proxy auth for remote deployment."""
import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from .core import PolicyError

def init(db):
    db.execute("""CREATE TABLE IF NOT EXISTS users(
      username TEXT PRIMARY KEY, salt TEXT NOT NULL, password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('researcher','reviewer','admin')), enabled INTEGER NOT NULL DEFAULT 1)""")
    db.execute("""CREATE TABLE IF NOT EXISTS sessions(
      token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires TEXT NOT NULL)""")
    db.commit()

def create_user(db, username, password, role="researcher"):
    if not username or len(username) > 64 or not username.replace("_", "").replace("-", "").isalnum():
        raise PolicyError("Invalid username")
    if role not in ("researcher", "reviewer", "admin") or len(password) < 14:
        raise PolicyError("Invalid role or password shorter than 14 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1).hex()
    with db:
        db.execute("INSERT INTO users(username,salt,password_hash,role) VALUES(?,?,?,?)",
                   (username, salt.hex(), digest, role))

def authenticate(db, username, password):
    row = db.execute("SELECT salt,password_hash,role,enabled FROM users WHERE username=?", (username,)).fetchone()
    if not row or not row[3]:
        return None
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(row[0]), n=2**14, r=8, p=1).hex()
    return row[2] if hmac.compare_digest(digest, row[1]) else None

def login(db, username, password):
    role = authenticate(db, username, password)
    if role is None:
        raise PolicyError("Invalid credentials")
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()
    with db:
        db.execute("INSERT INTO sessions(token_hash,username,expires) VALUES(?,?,?)",
                   (hashlib.sha256(token.encode()).hexdigest(), username, expires))
    return token

def session_user(db, token):
    if not token:
        return None
    row = db.execute("""SELECT u.username,u.role,s.expires FROM sessions s JOIN users u
      ON u.username=s.username WHERE s.token_hash=? AND u.enabled=1""",
      (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
    if not row or datetime.fromisoformat(row[2]) <= datetime.now(timezone.utc):
        return None
    return (row[0], row[1])

def logout(db, token):
    with db:
        db.execute("DELETE FROM sessions WHERE token_hash=?",
                   (hashlib.sha256(token.encode()).hexdigest(),))

def require_role(user, roles):
    if not user or user[1] not in roles:
        raise PolicyError("Authenticated reviewer privileges required")
    return user[0]
