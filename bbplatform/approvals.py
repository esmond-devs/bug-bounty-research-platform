"""SQLite approval queue and append-only event records (local MVP)."""
import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .core import PolicyError, normalize_host

def now():
    return datetime.now(timezone.utc).isoformat()

def connect(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10)
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("""CREATE TABLE IF NOT EXISTS requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL,
      reason TEXT NOT NULL, requester TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending', created TEXT NOT NULL,
      decided TEXT, reviewer TEXT, expires TEXT, policy_sha TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,
      actor TEXT NOT NULL, action TEXT NOT NULL, request_id INTEGER,
      detail TEXT NOT NULL)""")
    db.commit()
    return db

def fingerprint(policy):
    data = {"include": policy.includes, "exclude": policy.excludes,
            "active_http": policy.active_http, "approved": policy.approved,
            "cidrs": policy.authorized_ip_cidrs}
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

def request(db, policy, host, reason, requester):
    host = policy.require(normalize_host(host))
    if not reason.strip() or not requester.strip():
        raise PolicyError("Requester and justification are required")
    with db:
        cur = db.execute("INSERT INTO requests(host,reason,requester,created,policy_sha) VALUES(?,?,?,?,?)",
                         (host, reason[:500], requester[:100], now(), fingerprint(policy)))
        db.execute("INSERT INTO audit(at,actor,action,request_id,detail) VALUES(?,?,?,?,?)",
                   (now(), requester[:100], "request", cur.lastrowid, host))
    return cur.lastrowid

def decide(db, policy, request_id, reviewer, approve, ttl_hours=24):
    if not reviewer.strip():
        raise PolicyError("Reviewer required")
    if not 1 <= ttl_hours <= 72:
        raise PolicyError("Approval expiry must be 1-72 hours")
    with db:
        row = db.execute("SELECT host,status,requester,policy_sha FROM requests WHERE id=?",
                         (request_id,)).fetchone()
        if not row or row[1] != "pending":
            raise PolicyError("Request is not pending")
        if reviewer.strip() == row[2]:
            raise PolicyError("Requester cannot approve or reject their own request")
        policy.require(row[0])
        if row[3] != fingerprint(policy):
            raise PolicyError("Policy changed; submit a new request")
        expires = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat() if approve else None
        status = "approved" if approve else "rejected"
        db.execute("UPDATE requests SET status=?,reviewer=?,decided=?,expires=? WHERE id=?",
                   (status, reviewer[:100], now(), expires, request_id))
        db.execute("INSERT INTO audit(at,actor,action,request_id,detail) VALUES(?,?,?,?,?)",
                   (now(), reviewer[:100], status, request_id, row[0]))

def require_approval(db, policy, request_id, host):
    host = policy.require(host, active=True)
    row = db.execute("SELECT host,status,expires,policy_sha FROM requests WHERE id=?",
                     (request_id,)).fetchone()
    if not row or row[0] != host or row[1] != "approved" or row[3] != fingerprint(policy):
        raise PolicyError("No matching approved request for this host and policy")
    if not row[2] or datetime.fromisoformat(row[2]) <= datetime.now(timezone.utc):
        raise PolicyError("Approval expired")
    return host

def audit_event(db, actor, action, request_id, detail):
    with db:
        db.execute("INSERT INTO audit(at,actor,action,request_id,detail) VALUES(?,?,?,?,?)",
                   (now(), actor, action, request_id, str(detail)[:500]))

def requests(db):
    return db.execute("SELECT id,host,reason,requester,status,created,reviewer,expires FROM requests ORDER BY id DESC LIMIT 200").fetchall()

def events(db):
    return db.execute("SELECT at,actor,action,request_id,detail FROM audit ORDER BY id DESC LIMIT 200").fetchall()
