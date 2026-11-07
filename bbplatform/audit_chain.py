"""Hash-linked append-only-at-application-layer audit events.

A local administrator can rewrite the database and recompute hashes; export and
anchor head hashes in independent immutable storage for actual tamper evidence.
"""
import hashlib
import json
from datetime import datetime, timezone
from .core import PolicyError

def init(db):
    db.execute("""CREATE TABLE IF NOT EXISTS audit_chain (
      id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,
      actor TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL,
      detail TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL)""")
    db.commit()

def digest(values):
    return hashlib.sha256(json.dumps(values, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

def append(db, actor, action, subject, detail):
    # Caller must serialize writes in a single SQLite transaction / connection.
    previous = db.execute("SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1").fetchone()
    previous_hash = previous[0] if previous else "0" * 64
    fields = [datetime.now(timezone.utc).isoformat(), actor, action, subject, detail, previous_hash]
    entry_hash = digest(fields)
    with db:
        db.execute("""INSERT INTO audit_chain(at,actor,action,subject,detail,previous_hash,entry_hash)
          VALUES(?,?,?,?,?,?,?)""", (*fields, entry_hash))
    return entry_hash

def verify(db, expected_head=None):
    rows = db.execute("""SELECT at,actor,action,subject,detail,previous_hash,entry_hash
      FROM audit_chain ORDER BY id""").fetchall()
    previous = "0" * 64
    for row in rows:
        if row[5] != previous or digest(list(row[:6])) != row[6]:
            raise PolicyError("Audit chain verification failed")
        previous = row[6]
    if expected_head is not None and previous != expected_head:
        raise PolicyError("Audit head differs from independently anchored head")
    return {"entries": len(rows), "head": previous}
