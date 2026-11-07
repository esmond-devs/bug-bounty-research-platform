"""Program authorization evidence registry: verified means reviewed, not legally proven."""
import hashlib
import json
from datetime import datetime, timezone
from .core import PolicyError, normalize_host

def init(db):
    db.execute("""CREATE TABLE IF NOT EXISTS ownership_evidence (
      id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL,
      program TEXT NOT NULL, reference TEXT NOT NULL,
      network_attestation TEXT NOT NULL, cname_attestation TEXT NOT NULL,
      submitted_by TEXT NOT NULL, reviewed_by TEXT,
      status TEXT NOT NULL DEFAULT 'pending', expires TEXT,
      created TEXT NOT NULL)""")
    db.commit()

def submit(db, host, program, reference, networks, cnames, actor):
    host = normalize_host(host)
    if not all((program.strip(), reference.strip(), actor.strip())):
        raise PolicyError("Program and evidence reference required")
    with db:
        cur = db.execute("""INSERT INTO ownership_evidence
          (host,program,reference,network_attestation,cname_attestation,submitted_by,created)
          VALUES(?,?,?,?,?,?,?)""",
          (host, program[:120], reference[:500], json.dumps(networks),
           json.dumps(cnames), actor, datetime.now(timezone.utc).isoformat()))
    return cur.lastrowid

def review(db, evidence_id, reviewer, approved, expires):
    with db:
        row = db.execute("SELECT submitted_by,status FROM ownership_evidence WHERE id=?", (evidence_id,)).fetchone()
        if not row or row[1] != "pending" or row[0] == reviewer:
            raise PolicyError("Evidence requires independent review")
        db.execute("""UPDATE ownership_evidence SET status=?,reviewed_by=?,expires=? WHERE id=?""",
                   ("verified" if approved else "rejected", reviewer, expires if approved else None, evidence_id))

def require_evidence(db, host, policy, program):
    rows = db.execute("""SELECT network_attestation,cname_attestation,expires FROM ownership_evidence
      WHERE host=? AND program=? AND status='verified' ORDER BY id DESC""",
      (normalize_host(host), program)).fetchall()
    for networks, cnames, expires in rows:
        if not expires:
            continue
        if datetime.fromisoformat(expires) <= datetime.now(timezone.utc):
            continue
        if set(json.loads(networks)) == set(policy.authorized_ip_cidrs) and set(json.loads(cnames)) == set(policy.authorized_cname_suffixes):
            return True
    raise PolicyError("Missing current independently reviewed program/infrastructure evidence")
