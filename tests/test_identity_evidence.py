import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone
from bbplatform.approvals import connect
from bbplatform.identity import init as init_users, create_user, authenticate, login, session_user
from bbplatform.evidence import init as init_evidence, submit, review, require_evidence
from bbplatform.audit_chain import init as init_audit, append, verify
from bbplatform.core import Policy, PolicyError

class IdentityEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = connect(str(Path(self.tmp.name) / "test.sqlite"))
        init_users(self.db); init_evidence(self.db); init_audit(self.db)

    def tearDown(self):
        self.db.close(); self.tmp.cleanup()

    def test_authenticated_role_and_session(self):
        create_user(self.db, "researcher", "a strong password with 20 chars", "researcher")
        self.assertIsNone(authenticate(self.db, "researcher", "wrong password"))
        token = login(self.db, "researcher", "a strong password with 20 chars")
        self.assertEqual(session_user(self.db, token), ("researcher", "researcher"))

    def test_independent_evidence_review(self):
        p = Policy(["example.com"], [], True, True, 1, 100, ("8.8.8.0/24",), ())
        ident = submit(self.db, "example.com", "program-123", "scope record",
                       p.authorized_ip_cidrs, p.authorized_cname_suffixes, "alice")
        with self.assertRaises(PolicyError):
            review(self.db, ident, "alice", True, "2099-01-01T00:00:00+00:00")
        review(self.db, ident, "bob", True, "2099-01-01T00:00:00+00:00")
        self.assertTrue(require_evidence(self.db, "example.com", p, "program-123"))

    def test_audit_detects_change(self):
        head = append(self.db, "alice", "request", "example.com", "test")
        self.assertEqual(verify(self.db, head)["entries"], 1)
        self.db.execute("UPDATE audit_chain SET detail='tampered'")
        self.db.commit()
        with self.assertRaises(PolicyError):
            verify(self.db, head)

if __name__ == "__main__":
    unittest.main()
