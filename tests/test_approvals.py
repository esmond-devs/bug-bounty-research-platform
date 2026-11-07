import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from bbplatform.core import Policy, PolicyError
from bbplatform.approvals import connect, request, decide, require_approval, events
from bbplatform.ownership import check_ownership

class OwnershipAndApprovalTests(unittest.TestCase):
    def setUp(self):
        self.policy = Policy(["example.com", "*.example.com"], [], True, True, 1, 100,
                             ("8.8.8.0/24",), ("*.example.net",))
        self.tmp = tempfile.TemporaryDirectory()
        self.db = connect(str(Path(self.tmp.name) / "approvals.sqlite3"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_independent_reviewer_and_expiring_approval(self):
        ident = request(self.db, self.policy, "www.example.com", "Program permits HEAD", "alice")
        with self.assertRaises(PolicyError):
            decide(self.db, self.policy, ident, "alice", True)
        decide(self.db, self.policy, ident, "bob", True)
        self.assertEqual(require_approval(self.db, self.policy, ident, "www.example.com"), "www.example.com")
        with self.assertRaises(PolicyError):
            require_approval(self.db, self.policy, ident, "other.example.com")
        self.assertEqual(len(events(self.db)), 2)

    def test_policy_change_invalidates_approval(self):
        ident = request(self.db, self.policy, "www.example.com", "Program permits HEAD", "alice")
        decide(self.db, self.policy, ident, "bob", True)
        self.policy.authorized_cname_suffixes = ("*.other.net",)
        with self.assertRaises(PolicyError):
            require_approval(self.db, self.policy, ident, "www.example.com")

    def test_cname_requires_declared_suffix(self):
        class Record:
            def __init__(self, target): self.target = target
        def resolver(name, record_type):
            if name == "www.example.com":
                return [Record("edge.example.net.")]
            class NoAnswer(Exception): pass
            raise NoAnswer()
        result = check_ownership("www.example.com", self.policy, ["8.8.8.8"], resolver=resolver)
        self.assertEqual(result["chain"], ["www.example.com", "edge.example.net"])
        self.policy.authorized_cname_suffixes = ()
        with self.assertRaises(PolicyError):
            check_ownership("www.example.com", self.policy, ["8.8.8.8"], resolver=resolver)

    def test_no_approved_network(self):
        self.policy.authorized_ip_cidrs = ()
        with self.assertRaises(PolicyError):
            check_ownership("www.example.com", self.policy, ["8.8.8.8"], resolver=lambda *args: [])

if __name__ == "__main__":
    unittest.main()
