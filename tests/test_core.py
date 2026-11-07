import unittest
from unittest.mock import patch
from bbplatform.core import Policy, PolicyError, matches, normalize_host, recommend, run

class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.p = Policy(["example.com", "*.example.com"], ["admin.example.com"])

    def test_exact_and_wildcard(self):
        self.assertEqual(self.p.require("example.com"), "example.com")
        self.assertEqual(self.p.require("www.example.com"), "www.example.com")

    def test_exclusion(self):
        with self.assertRaises(PolicyError):
            self.p.require("admin.example.com")

    def test_suffix_attack(self):
        with self.assertRaises(PolicyError):
            self.p.require("example.com.evil.org")

    def test_wildcard_does_not_include_apex(self):
        self.assertFalse(matches("example.com", "*.example.com"))

    def test_active_denied(self):
        with self.assertRaises(PolicyError):
            self.p.require("example.com", active=True)

    def test_explanations(self):
        self.assertTrue(all(x["why"] and x["next_step"] for x in recommend({})))

    def test_scope_only_no_network(self):
        with patch("bbplatform.core.check_https") as check:
            result = run(self.p, ["example.com", "admin.example.com"], False)
            check.assert_not_called()
            self.assertEqual(result[0]["scope"], "allowed")
            self.assertEqual(result[1]["scope"], "rejected_or_failed")

if __name__ == "__main__":
    unittest.main()
