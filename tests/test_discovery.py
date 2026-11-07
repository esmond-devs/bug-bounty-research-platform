import unittest
from bbplatform.core import Policy, PolicyError
from bbplatform.discovery import certificate_transparency
from bbplatform.guard import authorized_addresses

class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.p = Policy(["example.com", "*.example.com"], ["admin.example.com"])

    def test_candidates_filtered_and_tagged(self):
        fake = lambda url: [{"name_value": "www.example.com\nadmin.example.com\nevil.org\n*.api.example.com"}]
        found = certificate_transparency("example.com", self.p, fetch=fake)
        self.assertEqual([x["host"] for x in found], ["admin.example.com", "api.example.com", "www.example.com"])
        self.assertEqual(found[0]["scope"], "candidate_excluded")

    def test_out_of_scope_root_rejected_before_fetch(self):
        with self.assertRaises(PolicyError):
            certificate_transparency("evil.org", self.p, fetch=lambda url: self.fail("must not fetch"))

    def test_network_denied_without_cidrs(self):
        with self.assertRaises(PolicyError):
            authorized_addresses(["8.8.8.8"], [])

    def test_mixed_network_denied(self):
        with self.assertRaises(PolicyError):
            authorized_addresses(["8.8.8.8", "1.1.1.1"], ["8.8.8.0/24"])

if __name__ == "__main__":
    unittest.main()
