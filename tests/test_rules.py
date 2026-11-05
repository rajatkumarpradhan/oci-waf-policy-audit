import unittest

from oci_waf_policy_audit.rules import audit_document


def doc(policy):
    return {"waf_policies": [policy]}


def base_policy():
    return {
        "name": "p",
        "listeners": [{"name": "l", "protocol": "HTTPS", "port": 443}],
        "access_rules": [{"name": "r", "action": "CHECK", "condition": ""}],
        "rate_limiting": {"enabled": True, "requests_per_second": 100},
        "request_protection": {
            "enabled": True,
            "capabilities": [{"name": "SQL Injection", "version": 3, "enabled": True}],
        },
        "address_lists": [{"name": "a", "type": "WHITELIST", "addresses": ["10.0.0.0/8"]}],
    }


def rule_ids(findings):
    return {f.rule_id for f in findings}


class TestWafRules(unittest.TestCase):
    def test_clean_policy_has_no_findings(self):
        self.assertEqual(audit_document(doc(base_policy())), [])

    def test_waf001_no_access_rules(self):
        policy = base_policy()
        del policy["access_rules"]
        self.assertIn("WAF001", rule_ids(audit_document(doc(policy))))
        policy["access_rules"] = []
        self.assertIn("WAF001", rule_ids(audit_document(doc(policy))))

    def test_waf002_missing_rate_limiting(self):
        policy = base_policy()
        del policy["rate_limiting"]
        self.assertIn("WAF002", rule_ids(audit_document(doc(policy))))

    def test_waf002_disabled_rate_limiting(self):
        policy = base_policy()
        policy["rate_limiting"]["enabled"] = False
        self.assertIn("WAF002", rule_ids(audit_document(doc(policy))))

    def test_waf002_non_positive_limit(self):
        policy = base_policy()
        policy["rate_limiting"]["requests_per_second"] = 0
        self.assertIn("WAF002", rule_ids(audit_document(doc(policy))))

    def test_waf003_protection_disabled(self):
        policy = base_policy()
        policy["request_protection"]["enabled"] = False
        self.assertIn("WAF003", rule_ids(audit_document(doc(policy))))

    def test_waf003_all_capabilities_off(self):
        policy = base_policy()
        for cap in policy["request_protection"]["capabilities"]:
            cap["enabled"] = False
        self.assertIn("WAF003", rule_ids(audit_document(doc(policy))))

    def test_waf004_sensitive_path_allow(self):
        policy = base_policy()
        policy["access_rules"].append(
            {"name": "x", "action": "ALLOW", "condition": "http.request.url.path sw '/admin'"}
        )
        self.assertIn("WAF004", rule_ids(audit_document(doc(policy))))

    def test_waf004_sensitive_path_with_address_restriction_ok(self):
        policy = base_policy()
        policy["access_rules"].append(
            {
                "name": "x",
                "action": "ALLOW",
                "condition": "http.request.url.path sw '/admin' and i_in(http.request.remoteAddress, 'vpn')",
            }
        )
        self.assertNotIn("WAF004", rule_ids(audit_document(doc(policy))))

    def test_waf005_http_listener(self):
        policy = base_policy()
        policy["listeners"].append({"name": "h", "protocol": "HTTP", "port": 80})
        self.assertIn("WAF005", rule_ids(audit_document(doc(policy))))

    def test_waf006_anywhere_whitelist(self):
        policy = base_policy()
        policy["address_lists"][0]["addresses"] = ["0.0.0.0/0"]
        self.assertIn("WAF006", rule_ids(audit_document(doc(policy))))

    def test_waf006_scoped_whitelist_ok(self):
        findings = audit_document(doc(base_policy()))
        self.assertNotIn("WAF006", rule_ids(findings))

    def test_findings_sorted_high_first(self):
        policy = base_policy()
        del policy["access_rules"]          # WAF001 HIGH
        policy["rate_limiting"]["enabled"] = False  # WAF002 MEDIUM
        findings = audit_document(doc(policy))
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[-1].severity, "MEDIUM")

    def test_multiple_policies_all_audited(self):
        clean = base_policy()
        bad = base_policy()
        bad["name"] = "bad"
        del bad["access_rules"]
        findings = audit_document({"waf_policies": [clean, bad]})
        self.assertTrue(any(f.policy == "bad" for f in findings))
        self.assertFalse(any(f.policy == "p" for f in findings))

    def test_non_dict_policy_entries_skipped(self):
        findings = audit_document({"waf_policies": [None, "junk", base_policy()]})
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
