# oci-waf-policy-audit

Offline auditor for **simplified OCI Web Application Firewall (WAF) policy exports**. It reads a static JSON document describing one or more WAF policies and reports posture findings: missing access control, absent rate limiting, disabled request protection, exposed sensitive paths, unencrypted listeners, and whitelist bypasses.

## What it is

A command-line review tool for WAF configuration-as-data. Point it at a policy JSON, get a severity-sorted findings list and an exit code suitable for CI gates.

- Runs 100% locally. No OCI SDK, no credentials, no network calls.
- Six rules (WAF001-WAF006), each unit-tested on positive and negative inputs.
- Exit code 2 when any HIGH finding exists, so a pipeline can block a risky policy change; 0 when no HIGH finding exists; 1 on unreadable or malformed input.

## What it is NOT (honest limits)

- The input schema is a **simplified approximation** of the parts of an OCI WAF policy that matter for posture review. It is not the OCI API response shape, and the tool does not fetch policies from a tenancy.
- WAF004's sensitive-path and address-restriction detection is a string heuristic over the `condition` field, not a full parser of the OCI WAF rule condition language.
- The tool reviews configuration posture only. It cannot measure live traffic, attack pressure, or actual block rates.
- Findings are advisory review signals, not proof of exploitability; a "clean" result is not a guarantee of security.

## Input schema

```json
{
  "waf_policies": [
    {
      "name": "edge-waf",
      "listeners": [{"name": "https", "protocol": "HTTPS", "port": 443}],
      "access_rules": [{"name": "r", "action": "ALLOW|BLOCK|CHECK", "condition": "..."}],
      "rate_limiting": {"enabled": true, "requests_per_second": 200, "action": "BLOCK"},
      "request_protection": {
        "enabled": true,
        "capabilities": [{"name": "SQL Injection", "version": 3, "enabled": true}]
      },
      "address_lists": [{"name": "vpn", "type": "WHITELIST", "addresses": ["203.0.113.8/32"]}]
    }
  ]
}
```

## Rules

| Rule | Severity | Finding |
| --- | --- | --- |
| WAF001 | HIGH | Policy has no access control rules; all traffic reaches the origin unfiltered |
| WAF002 | MEDIUM | Rate limiting missing, disabled, or without a positive request limit |
| WAF003 | HIGH | Request protection disabled, or enabled with every capability switched off |
| WAF004 | MEDIUM | ALLOW rule on a sensitive path (`/admin`, `/internal`, `/manage`, `/debug`) with no address restriction in its condition |
| WAF005 | HIGH | WAF fronting a plain HTTP listener (credentials cross unencrypted) |
| WAF006 | MEDIUM | WHITELIST address list containing `0.0.0.0/0` or `::/0`, which matches every client |

## Run

Requires Python 3.10+, no third-party dependencies.

```sh
PYTHONPATH=src python3 -m oci_waf_policy_audit samples/insecure-waf-policy.json
PYTHONPATH=src python3 -m oci_waf_policy_audit samples/hardened-waf-policy.json
```

Or the end-to-end demo (vulnerable sample -> corrected sample, with expected exit codes):

```sh
sh demo.sh
```

Expected demo output: the seeded sample reports 3 high and 4 medium findings and exits 2; the corrected sample reports zero findings and exits 0.

## Test

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

19 unit tests cover every rule on positive and negative inputs, finding sort order, malformed-input handling, and CLI exit codes. CI runs the same tests plus the demo on Python 3.10/3.11/3.12.
