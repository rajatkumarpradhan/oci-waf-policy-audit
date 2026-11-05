#!/bin/sh
# Runs the auditor against the seeded vulnerable sample and the corrected sample.
set -u
export PYTHONPATH="$(dirname "$0")/src"

echo "=== Auditing samples/insecure-waf-policy.json ==="
python3 -m oci_waf_policy_audit samples/insecure-waf-policy.json
echo "exit code: $? (2 = high-severity findings present, expected for the seeded sample)"
echo
echo "=== Auditing samples/hardened-waf-policy.json ==="
python3 -m oci_waf_policy_audit samples/hardened-waf-policy.json
echo "exit code: $? (0 = no high-severity findings, expected for the corrected sample)"
