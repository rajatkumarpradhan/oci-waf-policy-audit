"""Audit rules for simplified OCI WAF policy documents.

The input schema is a static, simplified JSON approximation of the parts of an
OCI Web Application Firewall (WAF) policy that matter for posture review. It is
NOT the OCI API shape; see README.md for the documented schema. All analysis is
offline - no OCI calls, no live policy inspection.
"""

from dataclasses import dataclass, field
from ipaddress import ip_network

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    policy: str
    message: str


def _as_bool(value):
    return value is True


def _is_anywhere(address):
    try:
        return ip_network(address, strict=False).prefixlen == 0
    except ValueError:
        return False


def rule_no_access_rules(policy):
    """WAF001: policy defines no access control rules."""
    if not policy.get("access_rules"):
        yield Finding(
            "WAF001", "HIGH", policy.get("name", "<unnamed>"),
            "policy has no access control rules; every request reaches the origin unfiltered",
        )


def rule_rate_limiting(policy):
    """WAF002: rate limiting missing or disabled."""
    rl = policy.get("rate_limiting")
    name = policy.get("name", "<unnamed>")
    if rl is None:
        yield Finding("WAF002", "MEDIUM", name,
                      "no rate limiting configured; origin is exposed to request floods")
    elif not _as_bool(rl.get("enabled")):
        yield Finding("WAF002", "MEDIUM", name,
                      "rate limiting is present but disabled")
    elif not isinstance(rl.get("requests_per_second"), int) or rl["requests_per_second"] <= 0:
        yield Finding("WAF002", "MEDIUM", name,
                      "rate limiting has no positive requests_per_second limit")


def rule_request_protection(policy):
    """WAF003: request protection disabled or all capabilities off."""
    rp = policy.get("request_protection")
    name = policy.get("name", "<unnamed>")
    if rp is None or not _as_bool(rp.get("enabled")):
        yield Finding("WAF003", "HIGH", name,
                      "request protection is not enabled; common web attacks are not inspected")
        return
    caps = rp.get("capabilities") or []
    if not any(_as_bool(c.get("enabled")) for c in caps):
        yield Finding("WAF003", "HIGH", name,
                      "request protection is enabled but every protection capability is off")


def rule_sensitive_path_allow(policy):
    """WAF004: ALLOW rule exposing a sensitive path without an address restriction."""
    sensitive = ("/admin", "/internal", "/manage", "/debug")
    name = policy.get("name", "<unnamed>")
    for rule in policy.get("access_rules") or []:
        if rule.get("action") != "ALLOW":
            continue
        cond = (rule.get("condition") or "").lower()
        if any(p in cond for p in sensitive) and not any(
            k in cond for k in ("i_in(", "address", "ip")
        ):
            yield Finding(
                "WAF004", "MEDIUM", name,
                f"rule '{rule.get('name', '<unnamed>')}' allows a sensitive path without an address restriction",
            )


def rule_http_listener(policy):
    """WAF005: WAF fronting an unencrypted HTTP listener."""
    name = policy.get("name", "<unnamed>")
    for listener in policy.get("listeners") or []:
        if (listener.get("protocol") or "").upper() == "HTTP":
            yield Finding(
                "WAF005", "HIGH", name,
                f"listener '{listener.get('name', '<unnamed>')}' uses plain HTTP; credentials and tokens cross unencrypted",
            )


def rule_anywhere_whitelist(policy):
    """WAF006: WHITELIST address list that effectively allows the whole internet."""
    name = policy.get("name", "<unnamed>")
    for alist in policy.get("address_lists") or []:
        if (alist.get("type") or "").upper() != "WHITELIST":
            continue
        for addr in alist.get("addresses") or []:
            if _is_anywhere(addr):
                yield Finding(
                    "WAF006", "MEDIUM", name,
                    f"whitelist '{alist.get('name', '<unnamed>')}' contains {addr}, which matches every client",
                )


RULES = (
    rule_no_access_rules,
    rule_rate_limiting,
    rule_request_protection,
    rule_sensitive_path_allow,
    rule_http_listener,
    rule_anywhere_whitelist,
)


def audit_document(document):
    """Run every rule over a parsed document and return sorted findings."""
    findings = []
    for policy in document.get("waf_policies") or []:
        if not isinstance(policy, dict):
            continue
        for rule in RULES:
            findings.extend(rule(policy))
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.policy, f.message))
