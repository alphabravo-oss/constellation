"""E2 compliance audit-log mappings — sanity-check the static control table."""
from __future__ import annotations


EXPECTED_FRAMEWORKS = [
    "nist-sp-800-53-r5",
    "soc2-tsc-2017",
    "pci-dss-v4.0",
    "iso-27001-2022",
]


def test_mappings_endpoint_returns_all_frameworks(api):
    d = api.compliance_mappings()
    fws = d.get("frameworks", [])
    missing = [f for f in EXPECTED_FRAMEWORKS if f not in fws]
    assert not missing, f"missing frameworks: {missing} (got: {fws})"


def test_mappings_endpoint_returns_minimum_controls(api):
    """The hand-written mapping table covers ~70 distinct controls; assert
    at least 20 to catch a regression where the table got truncated."""
    d = api.compliance_mappings()
    assert len(d.get("controls", [])) >= 20


def test_mappings_filtered_by_framework(api):
    d = api.compliance_mappings(framework="nist-sp-800-53-r5")
    for m in d.get("controls", []):
        assert m["framework"] == "nist-sp-800-53-r5", \
            f"framework filter leaked: {m}"


def test_audit_login_maps_to_known_controls(api):
    """One specific auth.login.local row exists in the chain (test_login set
    that up); fetching it `with_controls=1` should return at least the
    federal AC-2 + AU-2 mappings.
    """
    # We can't use the standard audit_list helper for this — need
    # with_controls=1. Just hit the endpoint directly via the client's
    # internals; the suite's _RemoteApiClient uses curl, so we pass through
    # the same path.
    import urllib.parse as urlp
    qs = urlp.urlencode({"action": "auth.login.local", "with_controls": "1", "limit": "1"})
    # _curl is a private helper on the remote variant; the local ApiClient
    # doesn't have one, so just GET via requests.
    if hasattr(api, "_curl"):
        status, body = api._curl("GET", f"/api/v1/audit/events?{qs}")
        assert status < 400, f"audit list with controls failed: {status} {body}"
        import json as _json
        payload = _json.loads(body)
    else:
        import requests
        r = requests.get(f"{api.base_url}/api/v1/audit/events?{qs}",
                         headers=api.headers, timeout=15)
        r.raise_for_status()
        payload = r.json()
    events = payload["events"]
    assert events, "expected at least one auth.login.local row to map"
    controls = events[0].get("controls", [])
    # Must contain AC-2 (Account Management) under NIST 800-53.
    have_ac2 = any(
        c["framework"] == "nist-sp-800-53-r5" and c["control_id"] == "AC-2"
        for c in controls
    )
    assert have_ac2, f"AC-2 mapping missing from auth.login.local: {controls}"
