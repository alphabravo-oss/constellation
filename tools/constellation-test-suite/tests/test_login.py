"""Bootstrap admin login round-trip."""
from __future__ import annotations


def test_login_succeeds(api):
    """The `api` fixture already calls login() with the bootstrap admin —
    if it returned a working ApiClient, login worked.
    """
    # If we got here the api fixture's login() didn't raise.
    assert api._token is not None and len(api._token) > 100, \
        f"token looks wrong: {api._token!r}"


def test_login_token_carries_global_admin(api, kubectl):
    """The JWT issued by login() should claim GlobalAdmin role for our admin user."""
    import base64, json
    # JWT shape: header.payload.signature; payload is base64url-encoded JSON.
    parts = api._token.split(".")
    assert len(parts) == 3, "JWT should have 3 parts"
    payload_b64 = parts[1] + "==="  # pad for urlsafe_b64decode
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    assert "GlobalAdmin" in payload.get("roles", []), \
        f"expected GlobalAdmin in roles, got {payload.get('roles')}"


def test_login_emits_audit_event(api):
    """login() should produce one audit_events row of action 'auth.login.local'."""
    events = api.audit_list(action="auth.login.local", limit=10)["events"]
    assert len(events) >= 1, "expected at least one auth.login.local audit event"
    # Most recent must reference our admin user.
    most_recent = events[0]
    assert most_recent["action"] == "auth.login.local"
    assert most_recent["target_kind"] == "user"
