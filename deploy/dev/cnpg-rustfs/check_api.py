"""Verify session, encrypted credential and audit continuity in disposable recovery."""
import hashlib
import json
import os
import pathlib
import secrets
import sys
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def save(root, name, value):
    with os.fdopen(os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as stream:
        json.dump(value, stream)


def read(root, name):
    return json.loads((root / name).read_text())


def client(port):
    base = f"http://127.0.0.1:{int(port)}/api/v1"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(path, token=None, data=None, expected=200):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(base + path, headers=headers,
                                     data=json.dumps(data).encode() if data is not None else None)
        try:
            response = opener.open(req, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            require(response.code == expected, f"Unexpected HTTP status for recovery check: {response.code}")
            raw = response.read(1024 * 1024 + 1)
            require(len(raw) <= 1024 * 1024, "Recovery response exceeds size budget")
            try:
                return json.loads(raw)
            except ValueError:
                raise RuntimeError("Invalid recovery JSON response") from None
    return request


def verify_audit(request, token, saved_head=None):
    result = request("/audit/verify", token, {})
    require(result.get("status") == "verified" and result.get("events", 0) > 0,
            "Audit chain was not verified")
    if saved_head:
        rows = request("/audit/events?event_id=" + str(saved_head["id"]), token)["events"]
        require(len(rows) == 1 and rows[0]["chain_hash"] == saved_head["chain_hash"],
                "Pre-recovery audit anchor changed or disappeared")
    return request("/audit/events?limit=1", token)["events"][0]


def check(mode, root, request):
    if mode == "prepare":
        # Seed only a disposable scanner identity. Credential encryption and issuance
        # below still cross the production API and its real audit boundary.
        token = "cst_" + secrets.token_urlsafe(32)
        save(root, "scanner-token.json", token)
        digest = hashlib.sha256(token.encode()).hexdigest()
        (root / "scanner.sql").write_text(
            "INSERT INTO scanner_tokens (org_id,name,token_hash,expires_at) "
            "SELECT org_id,'recovery-proof','" + digest + "',now()+interval '2 hours' "
            "FROM users WHERE email='admin@demo.test';\n")
        return
    scanner = read(root, "scanner-token.json")
    if mode == "source":
        token = request("/auth/login", data={"email": "admin@demo.test", "password": "Constellation!1"})["token"]
        save(root, "source-token.json", token)
        save(root, "source-me.json", request("/auth/me", token))
        save(root, "source-config.json", request("/system/config", token))
        credentials = {"username": "recovery-proof", "password": secrets.token_urlsafe(32)}
        registry = request("/registries", token, {
            "name": "recovery-proof", "kind": "generic-v2", "endpoint": "registry.invalid",
            "auth_kind": "static", "credentials": credentials, "scan_cadence": "manual",
        }, expected=201)
        save(root, "registry-proof.json", {"id": registry["id"], "credentials": credentials})
    else:
        require(mode in ("restored", "wrong-key"), "Expected prepare, source, restored or wrong-key")
        token = read(root, "source-token.json")
        require(request("/auth/me", token) == read(root, "source-me.json"), "Session identity changed")
        require(request("/system/config", token) == read(root, "source-config.json"), "Configuration changed")
    fixture = read(root, "registry-proof.json")
    path = "/scanner/registry-credentials?registry_id=" + fixture["id"]
    if mode == "wrong-key":
        result = request(path, scanner, expected=500)
        require(result.get("error", "").startswith("decrypt credentials:"), "Wrong-key failure was not decryption rejection")
        require(all(value not in json.dumps(result) for value in fixture["credentials"].values()),
                "Wrong-key response exposed credential material")
        verify_audit(request, token, read(root, "audit-anchor.json"))
        return
    result = request(path, scanner)
    require(result.get("registry_id") == fixture["id"], "Wrong registry returned")
    require(all(result.get(key) == value for key, value in fixture["credentials"].items()),
            "Recovered credential did not decrypt to the original value")
    receipts = request("/audit/events?action=registry.credentials-issued&limit=100", token)["events"]
    require(any(row["target_id"] == fixture["id"] for row in receipts), "Credential issuance audit receipt missing")
    anchor = verify_audit(request, token, None if mode == "source" else read(root, "audit-anchor.json"))
    if mode == "source":
        save(root, "audit-anchor.json", anchor)
    else:
        fresh = request("/auth/login", data={"email": "admin@demo.test", "password": "Constellation!1"})["token"]
        request("/auth/me", fresh)


def main():
    mode, port, directory = sys.argv[1:]
    root = pathlib.Path(directory)
    require(root.is_dir() and root.stat().st_mode & 0o077 == 0, "Recovery evidence directory must be private")
    check(mode, root, client(port))
    print(f"API checks passed: {mode} (session, credentials and audit where applicable)")


if __name__ == "__main__":
    main()
