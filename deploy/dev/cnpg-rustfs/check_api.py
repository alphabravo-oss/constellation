"""Verify session, encrypted credential and audit continuity in disposable recovery."""
import hashlib
import json
import os
import pathlib
import secrets
import sys
import urllib.error
import urllib.request
import uuid


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
    if mode == "fixture":
        token = request("/auth/login", data={"email": "admin@demo.test", "password": "Constellation!1"})["token"]
        save(root, "source-token.json", token)
        save(root, "source-me.json", request("/auth/me", token))
        save(root, "source-config.json", request("/system/config", token))
        credentials = {"username": "recovery-proof", "password": secrets.token_urlsafe(32)}
        registry = request("/registries", token, {
            "name": "recovery-proof", "kind": "generic-v2", "endpoint": "registry.invalid",
            "auth_kind": "static", "credentials": credentials, "scan_cadence": "manual",
        }, expected=201)
        registry_id = str(uuid.UUID(registry["id"]))
        job_id, target_id = str(uuid.uuid4()), str(uuid.uuid4())
        save(root, "registry-proof.json", {"id": registry_id, "job_id": job_id, "credentials": credentials})
        # Only the disposable harness seeds the pending target. The real claim
        # endpoint assigns the scanner identity and lease before any release.
        # The demo seed includes pending scans. Put this proof first in FIFO
        # order without altering their state or accepting an unrelated claim.
        (root / "registry-job.sql").write_text(
            "INSERT INTO scan_targets (id,org_id,type,ref,source_type,registry_id) "
            f"SELECT '{target_id}',org_id,'image','registry.invalid/proof:latest','registry',id FROM registries WHERE id='{registry_id}';\n"
            "INSERT INTO scan_jobs (id,org_id,target_id,status,requested_at) "
            f"SELECT '{job_id}',st.org_id,st.id,'pending',"
            "LEAST(now(),COALESCE((SELECT min(sj.requested_at) FROM scan_jobs sj WHERE sj.org_id=st.org_id),now()))-interval '1 second' "
            f"FROM scan_targets st WHERE st.id='{target_id}';\n")
        return
    else:
        require(mode in ("source", "restored", "wrong-key"), "Expected prepare, fixture, source, restored or wrong-key")
        token = read(root, "source-token.json")
        require(request("/auth/me", token) == read(root, "source-me.json"), "Session identity changed")
        require(request("/system/config", token) == read(root, "source-config.json"), "Configuration changed")
    fixture = read(root, "registry-proof.json")
    if mode == "source":
        claimed = request("/scan-jobs/claim", scanner, {})
        require(claimed.get("id") == fixture["job_id"] and claimed.get("registry_id") == fixture["id"],
                "Recovery scanner claimed the wrong registry job")
    else:
        request("/scan-jobs/" + fixture["job_id"] + "/renew", scanner, {})
    path = "/scanner/registry-credentials?registry_id=" + fixture["id"] + "&job_id=" + fixture["job_id"]
    if mode == "wrong-key":
        result = request(path, scanner, expected=500)
        require(result.get("error") == "credential decryption failed", "Wrong-key failure was not decryption rejection")
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
