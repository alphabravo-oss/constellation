#!/usr/bin/env python3
"""Run bounded endpoint-map recipes against a local API; writes require opt-in."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import sys
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


MAX_RESPONSE = 1 << 20
MAX_EXPORT = 512 << 10
TIMEOUT = 5
FIXTURE_NAME = "api-1-cli-smoke-profile"
FIXTURE_EXPORT = json.dumps({"vulnerability_profiles": [{
    "name": FIXTURE_NAME, "entries": [{"name": "CVE-2026-1234"}],
}]}, separators=(",", ":"))


class CheckError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None


def local_origin(raw):
    parsed = urlsplit(raw)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as error:
        raise CheckError("CONSTELLATION must use a loopback IP address") from error
    if (parsed.scheme not in ("http", "https") or not address.is_loopback
            or parsed.username or parsed.password or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment or port is None):
        raise CheckError("CONSTELLATION must be a loopback HTTP(S) origin with an explicit port")
    return raw.rstrip("/")


def required_environment(environment):
    missing = [name for name in ("CONSTELLATION", "TOKEN", "CLUSTER") if not environment.get(name)]
    if missing:
        raise CheckError("set " + ", ".join(missing) + " before running the smoke check")
    origin = local_origin(environment["CONSTELLATION"])
    token = environment["TOKEN"]
    if token != token.strip() or any(character in token for character in "\r\n"):
        raise CheckError("TOKEN must be a single-line bearer token")
    try:
        cluster = str(uuid.UUID(environment["CLUSTER"]))
    except ValueError as error:
        raise CheckError("CLUSTER must be a UUID") from error
    return origin, token, cluster


def request_json(opener, origin, token, label, path, payload=None):
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = Request(origin + path, data=payload, headers=headers,
                      method="POST" if payload is not None else "GET")
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            if response.status != 200:
                raise CheckError(f"{label}: HTTP {response.status}")
            body = response.read(MAX_RESPONSE + 1)
    except HTTPError as error:
        raise CheckError(f"{label}: HTTP {error.code}") from None
    except (URLError, OSError, ValueError) as error:
        raise CheckError(f"{label}: request failed ({type(error).__name__})") from None
    if len(body) > MAX_RESPONSE:
        raise CheckError(f"{label}: response exceeds {MAX_RESPONSE} bytes")
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CheckError(f"{label}: response is not JSON") from None


def assert_shape(label, value, fields):
    if not isinstance(value, dict):
        raise CheckError(f"{label}: expected a JSON object")
    for field, expected_type in fields.items():
        if type(value.get(field)) is not expected_type:
            raise CheckError(f"{label}: expected {field} to be {expected_type.__name__}")
        if expected_type is list and any(not isinstance(item, dict) for item in value[field]):
            raise CheckError(f"{label}: expected {field} entries to be objects")


def preview_payload(path, cluster):
    try:
        with Path(path).open("rb") as source:
            raw = source.read(MAX_EXPORT + 1)
    except OSError:
        raise CheckError("preview: cannot read export file") from None
    if not raw or len(raw) > MAX_EXPORT:
        raise CheckError(f"preview: export must be 1–{MAX_EXPORT} bytes")
    try:
        export = raw.decode("utf-8")
        json.loads(export)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CheckError("preview: export must be UTF-8 JSON") from None
    payload = json.dumps({"source": "neuvector", "cluster_id": cluster,
                          "export": export}).encode("utf-8")
    if len(payload) > 2 << 20:
        raise CheckError("preview: encoded request exceeds API limit")
    return payload


def fixture_profiles(opener, origin, token):
    result = request_json(opener, origin, token, "fixture profiles", "/api/v1/vuln-profiles")
    assert_shape("fixture profiles", result, {"profiles": list})
    return [profile for profile in result["profiles"] if profile.get("name") == FIXTURE_NAME]


def fixture_is_applied(profiles):
    if len(profiles) != 1:
        return False
    profile = profiles[0]
    entries = profile.get("entries")
    return (profile.get("active") is True and isinstance(entries, list)
            and len(entries) == 1 and isinstance(entries[0], dict)
            and entries[0].get("name") == "CVE-2026-1234")


def fixture_apply_rollback(opener, origin, token, cluster, output):
    if fixture_profiles(opener, origin, token):
        raise CheckError("fixture: profile name already exists; refusing to change it")
    payload = json.dumps({"source": "neuvector", "cluster_id": cluster,
                          "export": FIXTURE_EXPORT}).encode("utf-8")
    preview = request_json(opener, origin, token, "fixture preview",
                           "/api/v1/migration/preview", payload)
    assert_shape("fixture preview", preview, {"import_id": str, "summary": dict,
                                               "vulnerability_profiles": list})
    summary = preview["summary"]
    assert_shape("fixture summary", summary, {"source": str, "read_only": bool,
                                              "total": int, "create": int,
                                              "unsupported": int,
                                              "vulnerability_profiles": int})
    profiles = preview["vulnerability_profiles"]
    if (summary["source"] != "neuvector" or not summary["read_only"]
            or (summary["total"], summary["create"], summary["unsupported"],
                summary["vulnerability_profiles"]) != (1, 1, 0, 1)
            or len(profiles) != 1 or profiles[0].get("name") != FIXTURE_NAME
            or profiles[0].get("diff_action") != "create"
            or fixture_profiles(opener, origin, token)):
        raise CheckError("fixture preview: unexpected conversion or existing profile")
    try:
        import_id = str(uuid.UUID(preview["import_id"]))
    except ValueError:
        raise CheckError("fixture preview: invalid import ID") from None
    path = "/api/v1/migration/imports/" + import_id
    apply_attempted = False
    try:
        apply_attempted = True
        applied = request_json(opener, origin, token, "fixture apply", path + ":apply", b"")
        assert_shape("fixture apply", applied, {"id": str, "status": str, "applied": dict})
        counts = applied["applied"]
        if (applied["id"] != import_id or applied["status"] != "applied"
                or any(type(counts.get(key)) is not int or counts[key] != expected
                       for key, expected in {"created": 1, "updated": 0,
                                             "vulnerability_profiles": 1,
                                             "registries": 0}.items())
                or not fixture_is_applied(fixture_profiles(opener, origin, token))):
            raise CheckError("fixture apply: unexpected result or profile count")
        output("PASS fixture apply")
        repeated = request_json(opener, origin, token, "fixture apply retry", path + ":apply", b"")
        if (not isinstance(repeated, dict) or repeated.get("id") != import_id
                or repeated.get("status") != "applied"
                or repeated.get("already_applied") is not True
                or not fixture_is_applied(fixture_profiles(opener, origin, token))):
            raise CheckError("fixture apply retry: not idempotent")
        output("PASS fixture apply idempotency")
        rolled_back = request_json(opener, origin, token, "fixture rollback", path + ":rollback", b"")
        if (not isinstance(rolled_back, dict) or rolled_back.get("id") != import_id
                or rolled_back.get("status") != "rolled_back"
                or type(rolled_back.get("deleted")) is not int or rolled_back["deleted"] != 1
                or type(rolled_back.get("restored")) is not int or rolled_back["restored"] != 0
                or fixture_profiles(opener, origin, token)):
            raise CheckError("fixture rollback: unexpected result or profile remains")
        output("PASS fixture rollback")
        repeated = request_json(opener, origin, token, "fixture rollback retry", path + ":rollback", b"")
        if (not isinstance(repeated, dict) or repeated.get("id") != import_id
                or repeated.get("status") != "rolled_back"
                or repeated.get("already_rolled_back") is not True
                or fixture_profiles(opener, origin, token)):
            raise CheckError("fixture rollback retry: not idempotent")
        output("PASS fixture rollback idempotency")
    except CheckError as error:
        if apply_attempted:
            try:
                cleanup = request_json(opener, origin, token, "fixture cleanup", path + ":rollback", b"")
                if (not isinstance(cleanup, dict) or cleanup.get("status") != "rolled_back"
                        or fixture_profiles(opener, origin, token)):
                    raise CheckError("fixture cleanup: rollback not confirmed")
            except CheckError:
                raise CheckError(f"{error}; cleanup rollback unconfirmed; inspect import history") from None
        raise


def run(environment, preview_file=None, output=print, apply_rollback_fixture=False):
    origin, token, cluster = required_environment(environment)
    if apply_rollback_fixture and preview_file is not None:
        raise CheckError("fixture mutation cannot use an arbitrary preview file")
    payload = preview_payload(preview_file, cluster) if preview_file else None
    opener = build_opener(ProxyHandler({}), NoRedirect())
    recipes = (
        ("groups", "/api/v1/groups?" + urlencode({"cluster_id": cluster}), {"groups": list}),
        ("audit events", "/api/v1/audit/events?limit=5", {"events": list, "limit": int, "has_more": bool}),
        ("security timeline", "/api/v1/security/timeline?" + urlencode({"cluster_id": cluster, "type": "dpi_threat,runtime_event,network_violation", "limit": 5}), {"items": list, "limit": int, "has_more": bool}),
        ("scan jobs", "/api/v1/scan-jobs?" + urlencode({"cluster_id": cluster}), {"jobs": list, "queue_metrics": list}),
    )
    for label, path, shape in recipes:
        result = request_json(opener, origin, token, label, path)
        assert_shape(label, result, shape)
        if label in ("audit events", "security timeline") and result["limit"] != 5:
            raise CheckError(f"{label}: expected limit 5")
        output(f"PASS {label}")
    if payload is not None:
        result = request_json(opener, origin, token, "migration preview",
                              "/api/v1/migration/preview", payload)
        assert_shape("migration preview", result, {"import_id": str, "summary": dict,
                                                    "policies": list, "groups": list,
                                                    "vulnerability_profiles": list,
                                                    "rollback_bundle": str})
        assert_shape("migration preview summary", result["summary"],
                     {"source": str, "total": int, "unsupported": int, "read_only": bool})
        if result["summary"]["source"] != "neuvector" or not result["summary"]["read_only"]:
            raise CheckError("migration preview: unexpected source or read_only value")
        output("PASS migration preview")
        return result
    if apply_rollback_fixture:
        fixture_apply_rollback(opener, origin, token, cluster, output)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preview-file", metavar="NV_EXPORT_JSON",
                        help="explicitly POST a NeuVector export to migration preview")
    parser.add_argument("--apply-rollback-fixture", action="store_true",
                        help="explicitly apply and roll back the fixed profile fixture on a disposable local API")
    args = parser.parse_args(argv)
    try:
        run(os.environ, args.preview_file, apply_rollback_fixture=args.apply_rollback_fixture)
    except CheckError as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
