#!/usr/bin/env python3
"""Apply and roll back the fixed NeuVector fixture on a disposable loopback org.

Run with --apply-and-rollback and CONSTELLATION, TOKEN, CLUSTER, and UI_ORIGIN.
The preview endpoint persists a preview record even though it creates no target objects.
"""

import argparse
import json
import os
from pathlib import Path
import sys
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

from smoke_api_recipes import (CheckError, MAX_EXPORT, MAX_RESPONSE, NoRedirect,
                               TIMEOUT, assert_shape, local_origin,
                               request_json, required_environment)


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load_fixture():
    try:
        manifest = json.loads((FIXTURES / "neuvector-cutover-manifest.json").read_text())
        raw = (FIXTURES / "neuvector-cutover-export.json").read_bytes()
        export = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise CheckError("fixture: cannot read valid fixture JSON") from None
    if not raw or len(raw) > MAX_EXPORT:
        raise CheckError("fixture: export size is outside the safe limit")
    try:
        names = manifest["names"]
        expected = {"groups": 2, "network_rules": 1,
                    "vulnerability_profiles": 1, "total": 4}
        if (manifest["source"] != "neuvector"
                or manifest["fixture"] != "neuvector-cutover-export.json"
                or manifest["source_objects"] != expected
                or manifest["converted"] != expected
                or manifest["unsupported"] != 0
                or manifest["applied"] != {"groups": 2, "network_rules": 1,
                                          "vulnerability_profiles": 1,
                                          "created": 4, "updated": 0}
                or manifest["rolled_back"] != {"deleted": 4, "restored": 0}
                or len(names["groups"]) != 2 or len(names["network_edge"]) != 2
                or len(set(names["groups"])) != 2
                or names["network_edge"] != names["groups"]
                or {item["name"] for item in export["groups"]} != set(names["groups"])
                or len(export["groups"]) != 2
                or len(export["network_rules"]) != 1
                or export["network_rules"][0]["from"] != names["network_edge"][0]
                or export["network_rules"][0]["to"] != names["network_edge"][1]
                or len(export["vulnerability_profiles"]) != 1
                or export["vulnerability_profiles"][0]["name"] != names["vulnerability_profile"]
                or manifest["ui_routes"] != ["/settings/migration",
                                             "/clusters/{cluster_id}/policy-center"]):
            raise CheckError("fixture: manifest and export do not match the fixed cutover contract")
    except (KeyError, TypeError, ValueError):
        raise CheckError("fixture: manifest and export do not match the fixed cutover contract") from None
    return manifest, raw.decode("utf-8")


def ui_origin(environment, api_origin):
    raw = environment.get("UI_ORIGIN")
    if not raw:
        raise CheckError("set UI_ORIGIN to a separate loopback UI origin")
    try:
        origin = local_origin(raw)
    except CheckError:
        raise CheckError("UI_ORIGIN must be a loopback HTTP(S) origin with an explicit port") from None
    if origin == api_origin:
        raise CheckError("UI_ORIGIN must be separate from CONSTELLATION")
    return origin


def ui_routes_available(opener, origin, cluster, routes):
    for route in routes:
        path = route.replace("{cluster_id}", cluster)
        request = Request(origin + path, headers={"Accept": "text/html"})
        try:
            with opener.open(request, timeout=TIMEOUT) as response:
                if response.status != 200:
                    raise CheckError("UI route: unexpected HTTP status")
                content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
                body = response.read(MAX_RESPONSE + 1)
        except HTTPError as error:
            raise CheckError(f"UI route: HTTP {error.code}") from None
        except (URLError, OSError, ValueError) as error:
            raise CheckError(f"UI route: request failed ({type(error).__name__})") from None
        if (content_type != "text/html" or len(body) > MAX_RESPONSE
                or b"<html" not in body.lower()):
            raise CheckError("UI route: expected bounded HTML response")


def targets(opener, origin, token, cluster, names):
    query = "?" + urlencode({"cluster_id": cluster})
    groups = request_json(opener, origin, token, "groups", "/api/v1/groups" + query)
    edges = request_json(opener, origin, token, "network edges",
                         "/api/v1/runtime-policies/group-edges" + query)
    profiles = request_json(opener, origin, token, "vulnerability profiles",
                            "/api/v1/vuln-profiles" + query)
    for label, result, field in (("groups", groups, "groups"),
                                 ("network edges", edges, "edges"),
                                 ("vulnerability profiles", profiles, "profiles")):
        assert_shape(label, result, {field: list})
    group_names = set(names["groups"])
    pair = tuple(names["network_edge"])
    return (sum(item.get("name") in group_names for item in groups["groups"]),
            sum((item.get("from_group"), item.get("to_group")) == pair
                for item in edges["edges"]),
            sum(item.get("name") == names["vulnerability_profile"]
                for item in profiles["profiles"]))


def check_preview(preview, manifest, cluster):
    assert_shape("preview", preview, {"import_id": str, "summary": dict,
                                      "groups": list, "network_rules": list,
                                      "vulnerability_profiles": list})
    summary = preview["summary"]
    expected = manifest["converted"]
    if (summary.get("source") != "neuvector" or summary.get("read_only") is not True
            or preview.get("target_cluster_id") != cluster
            or any(type(summary.get(key)) is not int or summary[key] != count
                   for key, count in expected.items())
            or summary.get("create") != 4 or summary.get("update") != 0
            or summary.get("unsupported") != 0
            or len(preview["groups"]) != 2 or len(preview["network_rules"]) != 1
            or len(preview["vulnerability_profiles"]) != 1
            or {item.get("name") for item in preview["groups"]} != set(manifest["names"]["groups"])
            or preview["network_rules"][0].get("from_group") != manifest["names"]["network_edge"][0]
            or preview["network_rules"][0].get("to_group") != manifest["names"]["network_edge"][1]
            or preview["vulnerability_profiles"][0].get("name") != manifest["names"]["vulnerability_profile"]
            or any(item.get("diff_action") != "create" for field in
                   ("groups", "network_rules", "vulnerability_profiles")
                   for item in preview[field])):
        raise CheckError("preview: counts, scope, or create-only conversion differ from manifest")
    try:
        return str(uuid.UUID(preview["import_id"]))
    except ValueError:
        raise CheckError("preview: invalid import ID") from None


def check_counts(label, result, import_id, status, counts):
    assert_shape(label, result, {"id": str, "status": str})
    if result["id"] != import_id or result["status"] != status:
        raise CheckError(f"{label}: unexpected import ID or status")
    if status == "applied":
        if not isinstance(result.get("applied"), dict):
            raise CheckError(f"{label}: missing applied counts")
        values = result["applied"]
    else:
        values = result
    if any(type(values.get(key)) is not int or values[key] != value
           for key, value in counts.items()):
        raise CheckError(f"{label}: counts differ from manifest")


def run(environment, apply_and_rollback=False, output=print):
    if not apply_and_rollback:
        raise CheckError("pass --apply-and-rollback to opt in")
    origin, token, cluster = required_environment(environment)
    ui = ui_origin(environment, origin)
    manifest, export = load_fixture()
    opener = build_opener(ProxyHandler({}), NoRedirect())
    history = request_json(opener, origin, token, "import history",
                           "/api/v1/migration/imports?limit=1")
    assert_shape("import history", history, {"imports": list, "has_more": bool})
    if history["imports"] or history["has_more"]:
        raise CheckError("import history is not empty; use a fresh organization")
    if targets(opener, origin, token, cluster, manifest["names"]) != (0, 0, 0):
        raise CheckError("fixture targets already exist; refusing cutover")
    ui_routes_available(opener, ui, cluster, manifest["ui_routes"])
    output("PASS preflight: empty history, absent targets, UI HTML routes")
    payload = json.dumps({"source": "neuvector", "cluster_id": cluster,
                          "export": export}).encode("utf-8")
    if len(payload) > 2 << 20:
        raise CheckError("preview: encoded request exceeds API limit")
    preview = request_json(opener, origin, token, "preview", "/api/v1/migration/preview", payload)
    import_id = check_preview(preview, manifest, cluster)
    if targets(opener, origin, token, cluster, manifest["names"]) != (0, 0, 0):
        raise CheckError("preview created target objects; refusing apply")
    output("PASS preview: four create-only conversions, no target objects")
    path = "/api/v1/migration/imports/" + import_id
    try:
        applied = request_json(opener, origin, token, "apply", path + ":apply", b"")
        check_counts("apply", applied, import_id, "applied", manifest["applied"])
        if targets(opener, origin, token, cluster, manifest["names"]) != (2, 1, 1):
            raise CheckError("apply: expected groups, network edge, and profile are not present")
        ui_routes_available(opener, ui, cluster, manifest["ui_routes"])
        output("PASS apply: four objects and UI HTML routes")
        rolled_back = request_json(opener, origin, token, "rollback", path + ":rollback", b"")
        check_counts("rollback", rolled_back, import_id, "rolled_back", manifest["rolled_back"])
        if targets(opener, origin, token, cluster, manifest["names"]) != (0, 0, 0):
            raise CheckError("rollback: fixture targets remain")
        output("PASS rollback: four objects removed")
    except CheckError as error:
        try:
            cleanup = request_json(opener, origin, token, "cleanup", path + ":rollback", b"")
            if (not isinstance(cleanup, dict) or cleanup.get("id") != import_id
                    or cleanup.get("status") != "rolled_back"
                    or targets(opener, origin, token, cluster, manifest["names"]) != (0, 0, 0)):
                raise CheckError("cleanup: rollback not confirmed")
        except CheckError:
            raise CheckError(f"{error}; cleanup rollback unconfirmed; inspect import history") from None
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply-and-rollback", action="store_true",
                        help="explicitly mutate a fresh disposable loopback org")
    args = parser.parse_args(argv)
    try:
        run(os.environ, args.apply_and_rollback)
    except CheckError as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
