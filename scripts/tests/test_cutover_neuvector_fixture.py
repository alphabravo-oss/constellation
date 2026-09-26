"""Run: python3 -B -m unittest discover -s scripts/tests -p test_cutover_neuvector_fixture.py"""

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/cutover_neuvector_fixture.py"
EXPORT = json.loads((ROOT / "scripts/fixtures/neuvector-cutover-export.json").read_text())
CLUSTER = "11111111-1111-1111-1111-111111111111"
IMPORT_ID = "22222222-2222-2222-2222-222222222222"
TOKEN = "secret-cutover-token"
NAMES = ["cutover.api.default", "cutover.db.default"]
GROUP_IDS = ["33333333-3333-3333-3333-333333333333", "44444444-4444-4444-4444-444444444444"]
EDGE = (NAMES[0], NAMES[1])
PROFILE = "cutover-vuln-profile"
DPI_RULES = {"dlp": "nv-dlp-cutover-pii-account-marker",
             "waf": "nv-waf-cutover-waf-probe-path"}


class APIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_api(None)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.handle_api(body)

    def handle_api(self, body):
        state = self.server.state
        state["calls"].append((self.command, self.path, self.headers.get("Authorization"), body))
        path = urlsplit(self.path).path
        if path == "/api/v1/migration/imports":
            result = {"imports": [{"id": IMPORT_ID}] if state["history"] else [],
                      "has_more": False}
        elif path == "/api/v1/groups":
            result = {"groups": [{"id": group_id, "name": name}
                                 for group_id, name in zip(GROUP_IDS, NAMES)]
                      if state["groups"] else []}
        elif path == "/api/v1/runtime-policies/group-edges":
            result = {"edges": [{"from_group": EDGE[0], "to_group": EDGE[1]}]
                      if state["edge"] else None}
        elif path == "/api/v1/vuln-profiles":
            result = {"profiles": [{"name": PROFILE}] if state["profile"] else []}
        elif path == "/api/v1/runtime-dlp-rules":
            result = {"rules": [{"name": DPI_RULES[kind], "category": kind,
                                  "cluster_id": CLUSTER}
                                for kind in ("dlp", "waf") if state[f"{kind}_rule"]]}
        elif path == "/api/v1/runtime/dpi-sensor-bindings":
            result = {"bindings": [{"group_id": GROUP_IDS[0], "sensor_kind": kind}
                                   for kind in ("dlp", "waf") if state[f"{kind}_binding"]]
                      if any(state[f"{kind}_binding"] for kind in ("dlp", "waf")) else None}
        elif path == "/api/v1/migration/preview":
            state["preview_body"] = json.loads(body)
            result = {"import_id": IMPORT_ID, "target_cluster_id": CLUSTER,
                      "summary": {"source": "neuvector", "read_only": True,
                                  "total": 8, "source_total": 8, "create": 8,
                                  "update": 0, "unsupported": 0,
                                  "groups": 2, "network_rules": 1,
                                  "vulnerability_profiles": 1, "dpi_rules": 2,
                                  "dpi_bindings": 2},
                      "groups": [{"name": name, "diff_action": "create"} for name in NAMES],
                      "network_rules": [{"from_group": EDGE[0], "to_group": EDGE[1],
                                         "diff_action": "create"}],
                      "vulnerability_profiles": [{"name": PROFILE, "diff_action": "create"}],
                      "dpi_rules": [{"name": DPI_RULES[kind], "category": kind,
                                     "cluster_id": CLUSTER, "mode": "monitor",
                                     "patterns": [{"pattern": "fixture"}],
                                     "diff_action": "create"}
                                    for kind in ("dlp", "waf")],
                      "dpi_bindings": [{"sensor_kind": kind, "source_group": NAMES[0],
                                        "target_group_name": NAMES[0], "diff_action": "create"}
                                       for kind in ("dlp", "waf")]}
        elif path == f"/api/v1/migration/imports/{IMPORT_ID}:apply":
            state.update(groups=True, edge=True, profile=True, dlp_rule=True,
                         waf_rule=True, dlp_binding=True, waf_binding=True)
            if state["omit_on_apply"]:
                state[state["omit_on_apply"]] = False
            result = {"id": IMPORT_ID, "status": "applied",
                      "applied": {"groups": 2, "network_rules": 1,
                                  "vulnerability_profiles": 1, "dpi_rules": 2,
                                  "dpi_bindings": 2, "created": 8, "updated": 0}}
        elif path == f"/api/v1/migration/imports/{IMPORT_ID}:rollback":
            was_applied = any(state[key] for key in ("groups", "edge", "profile", "dlp_rule",
                                                    "waf_rule", "dlp_binding", "waf_binding"))
            state.update(groups=False, edge=False, profile=False, dlp_rule=False,
                         waf_rule=False, dlp_binding=False, waf_binding=False)
            if state["retain_on_rollback"]:
                state[state["retain_on_rollback"]] = True
            result = ({"id": IMPORT_ID, "status": "rolled_back", "deleted": 8, "restored": 0}
                      if was_applied else {"id": IMPORT_ID, "status": "rolled_back",
                                           "already_rolled_back": True})
        else:
            self.send_error(404)
            return
        status, result = state["overrides"].get(path, (200, result))
        if path.endswith(":apply") and status != 200:
            state.update(groups=False, edge=False, profile=False, dlp_rule=False,
                         waf_rule=False, dlp_binding=False, waf_binding=False)
        if path.endswith(":rollback") and status != 200:
            state.update(groups=True, edge=True, profile=True, dlp_rule=True,
                         waf_rule=True, dlp_binding=True, waf_binding=True)
        if status == 302:
            self.send_response(302)
            self.send_header("Location", "http://example.com/redirect")
            self.end_headers()
            return
        raw = json.dumps(result).encode() if not isinstance(result, bytes) else result
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format, *args):
        pass


class UIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.calls.append((self.path, self.headers.get("Authorization")))
        status = self.server.status
        if self.server.fail_after_apply and self.server.api_state["groups"]:
            status = 503
        if status == 302:
            self.send_response(302)
            self.send_header("Location", "http://example.com/redirect")
            self.end_headers()
            return
        raw = b"<!doctype html><html><body>app</body></html>" if status == 200 else b"unavailable"
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format, *args):
        pass


class CutoverFixtureTests(unittest.TestCase):
    def setUp(self):
        self.api = ThreadingHTTPServer(("127.0.0.1", 0), APIHandler)
        self.api.state = {"calls": [], "history": False, "groups": False,
                          "edge": False, "profile": False, "dlp_rule": False,
                          "waf_rule": False, "dlp_binding": False,
                          "waf_binding": False, "omit_on_apply": None,
                          "retain_on_rollback": None, "overrides": {}}
        self.ui = ThreadingHTTPServer(("127.0.0.1", 0), UIHandler)
        self.ui.calls = []
        self.ui.status = 200
        self.ui.fail_after_apply = False
        self.ui.api_state = self.api.state
        for server in (self.api, self.ui):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(thread.join, 2)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
        self.environment = {"CONSTELLATION": f"http://127.0.0.1:{self.api.server_port}",
                            "UI_ORIGIN": f"http://127.0.0.1:{self.ui.server_port}",
                            "TOKEN": TOKEN, "CLUSTER": CLUSTER}

    def run_cli(self, *args, **environment):
        return subprocess.run([sys.executable, "-B", str(SCRIPT), *args],
                              env={**os.environ, **self.environment, **environment},
                              capture_output=True, text=True, timeout=15, check=False)

    def assert_no_leaks(self, result):
        output = result.stdout + result.stderr
        for secret in (TOKEN, IMPORT_ID, CLUSTER, json.dumps(EXPORT)):
            self.assertNotIn(secret, output)

    def test_full_cutover_is_bounded_and_rolls_back(self):
        result = self.run_cli("--apply-and-rollback")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS rollback: eight objects removed", result.stdout)
        self.assertEqual(json.loads(self.api.state["preview_body"]["export"]), EXPORT)
        self.assertEqual(self.api.state["preview_body"]["cluster_id"], CLUSTER)
        self.assertFalse(any(self.api.state[key] for key in ("groups", "edge", "profile",
                                                          "dlp_rule", "waf_rule",
                                                          "dlp_binding", "waf_binding")))
        calls = self.api.state["calls"]
        self.assertEqual(calls[0][:2], ("GET", "/api/v1/migration/imports?limit=1"))
        self.assertEqual(sum(path.endswith(":apply") for _, path, _, _ in calls), 1)
        self.assertEqual(sum(path.endswith(":rollback") for _, path, _, _ in calls), 1)
        self.assertEqual(sum(path == "/api/v1/migration/preview" for _, path, _, _ in calls), 1)
        self.assertTrue(all(auth == "Bearer " + TOKEN for _, _, auth, _ in calls))
        self.assertEqual(len(self.ui.calls), 4)
        self.assertTrue(all(auth is None for _, auth in self.ui.calls))
        self.assert_no_leaks(result)

    def test_requires_opt_in_environment_and_separate_loopback_ui(self):
        for args, environment in (((), {}), (("--apply-and-rollback",), {"TOKEN": ""}),
                                  (("--apply-and-rollback",), {"UI_ORIGIN": ""}),
                                  (("--apply-and-rollback",), {"UI_ORIGIN": self.environment["CONSTELLATION"]}),
                                  (("--apply-and-rollback",), {"UI_ORIGIN": "https://example.com:443"})):
            with self.subTest(args=args, environment=environment):
                result = self.run_cli(*args, **environment)
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_leaks(result)
        self.assertEqual(self.api.state["calls"], [])

    def test_refuses_existing_history_or_targets_without_preview(self):
        for field in ("history", "groups", "edge", "profile", "dlp_rule", "waf_rule",
                      "dlp_binding", "waf_binding"):
            with self.subTest(field=field):
                self.api.state[field] = True
                if field.endswith("_binding"):
                    self.api.state["groups"] = True
                result = self.run_cli("--apply-and-rollback")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(method == "POST" for method, _, _, _ in self.api.state["calls"]))
                self.assert_no_leaks(result)
                self.api.state[field] = False
                self.api.state["groups"] = False
                self.api.state["calls"].clear()

    def test_refuses_bad_preview_without_apply(self):
        self.api.state["overrides"]["/api/v1/migration/preview"] = (200, {
            "import_id": IMPORT_ID, "target_cluster_id": CLUSTER,
            "summary": {"source": "neuvector", "read_only": True, "total": 8,
                        "create": 3, "update": 1, "unsupported": 0,
                        "groups": 2, "network_rules": 1, "vulnerability_profiles": 1,
                        "dpi_rules": 2, "dpi_bindings": 2},
            "groups": [], "network_rules": [], "vulnerability_profiles": [],
            "dpi_rules": [], "dpi_bindings": []})
        result = self.run_cli("--apply-and-rollback")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(path.endswith(":apply") for _, path, _, _ in self.api.state["calls"]))
        self.assert_no_leaks(result)

    def test_rejects_malformed_dpi_inventory_before_preview(self):
        self.api.state["overrides"]["/api/v1/runtime-dlp-rules"] = (200, {"rules": [None]})
        result = self.run_cli("--apply-and-rollback")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected rules entries to be objects", result.stderr)
        self.assertFalse(any(method == "POST" for method, _, _, _ in self.api.state["calls"]))
        self.assert_no_leaks(result)

    def test_apply_mismatch_attempts_cleanup(self):
        self.api.state["overrides"][f"/api/v1/migration/imports/{IMPORT_ID}:apply"] = (200, {
            "id": IMPORT_ID, "status": "applied", "applied": {"created": 3}})
        result = self.run_cli("--apply-and-rollback")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("counts differ", result.stderr)
        self.assertEqual(sum(path.endswith(":rollback") for _, path, _, _ in self.api.state["calls"]), 1)
        self.assertFalse(self.api.state["groups"])
        self.assert_no_leaks(result)

    def test_missing_dpi_target_after_apply_attempts_cleanup(self):
        for field in ("dlp_rule", "waf_rule", "dlp_binding", "waf_binding"):
            with self.subTest(field=field):
                self.api.state["omit_on_apply"] = field
                result = self.run_cli("--apply-and-rollback")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("expected groups, edge, profile, DLP/WAF rules and bindings", result.stderr)
                self.assertEqual(sum(path.endswith(":rollback") for _, path, _, _ in self.api.state["calls"]), 1)
                self.assertFalse(any(self.api.state[key] for key in ("groups", "edge", "profile",
                                                                  "dlp_rule", "waf_rule",
                                                                  "dlp_binding", "waf_binding")))
                self.assert_no_leaks(result)
                self.api.state["calls"].clear()

    def test_lingering_dpi_rule_after_rollback_is_unconfirmed(self):
        self.api.state["retain_on_rollback"] = "waf_rule"
        result = self.run_cli("--apply-and-rollback")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cleanup rollback unconfirmed", result.stderr)
        self.assertEqual(sum(path.endswith(":rollback") for _, path, _, _ in self.api.state["calls"]), 2)
        self.assert_no_leaks(result)

    def test_post_apply_ui_failure_attempts_cleanup(self):
        self.ui.fail_after_apply = True
        result = self.run_cli("--apply-and-rollback")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sum(path.endswith(":rollback") for _, path, _, _ in self.api.state["calls"]), 1)
        self.assertFalse(self.api.state["groups"])
        self.assert_no_leaks(result)

    def test_unconfirmed_rollback_reports_without_body(self):
        self.api.state["overrides"][f"/api/v1/migration/imports/{IMPORT_ID}:rollback"] = (409, {"error": TOKEN})
        result = self.run_cli("--apply-and-rollback")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cleanup rollback unconfirmed", result.stderr)
        self.assertEqual(sum(path.endswith(":rollback") for _, path, _, _ in self.api.state["calls"]), 2)
        self.assert_no_leaks(result)

    def test_ui_redirect_fails_before_preview(self):
        self.ui.status = 302
        result = self.run_cli("--apply-and-rollback")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(method == "POST" for method, _, _, _ in self.api.state["calls"]))
        self.assert_no_leaks(result)


if __name__ == "__main__":
    unittest.main()
