"""Run: python3 -B -m unittest discover -s scripts/tests -p test_smoke_api_recipes.py"""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/smoke_api_recipes.py"
spec = importlib.util.spec_from_file_location("smoke_api_recipes", SCRIPT)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)
CLUSTER = "11111111-1111-1111-1111-111111111111"
TOKEN = "secret-smoke-token"
IMPORT_ID = "22222222-2222-2222-2222-222222222222"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.calls.append(("GET", self.path, self.headers.get("Authorization"), b""))
        path = self.path.split("?", 1)[0]
        if path == "/api/v1/groups":
            result = {"groups": []}
        elif path == "/api/v1/audit/events":
            result = {"events": [], "limit": 5, "has_more": False}
        elif path == "/api/v1/security/timeline":
            result = {"items": [], "limit": 5, "has_more": False}
        elif path == "/api/v1/scan-jobs":
            result = {"jobs": [], "queue_metrics": []}
        elif path == "/api/v1/vuln-profiles":
            result = {"profiles": [{"name": smoke.FIXTURE_NAME, "active": True,
                                    "entries": [{"name": "CVE-2026-1234"}]}]
                      if self.server.profile_exists else []}
        else:
            self.send_error(404)
            return
        self.reply(path, result)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.calls.append(("POST", self.path, self.headers.get("Authorization"), body))
        if self.path == "/api/v1/migration/preview":
            fixture = json.loads(body)["export"] == smoke.FIXTURE_EXPORT
            result = {"import_id": IMPORT_ID if fixture else "preview-id",
                      "summary": {"source": "neuvector", "total": int(fixture),
                                  "create": int(fixture), "vulnerability_profiles": int(fixture),
                                  "unsupported": 0, "read_only": True},
                      "policies": [], "groups": [],
                      "vulnerability_profiles": [{"name": smoke.FIXTURE_NAME,
                                                  "diff_action": "create"}] if fixture else [],
                      "rollback_bundle": "{}"}
        elif self.path == f"/api/v1/migration/imports/{IMPORT_ID}:apply":
            already_applied = self.server.profile_exists
            if self.server.overrides.get(self.path, (200,))[0] == 200:
                self.server.profile_exists = True
            result = ({"id": IMPORT_ID, "status": "applied", "already_applied": True}
                      if already_applied else {"id": IMPORT_ID, "status": "applied", "applied": {
                          "created": 1, "updated": 0, "vulnerability_profiles": 1, "registries": 0}})
        elif self.path == f"/api/v1/migration/imports/{IMPORT_ID}:rollback":
            already_rolled_back = not self.server.profile_exists
            if self.server.overrides.get(self.path, (200,))[0] == 200:
                self.server.profile_exists = False
            result = ({"id": IMPORT_ID, "status": "rolled_back", "already_rolled_back": True}
                      if already_rolled_back else {"id": IMPORT_ID, "status": "rolled_back",
                                                    "restored": 0, "deleted": 1})
        else:
            self.send_error(404)
            return
        self.reply(self.path, result)

    def reply(self, path, result):
        status, result = self.server.overrides.get(path, (200, result))
        if status == 302:
            self.send_response(302)
            self.send_header("Location", "http://example.com/redirect")
            self.end_headers()
            return
        data = result if isinstance(result, bytes) else json.dumps(result).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


class SmokeAPIRecipesTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.calls = []
        self.server.overrides = {}
        self.server.profile_exists = False
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.environment = {"CONSTELLATION": f"http://127.0.0.1:{self.server.server_port}",
                            "TOKEN": TOKEN, "CLUSTER": CLUSTER}

    def run_cli(self, *args, **environment):
        return subprocess.run([sys.executable, "-B", str(SCRIPT), *args],
                              env={**os.environ, **self.environment, **environment},
                              capture_output=True, text=True, timeout=15, check=False)

    def test_read_only_recipes_are_bounded_and_do_not_print_secrets(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.server.calls), 4)
        self.assertTrue(all(method == "GET" and authorization == "Bearer " + TOKEN
                            for method, _, authorization, _ in self.server.calls))
        self.assertIn("limit=5", self.server.calls[1][1])
        self.assertIn("limit=5", self.server.calls[2][1])
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
        self.assertNotIn(CLUSTER, result.stdout + result.stderr)

    def test_preview_requires_opt_in_and_never_applies(self):
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "nv.json"
            export.write_text('{"config":{}}')
            result = self.run_cli("--preview-file", str(export))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.server.calls), 5)
        method, path, authorization, body = self.server.calls[-1]
        self.assertEqual((method, path), ("POST", "/api/v1/migration/preview"))
        self.assertEqual(authorization, "Bearer " + TOKEN)
        self.assertEqual(json.loads(body)["export"], '{"config":{}}')
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_preview_result_is_available_to_disposable_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "nv.json"
            export.write_text('{"config":{}}')
            preview = smoke.run(self.environment, export, output=lambda message: None)
        self.assertTrue(preview["summary"]["read_only"])
        self.assertEqual(len(self.server.calls), 5)

    def test_fixed_fixture_apply_retry_rollback_retry(self):
        result = self.run_cli("--apply-rollback-fixture")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS fixture rollback idempotency", result.stdout)
        self.assertFalse(self.server.profile_exists)
        paths = [(method, path) for method, path, _, _ in self.server.calls]
        self.assertEqual(paths[:4], [("GET", path) for path in (
            f"/api/v1/groups?cluster_id={CLUSTER}", "/api/v1/audit/events?limit=5",
            f"/api/v1/security/timeline?cluster_id={CLUSTER}&type=dpi_threat%2Cruntime_event%2Cnetwork_violation&limit=5",
            f"/api/v1/scan-jobs?cluster_id={CLUSTER}")])
        self.assertEqual(sum(path.endswith(":apply") for _, path in paths), 2)
        self.assertEqual(sum(path.endswith(":rollback") for _, path in paths), 2)
        self.assertEqual(sum(path == "/api/v1/migration/preview" for _, path in paths), 1)
        self.assertTrue(all(auth == "Bearer " + TOKEN for _, _, auth, _ in self.server.calls))
        self.assertEqual(json.loads(self.server.calls[5][3])["export"], smoke.FIXTURE_EXPORT)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
        self.assertNotIn(IMPORT_ID, result.stdout + result.stderr)

    def test_fixture_refuses_existing_profile_without_mutation(self):
        self.server.profile_exists = True
        result = self.run_cli("--apply-rollback-fixture")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stderr)
        self.assertTrue(self.server.profile_exists)
        self.assertFalse(any(method == "POST" for method, _, _, _ in self.server.calls))

    def test_fixture_refuses_arbitrary_export_before_requests(self):
        result = self.run_cli("--apply-rollback-fixture", "--preview-file", "ignored.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.server.calls, [])

    def test_fixture_rejects_bad_preview_before_apply(self):
        self.server.overrides["/api/v1/migration/preview"] = (200, {
            "import_id": IMPORT_ID, "summary": {"source": "neuvector", "total": 1,
            "create": 0, "unsupported": 0, "vulnerability_profiles": 1, "read_only": True},
            "vulnerability_profiles": [{"name": smoke.FIXTURE_NAME, "diff_action": "update"}],
        })
        result = self.run_cli("--apply-rollback-fixture")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(path.endswith(":apply") for _, path, _, _ in self.server.calls))
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_fixture_cleans_up_after_bad_apply_response(self):
        path = f"/api/v1/migration/imports/{IMPORT_ID}:apply"
        self.server.overrides[path] = (200, {"error": TOKEN})
        result = self.run_cli("--apply-rollback-fixture")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.server.profile_exists)
        self.assertEqual(sum(path.endswith(":rollback") for _, path, _, _ in self.server.calls), 1)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
        self.assertNotIn(IMPORT_ID, result.stdout + result.stderr)

    def test_fixture_cleans_up_after_wrong_apply_count(self):
        path = f"/api/v1/migration/imports/{IMPORT_ID}:apply"
        self.server.overrides[path] = (200, {"id": IMPORT_ID, "status": "applied",
                                             "applied": {"created": 0, "updated": 1,
                                                         "vulnerability_profiles": 1,
                                                         "registries": 0}})
        result = self.run_cli("--apply-rollback-fixture")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected result or profile count", result.stderr)
        self.assertFalse(self.server.profile_exists)
        self.assertEqual(sum(call[1].endswith(":rollback") for call in self.server.calls), 1)

    def test_fixture_reports_unconfirmed_rollback_without_response_body(self):
        path = f"/api/v1/migration/imports/{IMPORT_ID}:rollback"
        self.server.overrides[path] = (409, {"error": TOKEN})
        result = self.run_cli("--apply-rollback-fixture")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cleanup rollback unconfirmed", result.stderr)
        self.assertEqual(sum(call[1] == path for call in self.server.calls), 2)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_rejects_nonlocal_origin_and_missing_environment_before_requests(self):
        for origin in ("https://example.com:443", "http://localhost:8080",
                       "http://127.0.0.1:1234/path", "http://127.0.0.1"):
            with self.subTest(origin=origin):
                result = self.run_cli(CONSTELLATION=origin)
                self.assertNotEqual(result.returncode, 0)
        result = self.run_cli(TOKEN="")
        self.assertIn("set TOKEN", result.stderr)
        self.assertEqual(self.server.calls, [])

    def test_rejects_bad_shape_without_echoing_response(self):
        self.server.overrides["/api/v1/groups"] = (200, {"groups": TOKEN})
        result = self.run_cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected groups to be list", result.stderr)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
        self.assertEqual(len(self.server.calls), 1)

    def test_rejects_nonobject_list_entries(self):
        self.server.overrides["/api/v1/groups"] = (200, {"groups": [TOKEN]})
        result = self.run_cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected groups entries to be objects", result.stderr)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_rejects_redirect_and_large_response(self):
        self.server.overrides["/api/v1/groups"] = (302, b"")
        result = self.run_cli()
        self.assertIn("HTTP 302", result.stderr)
        self.assertEqual(len(self.server.calls), 1)
        self.server.calls.clear()
        self.server.overrides["/api/v1/groups"] = (200, b"x" * (smoke.MAX_RESPONSE + 1))
        result = self.run_cli()
        self.assertIn("response exceeds", result.stderr)
        self.assertEqual(len(self.server.calls), 1)

    def test_rejects_invalid_or_oversized_preview_before_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "nv.json"
            for content in ("not JSON", "x" * (smoke.MAX_EXPORT + 1)):
                with self.subTest(size=len(content)):
                    export.write_text(content)
                    result = self.run_cli("--preview-file", str(export))
                    self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.server.calls, [])


if __name__ == "__main__":
    unittest.main()
