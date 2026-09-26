"""Run: python3 -B -m unittest discover -s scripts/tests -p test_endpoint_mapping.py"""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("check_endpoint_mapping", ROOT / "scripts/check_endpoint_mapping.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def map_document(target):
    return ("## Primary Endpoint Map\n\n"
            "| NeuVector family | NeuVector examples | Constellation API | Constellation UI | Status |\n"
            "| --- | --- | --- | --- | --- |\n"
            f"| Groups | `/v1/group` | {target} | Groups | Implemented |\n\n"
            "## Next section\n")


class EndpointMappingTests(unittest.TestCase):
    def test_explicit_paths_methods_queries_and_wildcards(self):
        document = map_document("`GET /api/v1/groups?limit=10`, `/api/v1/groups/{id}/usage`, "
                                "`/api/v1/reports/compliance.*`")
        document += "`/api/v1/groups/{id}/usage`\n"
        paths = {
            "/api/v1/groups": {"get": {}},
            "/api/v1/groups/{group_id}/usage": {"get": {}},
            "/api/v1/reports/compliance.pdf": {"get": {}},
        }
        count, errors = checker.check_endpoints(document, paths)
        self.assertEqual(count, 4)
        self.assertEqual(errors, [])

    def test_missing_path_and_wrong_method(self):
        document = map_document("`POST /api/v1/groups`, `/api/v1/missing`")
        _, errors = checker.check_endpoints(document, {"/api/v1/groups": {"get": {}}})
        self.assertEqual(len(errors), 2)
        self.assertIn("POST /api/v1/groups has no OpenAPI operation", errors[0])
        self.assertIn("/api/v1/missing has no OpenAPI path", errors[1])

    def test_map_row_without_explicit_target_fails(self):
        _, errors = checker.check_endpoints(map_document("SBOM/VEX endpoints"), {})
        self.assertTrue(any("no explicit API path" in error for error in errors))
        _, errors = checker.check_endpoints("## Other\n", {})
        self.assertTrue(any("no endpoint map rows" in error for error in errors))

    def test_links_check_local_targets_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs" / "present.md").write_text("# Good Heading\n")
            document = ("[ok](present.md#good-heading) [missing](gone.md) "
                        "[anchor](present.md#other) [web](https://example.com)\n")
            count, errors = checker.check_links(document, root)
        self.assertEqual(count, 3)
        self.assertEqual(len(errors), 2)
        self.assertIn("gone.md", errors[0])
        self.assertIn("present.md#other", errors[1])

    def test_route_gate_runs_existing_live_router_tests(self):
        root = Path("/example")
        with patch.object(checker.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(checker.check_routes(root), [])
        self.assertEqual(run.call_args.args[0],
                         ["go", "test", "./internal/server", "-run", checker.ROUTE_TESTS, "-count=1"])
        self.assertEqual(run.call_args.kwargs["cwd"], root)
        self.assertEqual(run.call_args.kwargs["env"]["GOWORK"], "off")
        with patch.object(checker.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "stale spec", "")):
            self.assertIn("stale spec", checker.check_routes(root)[0])


if __name__ == "__main__":
    unittest.main()
