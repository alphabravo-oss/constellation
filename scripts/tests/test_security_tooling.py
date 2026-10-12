import copy
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class SecurityToolingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.artifacts = self.directory / "reports"
        self.calls = self.directory / "calls"
        self.environment = dict(
            os.environ,
            PATH=f"{self.directory}:{os.environ['PATH']}",
            ARTIFACT_DIR=str(self.artifacts),
            CALLS=str(self.calls),
        )

        self.environment.pop("GOTMPDIR", None)
        self.environment["XDG_CACHE_HOME"] = str(self.directory / "cache")
        self.executable("go", 'test "$*" = "list -f {{.Dir}} ./..."\nprintf "/module/cmd/api\\n/module/internal/app\\n"\n')

    def executable(self, name, body):
        executable = self.directory / name
        if name == "gosec":
            body = '''printf '{"runs":[{"results":[]}]}' > "$ARTIFACT_DIR/gosec.sarif"
printf '{"Issues":[]}'
''' + body
        executable.write_text("#!/bin/bash\nset -euo pipefail\n" + body)
        executable.chmod(0o755)
        return executable

    def run_scan(self, scanner):
        return subprocess.run(
            ["bash", "scripts/security-scan.sh", scanner],
            cwd=ROOT,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_make_lint_propagates_findings(self):
        executable = self.executable("golangci-lint", 'printf "%s\\n" "$@" > "$CALLS"\nexit 23\n')
        result = subprocess.run(
            ["make", "lint", f"GOLANGCI_LINT={executable}"],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Error 23", result.stderr)
        self.assertIn("./...", self.calls.read_text())
        self.assertNotIn("skipping", result.stdout + result.stderr)

    def test_make_lint_requires_tool(self):
        result = subprocess.run(
            ["make", "lint", f"GOLANGCI_LINT={self.directory / 'missing'}"],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is required", result.stderr)

    def test_format_uses_module_scope_and_blocks_differences_and_errors(self):
        for body, expected in (("exit 0\n", 0), ('echo "format diff"\n', 1), ("exit 9\n", 9)):
            with self.subTest(body=body):
                executable = self.executable("golangci-lint", 'printf "%s\\n" "$@" > "$CALLS"\n' + body)
                self.environment["GOLANGCI_LINT"] = str(executable)
                result = subprocess.run(["bash", "scripts/check-go-format.sh"], cwd=ROOT,
                                        env=self.environment, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, expected)
                self.assertEqual(self.calls.read_text().splitlines(), ["fmt", "--diff", "/module/cmd/api", "/module/internal/app"])

    def test_format_discovery_failure_or_empty_result_blocks(self):
        executable = self.executable("golangci-lint", 'touch "$CALLS"\n')
        self.environment["GOLANGCI_LINT"] = str(executable)
        for body in ("exit 9\n", "exit 0\n"):
            with self.subTest(body=body):
                self.executable("go", body)
                result = subprocess.run(["bash", "scripts/check-go-format.sh"], cwd=ROOT,
                                        env=self.environment, capture_output=True, text=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.calls.exists())

    def test_gosec_propagates_findings(self):
        self.executable("gosec", 'printf "%s\\n" "$@" > "$CALLS"\nexit 7\n')
        result = self.run_scan("gosec")
        self.assertEqual(result.returncode, 7)
        self.assertIn("sarif", self.calls.read_text())
        self.assertNotIn("-no-fail", self.calls.read_text())

    def test_gosec_defaults_to_bounded_resources(self):
        for key in ("GOSEC_GOMEMLIMIT", "GOSEC_GOMAXPROCS", "GOSEC_CONCURRENCY"):
            self.environment.pop(key, None)
        self.executable("gosec", 'printf "%s\\n" "$GOMEMLIMIT" "$GOMAXPROCS" "$@" > "$CALLS"\n')
        self.assertEqual(self.run_scan("gosec").returncode, 0)
        self.assertEqual(self.calls.read_text().splitlines()[:4], ["2GiB", "2", "-concurrency", "2"])

    def test_gosec_resource_overrides_preserve_findings_exit(self):
        self.environment.update(GOSEC_GOMEMLIMIT="1GiB", GOSEC_GOMAXPROCS="1", GOSEC_CONCURRENCY="1")
        self.executable("gosec", 'printf "%s\\n" "$GOMEMLIMIT" "$GOMAXPROCS" "$@" > "$CALLS"\nexit 7\n')
        self.assertEqual(self.run_scan("gosec").returncode, 7)
        self.assertEqual(self.calls.read_text().splitlines()[:4], ["1GiB", "1", "-concurrency", "1"])

    def test_gosec_scans_module_packages_and_cleans_owned_scratch(self):
        self.executable("gosec", 'test -d "$GOTMPDIR"\nprintf "%s\\n" "$GOTMPDIR" "$@" > "$CALLS"\nexit 7\n')
        self.assertEqual(self.run_scan("gosec").returncode, 7)
        arguments = self.calls.read_text().splitlines()
        self.assertEqual(arguments[-2:], ["/module/cmd/api", "/module/internal/app"])
        self.assertNotIn("./...", arguments)
        self.assertFalse(Path(arguments[0]).exists())
        self.assertTrue(Path(arguments[0]).is_relative_to(self.directory / "cache"))

    def test_gosec_preserves_caller_owned_scratch(self):
        scratch = self.directory / "caller-scratch"
        scratch.mkdir()
        self.environment["GOTMPDIR"] = str(scratch)
        self.executable("gosec", 'test -d "$GOTMPDIR"\n')
        self.assertEqual(self.run_scan("gosec").returncode, 0)
        self.assertTrue(scratch.exists())

    def test_gosec_discovery_failure_or_empty_result_blocks(self):
        self.executable("gosec", 'touch "$CALLS"\n')
        for body in ("exit 9\n", "exit 0\n"):
            with self.subTest(body=body):
                self.executable("go", body)
                self.assertNotEqual(self.run_scan("gosec").returncode, 0)
                self.assertFalse(self.calls.exists())

    def test_gosec_missing_or_invalid_reports_block(self):
        for body in ('rm "$ARTIFACT_DIR/gosec.sarif"\n', 'echo invalid > "$ARTIFACT_DIR/gosec.sarif"\n'):
            with self.subTest(body=body):
                self.executable("gosec", body)
                self.assertNotEqual(self.run_scan("gosec").returncode, 0)

    def test_gosec_sarif_rebases_distinct_files_and_preserves_findings(self):
        spec = importlib.util.spec_from_file_location("rebase_gosec", ROOT / "scripts/rebase-gosec-sarif.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = {"ruleId": "G101", "message": {"text": "review this"}, "level": "error", "locations": [{
            "physicalLocation": {"artifactLocation": {"uri": "main.go"}, "region": {"startLine": 12}},
        }]}
        report = {"runs": [{"results": [copy.deepcopy(result), copy.deepcopy(result)]}]}
        issues = [{"rule_id": "G101", "details": "review this", "line": "12-14", "file": str(ROOT / name)}
                  for name in ("cmd/api/main.go", "cmd/worker/main.go")]
        rebased = module.rebase(copy.deepcopy(report), {"Issues": issues}, ROOT)
        for entry, name in zip(rebased["runs"][0]["results"], ("cmd/api/main.go", "cmd/worker/main.go"), strict=True):
            self.assertEqual(entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], name)
            entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "main.go"
        self.assertEqual(rebased, report)
        invalid_sources = [issues[:1], [dict(issues[0], rule_id="G999"), issues[1]],
                           [dict(issues[0], file=str(ROOT.parent / "outside.go")), issues[1]],
                           [dict(issues[0], line="13"), issues[1]]]
        for invalid in invalid_sources:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    module.rebase(copy.deepcopy(report), {"Issues": invalid}, ROOT)

    def test_scan_ignores_parent_workspace(self):
        self.environment["GOWORK"] = "/outside/go.work"
        self.executable("gosec", 'test "$GOWORK" = off\n')
        self.assertEqual(self.run_scan("gosec").returncode, 0)

    def test_govulncheck_converts_same_evidence_and_blocks(self):
        self.executable("govulncheck", '''printf '%s\\n' "$*" >> "$CALLS"
if [[ "$1" == -json ]]; then
  printf '{"finding":{}}\\n'
elif [[ "$4" == sarif ]]; then
  cat > "${ARTIFACT_DIR}/converted-input.json"
  printf '{"version":"2.1.0","runs":[]}\\n'
else
  cat >/dev/null
  echo 'reachable vulnerability'
  exit 3
fi
''')
        result = self.run_scan("govulncheck")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(
            (self.artifacts / "govulncheck.json").read_bytes(),
            (self.artifacts / "converted-input.json").read_bytes(),
        )
        self.assertEqual(json.loads((self.artifacts / "govulncheck.sarif").read_text())["version"], "2.1.0")
        self.assertIn("reachable vulnerability", (self.artifacts / "govulncheck.txt").read_text())
        self.assertEqual(len(self.calls.read_text().splitlines()), 3)

    def test_sarif_normalization_preserves_findings_and_distinct_stacks(self):
        report = {"runs": [{"results": [
            {"ruleId": "test", "stacks": [{"frames": [1]}, {"frames": [1]}, {"frames": [2]}]},
            {"ruleId": "other", "message": {"text": "still blocks"}},
        ]}]}
        path = self.directory / "report.sarif"
        path.write_text(json.dumps(report))
        subprocess.run(["python3", "scripts/normalize-sarif.py", str(path)], cwd=ROOT, check=True)
        result = json.loads(path.read_text())["runs"][0]["results"]
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["stacks"], [{"frames": [1]}, {"frames": [2]}])
        self.assertEqual(result[1], report["runs"][0]["results"][1])

    def test_govulncheck_analysis_errors_do_not_convert_partial_report(self):
        self.executable("govulncheck", 'printf "%s\\n" "$*" >> "$CALLS"\nexit 9\n')
        self.assertEqual(self.run_scan("govulncheck").returncode, 9)
        self.assertEqual(self.calls.read_text().splitlines(), ["-json ./..."])
        self.assertFalse((self.artifacts / "govulncheck.sarif").exists())

    def test_govulncheck_conversion_errors_block(self):
        self.executable("govulncheck", 'if [[ "$1" == -json ]]; then echo "{}"; else exit 8; fi\n')
        self.assertEqual(self.run_scan("govulncheck").returncode, 8)

    def test_gitleaks_requires_full_history(self):
        self.executable("git", "echo true\n")
        self.executable("gitleaks", 'touch "$CALLS"\n')
        result = self.run_scan("gitleaks")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fetch --unshallow", result.stderr)
        self.assertFalse(self.calls.exists())

    def test_gitleaks_scans_all_refs_redacts_and_blocks(self):
        self.executable("git", "echo false\n")
        self.executable("gitleaks", 'printf "%s\\n" "$@" > "$CALLS"\nexit 5\n')
        self.assertEqual(self.run_scan("gitleaks").returncode, 5)
        arguments = self.calls.read_text().splitlines()
        self.assertIn("--redact=100", arguments)
        self.assertIn("--log-opts=--all", arguments)
        self.assertIn("sarif", arguments)

    def test_invalid_scanner_is_not_a_successful_noop(self):
        self.assertEqual(self.run_scan("unknown").returncode, 2)

    def test_installer_rejects_unknown_tool(self):
        result = subprocess.run(
            ["bash", "scripts/install-ci-tools.sh", "unknown"], cwd=ROOT,
            env=dict(self.environment, CI_TOOLS_BIN=str(self.directory / "bin")),
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)

    def test_frontend_runtime_pins_match(self):
        node_version = (ROOT / ".node-version").read_text().strip()
        self.assertRegex(node_version, r"^\d+\.\d+\.\d+$")
        package = json.loads((ROOT / "frontend/package.json").read_text())
        lock = json.loads((ROOT / "frontend/package-lock.json").read_text())
        self.assertEqual(package["engines"]["node"], node_version)
        self.assertEqual(package["engines"], lock["packages"][""]["engines"])
        self.assertEqual(package["packageManager"], f"npm@{package['engines']['npm']}")
        self.assertIn(
            f"ARG NODE_VERSION={node_version}\n",
            (ROOT / "deploy/docker/Dockerfile.frontend").read_text(),
        )


if __name__ == "__main__":
    unittest.main()
