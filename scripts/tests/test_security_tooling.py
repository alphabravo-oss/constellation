import json
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

    def executable(self, name, body):
        executable = self.directory / name
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

    def test_gosec_propagates_findings(self):
        self.executable("gosec", 'printf "%s\\n" "$@" > "$CALLS"\nexit 7\n')
        result = self.run_scan("gosec")
        self.assertEqual(result.returncode, 7)
        self.assertIn("sarif", self.calls.read_text())
        self.assertNotIn("-no-fail", self.calls.read_text())

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
