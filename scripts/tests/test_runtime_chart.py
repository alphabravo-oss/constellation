"""Verify optional execution dry-run rendering without changing existing gates."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy/charts/constellation"


class RuntimeChartTests(unittest.TestCase):
    def render(self, *values):
        command = ["helm", "template", "runtime-proof", str(CHART), "--show-only",
                   "templates/runtime-agent-daemonset.yaml"]
        for value in values:
            command.extend(["--set", value])
        return subprocess.run(command, text=True, capture_output=True, check=False)

    def test_omission_preserves_existing_environment(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("CONSTELLATION_EXEC_ENFORCER_DRYRUN", result.stdout)
        for name in ("PROCESS_ENFORCER", "FILE_PROFILE_ENFORCER", "EXEC_ENFORCER",
                     "DP_ENFORCE", "DLP_ENFORCE"):
            self.assertRegex(result.stdout, rf'name: CONSTELLATION_{name}\s+value: "false"')

    def test_explicit_true_and_false_render_without_arming_monitor_mode(self):
        for value in ("true", "false"):
            with self.subTest(value=value):
                result = self.render("runtimeAgent.execDryRun=" + value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.count("name: CONSTELLATION_EXEC_ENFORCER_DRYRUN"), 1)
                self.assertRegex(result.stdout, rf'name: CONSTELLATION_EXEC_ENFORCER_DRYRUN\s+value: "{value}"')
                self.assertRegex(result.stdout, r'name: CONSTELLATION_EXEC_ENFORCER\s+value: "false"')
                self.assertRegex(result.stdout, r'name: CONSTELLATION_EXEC_ENFORCER_MODE\s+value: "monitor"')

    def test_explicit_dry_run_remains_true_with_protect_mode(self):
        result = self.render("runtimeAgent.enforcement.mode=protect", "runtimeAgent.execDryRun=true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r'name: CONSTELLATION_EXEC_ENFORCER\s+value: "true"')
        self.assertRegex(result.stdout, r'name: CONSTELLATION_EXEC_ENFORCER_DRYRUN\s+value: "true"')

    def test_string_is_rejected_instead_of_truthy_coercion(self):
        result = subprocess.run(
            ["helm", "template", "runtime-proof", str(CHART), "--set-string",
             "runtimeAgent.execDryRun=false"], text=True, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("execDryRun", result.stderr)
        self.assertIn("boolean", result.stderr)
