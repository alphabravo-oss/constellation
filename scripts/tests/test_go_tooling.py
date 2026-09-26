"""Fast, dependency-free contract tests for the Go test shell entry points.

Run: python3 -B -m unittest discover -s scripts/tests -p test_go_tooling.py
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FAKE = r'''
import json
import os
from pathlib import Path
import sys

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({"tool": tool, "args": args, "cwd": os.getcwd(),
        "env": {key: os.environ.get(key) for key in (
            "DATABASE_URL", "CONSTELLATION_TEST_DATABASE_URL", "GOOSE_DRIVER",
            "GOOSE_DBSTRING", "GOOSE_MIGRATION_DIR", "GOWORK")}}) + "\n")
if tool == "docker":
    if args[0] == "run":
        if os.environ.get("FAKE_DOCKER_RUN_FAIL"):
            sys.exit(21)
        print("disposable-test-db")
    elif args[0] == "port":
        print("127.0.0.1:55432")
    elif args[0] == "exec":
        sys.exit(int(os.environ.get("FAKE_NOT_READY", "0")))
    elif args[0] == "rm":
        sys.exit(int(os.environ.get("FAKE_CLEANUP_EXIT", "0")))
elif tool.endswith("goose"):
    migrations = sum(json.loads(line)["tool"] == tool
                     for line in Path(os.environ["FAKE_LOG"]).read_text().splitlines())
    if migrations == int(os.environ.get("FAKE_MIGRATION_FAIL_AT", "1")):
        sys.exit(int(os.environ.get("FAKE_MIGRATION_EXIT", "0")))
elif tool.endswith("gotestsum"):
    for flag, content in (("--junitfile", "<testsuites/>"),
                          ("--jsonfile", '{"Action":"pass"}\n')):
        Path(args[args.index(flag) + 1]).write_text(content)
    sys.exit(int(os.environ.get("FAKE_TEST_EXIT", "0")))
elif tool == "go":
    sys.exit(int(os.environ.get("FAKE_TEST_EXIT", "0")))
'''


class GoToolingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="go tooling ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        for name in ("test-go.sh", "test-clean-database.sh"):
            shutil.copyfile(ROOT / "scripts" / name, self.root / "scripts" / name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("docker", "goose", "gotestsum", "go", "sleep"):
            self.make_fake(name)
        self.log = self.root / "calls.jsonl"
        self.env = os.environ.copy()
        for key in ("GOTESTSUM_BIN", "GOOSE_BIN", "ARTIFACT_DIR",
                    "TEST_GO_USE_GOTESTSUM", "PARITY_POSTGRES_IMAGE"):
            self.env.pop(key, None)
        for key in list(self.env):
            if key.startswith("FAKE_"):
                self.env.pop(key)
        self.env.update(PATH=f"{self.bin}:{os.defpath}", FAKE_LOG=str(self.log))

    def make_fake(self, name):
        executable = self.bin / name
        executable.write_text(f"#!{sys.executable}\n" + FAKE)
        executable.chmod(0o755)
        return str(executable)

    def run_script(self, *args, clean=False, **env):
        script = "test-clean-database.sh" if clean else "test-go.sh"
        return subprocess.run(
            ["bash", str(self.root / "scripts" / script), *args],
            cwd=self.root.parent, env={**self.env, **env}, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )

    def calls(self, tool=None):
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return [call for call in calls if tool is None or call["tool"] == tool]

    def assert_cleaned(self):
        self.assertEqual(self.calls()[-1]["args"], ["rm", "-f", "disposable-test-db"])

    def assert_reports(self, mode, directory="artifacts", tool="gotestsum"):
        args = self.calls(tool)[0]["args"]
        for flag, suffix in (("--junitfile", "xml"), ("--jsonfile", "json")):
            report = str(Path(directory) / f"{mode}.{suffix}")
            self.assertEqual(args[args.index(flag) + 1], report)
            self.assertTrue((self.root / report).is_file())
        return args[args.index("--") + 1:]

    def test_unit_defaults(self):
        result = self.run_script("unit", GOWORK="/outside/go.work")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.assert_reports("unit"), ["-race", "-shuffle=on", "-count=1", "./..."])
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.calls()[0]["cwd"], str(self.root))
        self.assertEqual(self.calls()[0]["env"]["GOWORK"], "off")

    def test_database_runner_ignores_parent_workspace(self):
        result = self.run_script(clean=True, GOWORK="/outside/go.work")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls("go")[0]["env"]["GOWORK"], "off")

    def test_unit_overrides_packages_and_failure(self):
        runner = self.make_fake("custom gotestsum")
        result = self.run_script("unit", "./pkg/...", "./internal/...",
                                 GOTESTSUM_BIN=runner, ARTIFACT_DIR="test reports",
                                 FAKE_TEST_EXIT="17")
        self.assertEqual(result.returncode, 17, result.stderr)
        args = self.assert_reports("unit", "test reports", "custom gotestsum")
        self.assertEqual(args[-2:], ["./pkg/...", "./internal/..."])

    def test_usage_errors(self):
        for args in ((), ("invalid",)):
            with self.subTest(args=args):
                result = self.run_script(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Usage:", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_missing_gotestsum_fails_before_database(self):
        for mode in ("unit", "integration"):
            with self.subTest(mode=mode):
                result = self.run_script(mode, GOTESTSUM_BIN=str(self.root / "missing"))
                self.assertEqual(result.returncode, 127)
                self.assertIn("GOTESTSUM_BIN", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_clean_database_default_preserved(self):
        result = self.run_script(clean=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls("go")[0]["args"],
                         ["test", "-tags=integration", "-p", "1", "-count=2", "./..."])
        self.assertEqual(self.calls("gotestsum"), [])
        self.assertFalse((self.root / "artifacts").exists())
        self.assert_migrations()
        self.assert_cleaned()

    def test_clean_database_custom_packages(self):
        result = self.run_script("./pkg/...", "./internal/...", clean=True,
                                 GOTESTSUM_BIN=str(self.root / "missing"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls("go")[0]["args"][-2:], ["./pkg/...", "./internal/..."])
        self.assertEqual(self.calls("gotestsum"), [])
        self.assert_cleaned()

    def assert_migrations(self, tool="goose"):
        migrations = self.calls(tool)
        self.assertEqual([call["args"] for call in migrations], [["up"], ["up"]])
        url = "postgres://test:test@127.0.0.1:55432/constellation_test?sslmode=disable"
        for call in migrations:
            self.assertEqual(call["env"], {
                "DATABASE_URL": url, "CONSTELLATION_TEST_DATABASE_URL": url,
                "GOOSE_DBSTRING": url, "GOOSE_DRIVER": "postgres",
                "GOOSE_MIGRATION_DIR": "db/migrations",
                "GOWORK": "off",
            })
        all_calls = self.calls()
        test_index = next(i for i, call in enumerate(all_calls)
                          if call["tool"] == "go" or call["tool"].endswith("gotestsum"))
        self.assertLess(all_calls.index(migrations[-1]), test_index)
        self.assertEqual(all_calls[test_index]["env"], migrations[-1]["env"])

    def test_integration_delegates_and_reports(self):
        directory = str(self.root / "absolute reports")
        result = self.run_script("integration", "./internal/...", "./pkg/...",
                                 ARTIFACT_DIR=directory,
                                 GOOSE_BIN=self.make_fake("custom goose"),
                                 GOTESTSUM_BIN=self.make_fake("custom gotestsum"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.assert_reports("integration", directory, "custom gotestsum"),
                         ["-tags=integration", "-p", "1", "-count=2", "-race", "-shuffle=on",
                          "./internal/...", "./pkg/..."])
        self.assert_migrations("custom goose")
        self.assertEqual(self.calls("go"), [])
        self.assert_cleaned()

    def test_direct_gotestsum_opt_in(self):
        result = self.run_script(clean=True, TEST_GO_USE_GOTESTSUM="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.assert_reports("integration")[-1], "./...")
        self.assert_cleaned()

    def test_test_failure_survives_cleanup_failure(self):
        for clean in (False, True):
            with self.subTest(clean=clean):
                self.log.unlink(missing_ok=True)
                args = () if clean else ("integration",)
                result = self.run_script(*args, clean=clean, FAKE_TEST_EXIT="23", FAKE_CLEANUP_EXIT="9")
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertIn("Failed to remove", result.stderr)
                self.assert_cleaned()

    def test_migration_failure_cleans_up_and_stops_tests(self):
        for fail_at in (1, 2):
            with self.subTest(fail_at=fail_at):
                self.log.unlink(missing_ok=True)
                result = self.run_script("integration", FAKE_MIGRATION_EXIT="19",
                                         FAKE_MIGRATION_FAIL_AT=str(fail_at))
                self.assertEqual(result.returncode, 19, result.stderr)
                self.assertEqual(len(self.calls("goose")), fail_at)
                self.assertEqual(self.calls("gotestsum"), [])
                self.assert_cleaned()

    def test_cleanup_failure_after_success_is_reported(self):
        result = self.run_script("integration", FAKE_CLEANUP_EXIT="9")
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertIn("Failed to remove", result.stderr)
        self.assert_reports("integration")
        self.assert_cleaned()

    def test_artifact_directory_failure_prevents_test_and_database_start(self):
        artifact_file = self.root / "not a directory"
        artifact_file.write_text("existing file")
        for mode in ("unit", "integration"):
            with self.subTest(mode=mode):
                result = self.run_script(mode, ARTIFACT_DIR=str(artifact_file))
                self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_unready_database_cleans_up_without_migrations(self):
        result = self.run_script("integration", FAKE_NOT_READY="1")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(len([call for call in self.calls("docker") if call["args"][0] == "exec"]), 60)
        self.assertIn(["logs", "disposable-test-db"], [call["args"] for call in self.calls("docker")])
        self.assertEqual(self.calls("goose"), [])
        self.assertEqual(self.calls("gotestsum"), [])
        self.assert_cleaned()

    def test_container_start_failure_propagates(self):
        result = self.run_script("integration", FAKE_DOCKER_RUN_FAIL="1")
        self.assertEqual(result.returncode, 21, result.stderr)
        self.assertEqual(len(self.calls()), 1)


if __name__ == "__main__":
    unittest.main()
