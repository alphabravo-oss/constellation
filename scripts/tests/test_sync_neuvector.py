#!/usr/bin/env python3
"""Private-fixture regression for declared vendor patches and failure preservation."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PATCH_NAME = "010-connection-lookup-application.patch"
PATCH_NAMES = (PATCH_NAME, "011-connection-report-wall-time.patch")


class VendorSyncTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="neuvector-sync-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.repo = self.directory / "repo"
        self.vendor = self.repo / "third_party/neuvector"
        self.upstream = self.directory / "upstream"
        for directory in [self.repo / "scripts", self.vendor / "dp", self.upstream / "dp"]:
            directory.mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/sync-neuvector.sh", self.repo / "scripts/sync-neuvector.sh")
        for name in ["base.h", "defs.h", "LICENSE"]:
            shutil.copyfile(ROOT / "third_party/neuvector" / name, self.upstream / name)
        shutil.copyfile(ROOT / "third_party/neuvector/dp/ctrl.c", self.upstream / "dp/ctrl.c")
        declared = {name: (ROOT / "third_party/neuvector/local-patches" / name).read_bytes()
                    for name in PATCH_NAMES}
        for name in reversed(PATCH_NAMES):
            self.command(["patch", "-R", "-p1", "--batch", "--fuzz=0", "--no-backup-if-mismatch"], self.upstream, declared[name])
        self.command(["git", "init", "-q"], self.upstream)
        self.command(["git", "add", "."], self.upstream)
        self.command(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                      "commit", "-qm", "fixture upstream"], self.upstream)
        self.revision = self.command(["git", "rev-parse", "HEAD"], self.upstream).stdout.decode().strip()
        shutil.copytree(self.upstream / "dp", self.vendor / "dp", dirs_exist_ok=True)
        for name in ["base.h", "defs.h", "LICENSE"]:
            shutil.copyfile(self.upstream / name, self.vendor / name)
        (self.vendor / "NOTICE").write_text(f"Source rev:   {self.revision}\nSource tag:   fixture\nVendored at:  2026-10-17\n")
        self.patches = self.vendor / "local-patches"
        self.patches.mkdir()
        for name in PATCH_NAMES:
            (self.patches / name).write_bytes(declared[name])
            self.command(["patch", "-p1", "--batch", "--fuzz=0", "--no-backup-if-mismatch"], self.vendor, declared[name])
        self.control = self.vendor / "dp/ctrl.c"

    def tearDown(self):
        self.assertEqual(list(self.vendor.rglob("*.orig")), [])
        self.assertEqual(list(self.vendor.rglob("*.rej")), [])

    def test_declared_stack_reproduces_current_vendor_bytes(self):
        target = self.directory / "roundtrip"
        shutil.copytree(ROOT / "third_party/neuvector", target)
        def snapshot():
            return {str(p.relative_to(target)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in target.rglob("*") if p.is_file()}
        expected = snapshot()
        patch_paths = sorted((target / "local-patches").glob("*.patch"))
        self.assertEqual([p.name for p in patch_paths], ["000-existing-threat-controls.patch", *PATCH_NAMES])
        for path in reversed(patch_paths):
            self.command(["patch", "-R", "-p1", "--batch", "--fuzz=0", "--no-backup-if-mismatch"], target, path.read_bytes())
        self.assertNotIn(b"key.application = log->Application;", (target / "dp/ctrl.c").read_bytes())
        self.assertNotIn(b"ctrl_set_threat", (target / "dp/ctrl.c").read_bytes())
        self.assertNotIn(b"dp_ctrl_connect_timestamp", (target / "dp/ctrl.c").read_bytes())
        for path in patch_paths:
            self.command(["patch", "-p1", "--batch", "--fuzz=0", "--no-backup-if-mismatch"], target, path.read_bytes())
        self.assertEqual(snapshot(), expected)
        self.assertEqual(list(target.rglob("*.orig")), [])

    def command(self, command, cwd, body=None, expected=0):
        result = subprocess.run(command, cwd=cwd, input=body, capture_output=True, check=False)
        self.assertEqual(result.returncode, expected, result.stdout.decode() + result.stderr.decode())
        return result

    def sync(self, mode="--sync", revision=None, build="skip", expected=0):
        command = ["bash", "scripts/sync-neuvector.sh", mode, "--upstream", str(self.upstream)]
        if mode == "--sync":
            command += ["--rev", revision or self.revision, "--build", build]
        return self.command(command, self.repo, expected=expected)

    def source_snapshot(self):
        return {str(p.relative_to(self.vendor)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.vendor.rglob("*") if p.is_file() and self.patches not in p.parents}

    def test_declared_patch_is_clean_and_sync_is_idempotent(self):
        self.sync("--diff")
        source = self.control.read_bytes()
        self.sync()
        self.sync()
        self.sync("--diff")
        self.assertEqual(source, self.control.read_bytes())
        self.assertEqual(sorted(p.name for p in self.patches.iterdir()), list(PATCH_NAMES))

    def test_undeclared_drift_is_detected_and_preserved_after_repeated_sync(self):
        with self.control.open("a") as f:
            f.write("\n/* owned fixture undeclared drift */\n")
        source = self.control.read_bytes()
        diff = self.sync("--diff", expected=2).stdout
        self.assertIn(b"--- a/dp/ctrl.c", diff)
        self.assertIn(b"+++ b/dp/ctrl.c", diff)
        self.assertNotIn(str(self.directory).encode(), diff)
        self.sync()
        captured = sorted(self.patches.glob("*.post-sync-drift-*.patch"))
        self.assertEqual(len(captured), 1)
        self.assertIn(b"owned fixture undeclared drift", captured[0].read_bytes())
        self.assertGreater(captured[0].name, PATCH_NAME)
        self.sync()
        self.sync("--diff")
        self.assertEqual(source, self.control.read_bytes())
        self.assertEqual(len(list(self.patches.glob("*.patch"))), len(PATCH_NAMES) + 1)

    def test_invalid_declared_patch_fails_without_replacing_source(self):
        (self.patches / "020-invalid.patch").write_text("not a patch\n")
        previous = self.source_snapshot()
        self.sync(expected=3)
        self.assertEqual(previous, self.source_snapshot())

    def test_conflicting_new_upstream_preserves_source_and_captured_drift(self):
        with self.control.open("a") as f:
            f.write("\n/* preserve on conflict */\n")
        previous = self.source_snapshot()
        upstream_control = self.upstream / "dp/ctrl.c"
        upstream_control.write_text(upstream_control.read_text().replace("conn4_key_t key;", "conn4_key_t differently_named_key;"))
        self.command(["git", "add", "."], self.upstream)
        self.command(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                      "commit", "-qm", "conflicting upstream"], self.upstream)
        revision = self.command(["git", "rev-parse", "HEAD"], self.upstream).stdout.decode().strip()
        self.sync(revision=revision, expected=3)
        self.assertEqual(previous, self.source_snapshot())
        captured = list(self.patches.glob("*.post-sync-drift-*.patch"))
        self.assertEqual(len(captured), 1)
        self.assertIn(b"preserve on conflict", captured[0].read_bytes())

    def test_build_failure_restores_prior_source_and_retains_drift_patch(self):
        with self.control.open("a") as f:
            f.write("\n/* preserve on build failure */\n")
        (self.repo / "Makefile").write_text("dp:\n\t@exit 42\n")
        previous = self.source_snapshot()
        self.sync(build="dp", expected=4)
        self.assertEqual(previous, self.source_snapshot())
        captured = list(self.patches.glob("*.post-sync-drift-*.patch"))
        self.assertEqual(len(captured), 1)
        self.assertIn(b"preserve on build failure", captured[0].read_bytes())
        self.sync()
        self.sync("--diff")

    def test_lexical_patch_order_and_forward_reverse_roundtrip(self):
        patch = (self.patches / PATCH_NAME).read_bytes()
        fixed = self.control.read_bytes()
        self.command(["patch", "-R", "-p1", "--batch", "--fuzz=0", "--no-backup-if-mismatch"], self.vendor, patch)
        self.assertNotIn(b"key.application = log->Application;", self.control.read_bytes())
        self.command(["patch", "-p1", "--batch", "--fuzz=0", "--no-backup-if-mismatch"], self.vendor, patch)
        self.assertEqual(fixed, self.control.read_bytes())
        second = ("--- a/dp/ctrl.c\n+++ b/dp/ctrl.c\n@@ -2695,1 +2695,1 @@\n"
                  "-        key.application = log->Application;\n"
                  "+        key.application = (uint16_t)log->Application;\n").encode()
        (self.patches / "020-order-fixture.patch").write_bytes(second)
        self.command(["patch", "-p1", "--batch", "--fuzz=0", "--no-backup-if-mismatch"], self.vendor, second)
        expected = self.control.read_bytes()
        self.sync()
        self.sync("--diff")
        self.assertEqual(expected, self.control.read_bytes())


if __name__ == "__main__":
    unittest.main()
