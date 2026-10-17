"""The TLS scenario must never retain private material in captured evidence."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy/e2e/threat-scenarios/04-admission-tls/run.sh"
KUBECTL = r'''#!/usr/bin/env python3
import base64
import json
import os
from pathlib import Path
import stat
import sys

args = sys.argv[1:]
if args[:3] == ["create", "secret", "tls"]:
    key = Path(next(a.split("=", 1)[1] for a in args if a.startswith("--key=")))
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(key.parent.stat().st_mode) == 0o700
    assert key.is_file()
    Path(os.environ["KEY_LOCATION"]).write_text(str(key))
    print(json.dumps({"kind": "Secret", "data": {
        "tls.key": base64.b64encode(key.read_bytes()).decode()}}))
elif args == ["apply", "-f", "-"]:
    secret = json.load(sys.stdin)
    assert b"PRIVATE KEY" in base64.b64decode(secret["data"]["tls.key"])
    Path(os.environ["SECRET_RECEIVED"]).write_text("received")
    if os.environ.get("FAIL_SECRET_APPLY") == "1":
        sys.exit(7)
elif args[:2] == ["get", "pods"]:
    print("fixture-admission-pod")
'''


class AdmissionTLSCredentialsTests(unittest.TestCase):
    def run_scenario(self, fail=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries, captures, scratch = (root / name for name in ("bin", "captures", "scratch"))
            for path in (binaries, captures / "tls", scratch):
                path.mkdir(parents=True)
            # An old public capture must not cause reuse of a missing/leaked key.
            (captures / "tls/tls.crt").write_text("historical public capture")
            for name, source in (("kubectl", KUBECTL), ("sleep", "#!/bin/sh\nexit 0\n")):
                path = binaries / name
                path.write_text(source)
                path.chmod(0o700)
            location, received = root / "key-location", root / "received"
            env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ["PATH"],
                       TMPDIR=str(scratch), CONSTELLATION_E2E_CAPTURE_DIR=str(captures),
                       KEY_LOCATION=str(location), SECRET_RECEIVED=str(received),
                       FAIL_SECRET_APPLY="1" if fail else "0", KUBECONFIG=str(root / "fake-config"))
            result = subprocess.run(["bash", str(SCRIPT)], env=env, text=True,
                                    capture_output=True, check=False, timeout=30)
            self.assertEqual(result.returncode, 7 if fail else 0, result.stderr)
            self.assertTrue(received.is_file(), "Secret must reach Kubernetes through stdin")
            key = Path(location.read_text())
            self.assertFalse(key.parent.exists(), "private workspace must be removed on exit")
            self.assertFalse((captures / "secret.yaml").exists())
            self.assertEqual(list(scratch.iterdir()), [])
            self.assertNotIn("PRIVATE KEY", result.stdout + result.stderr)
            for artifact in captures.rglob("*"):
                if artifact.is_file():
                    self.assertNotEqual(artifact.suffix, ".key")
                    self.assertNotIn(b"PRIVATE KEY", artifact.read_bytes())
            certificate = captures / "tls/tls.crt"
            self.assertIn("BEGIN CERTIFICATE", certificate.read_text())
            # Verify generated evidence really has the promised short lifetime.
            parsed = subprocess.run(["openssl", "x509", "-in", str(certificate),
                                     "-checkend", "172800", "-noout"],
                                    text=True, capture_output=True, check=False)
            self.assertEqual(parsed.returncode, 1, "test certificate must expire within two days")

    def test_streams_secret_and_retains_only_public_evidence(self):
        self.run_scenario()

    def test_private_workspace_is_removed_after_failed_apply(self):
        self.run_scenario(fail=True)


if __name__ == "__main__":
    unittest.main()
