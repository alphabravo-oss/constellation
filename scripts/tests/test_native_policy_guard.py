#!/usr/bin/env python3
"""No-Docker-writes regression for the native build's local-storage guard."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class NativeBuildStorageGuardTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="native-build-guard-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.repo = self.directory / "small-source"
        (self.repo / "scripts").mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/test-native-policy.sh", self.repo / "scripts/test-native-policy.sh")
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.docker_root = self.directory / "docker data"
        self.docker_root.mkdir()
        self.tmp = self.directory / "tmp"
        self.tmp.mkdir()
        self.calls = self.directory / "calls.jsonl"
        self.tool("docker", '''import json, os, sys
with open(os.environ['TEST_CALLS'], 'a') as f:
    f.write(json.dumps(['docker'] + sys.argv[1:]) + '\\n')
args = sys.argv[1:]
if args[:2] != ['--host', 'unix:///var/run/docker.sock']:
    sys.exit(91)
if args[2:] == ['info', '--format', '{{.DockerRootDir}}']:
    if os.getenv('TEST_INFO_FAIL'): sys.exit(9)
    print(os.environ['TEST_DOCKER_ROOT'])
    sys.exit(0)
if args[2:4] == ['build', '--progress=plain']:
    print('mock build reached; no Docker write performed')
    sys.exit(73)
sys.exit(92)
''')
        self.tool("df", '''import json, os, sys
with open(os.environ['TEST_CALLS'], 'a') as f:
    f.write(json.dumps(['df'] + sys.argv[1:]) + '\\n')
if os.getenv('TEST_DF_FAIL'): sys.exit(7)
print('Avail')
if sys.argv[1:] == ['--output=avail', os.environ['TEST_DOCKER_ROOT']]:
    print(os.environ['TEST_DOCKER_KIB'])
else:
    print(1024 * 1024)  # The source/tmp filesystem is intentionally too small.
''')

    def tool(self, name, body):
        path = self.bin / name
        path.write_text('#!' + sys.executable + '\n' + body)
        path.chmod(0o700)

    def run_guard(self, expected, **overrides):
        env = dict(os.environ)
        env.update(PATH=str(self.bin) + os.pathsep + env['PATH'],
                   ARTIFACT_DIR=str(self.directory / 'artifacts'), TMPDIR=str(self.tmp),
                   TEST_CALLS=str(self.calls), TEST_DOCKER_ROOT=str(self.docker_root),
                   TEST_DOCKER_KIB=str(50 * 1024 * 1024), NATIVE_POLICY_SKIP_BUILD='0',
                   CONSTELLATION_NATIVE_POLICY_IMAGE='constellation/native-policy-test:fixture')
        env.update(overrides)
        result = subprocess.run(['bash', 'scripts/test-native-policy.sh'], cwd=self.repo,
                                env=env, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def test_adequate_docker_storage_reaches_build_despite_small_source_tmp(self):
        calls = self.run_guard(73)
        self.assertIn(['df', '--output=avail', str(self.docker_root)], calls)
        self.assertTrue(any(c[0] == 'docker' and 'build' in c for c in calls))
        self.assertIn('no Docker write performed', (self.directory / 'artifacts/build.log').read_text())

    def test_insufficient_docker_storage_refuses_before_build(self):
        calls = self.run_guard(1, TEST_DOCKER_KIB=str(40 * 1024 * 1024 - 1))
        self.assertFalse(any('build' in c for c in calls))

    def test_info_failure_refuses_before_df_or_build(self):
        calls = self.run_guard(9, TEST_INFO_FAIL='1')
        self.assertEqual(len(calls), 1)

    def test_df_failure_refuses_before_build(self):
        calls = self.run_guard(7, TEST_DF_FAIL='1')
        self.assertFalse(any('build' in c for c in calls))

    def test_missing_docker_root_refuses_before_df_or_build(self):
        calls = self.run_guard(1, TEST_DOCKER_ROOT=str(self.directory / 'absent'))
        self.assertEqual(len(calls), 1)

    def test_empty_docker_root_refuses_before_df_or_build(self):
        calls = self.run_guard(1, TEST_DOCKER_ROOT='')
        self.assertEqual(len(calls), 1)

    def test_malformed_df_output_refuses_before_build(self):
        calls = self.run_guard(1, TEST_DOCKER_KIB='unavailable')
        self.assertFalse(any('build' in c for c in calls))


if __name__ == '__main__':
    unittest.main()
