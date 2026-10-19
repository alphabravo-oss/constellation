"""Release identity and digest-pin checks, without registry mutations."""
import importlib.util
import json
import pathlib
import subprocess
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("publisher", ROOT / "scripts/publish-dev-images.py")
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64


class ReleaseIdentityTests(unittest.TestCase):
    def test_status_digits_in_reference_are_not_authorization_errors(self):
        for fragment in ["401", "403", "404"]:
            ref = "example.com/team/api:dev-a" + fragment + "b" * 60
            result = subprocess.CompletedProcess([], 1, "", "ERROR: " + ref + ": not found")
            with patch.object(publisher.subprocess, "run", return_value=result):
                self.assertIsNone(publisher.remote_digest(ref))
            result.stderr = "ERROR: " + ref + ": connection timed out"
            with patch.object(publisher.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(RuntimeError, "inspection failed"):
                    publisher.remote_digest(ref)

    def image(self):
        return {"name": "api", "role": "api", "source": "local/api:tested",
                "repository": "example.com/team/api", "tag": "dev-" + "a" * 64, "digest": DIGEST}

    @patch.object(publisher, "local_digest", return_value=DIGEST)
    def test_plan_requires_reviewed_source_identity(self, _local):
        plan = {"registry": "example.com/team", "images": [{"name": "api", "role": "api",
                "source": "local/api:tested", "expected_digest": OTHER}]}
        with self.assertRaisesRegex(ValueError, "Local source changed"):
            publisher.prepare(plan)
        plan["images"][0]["expected_digest"] = DIGEST
        self.assertEqual(publisher.prepare(plan)[0]["digest"], DIGEST)
        plan["images"].append(plan["images"][0].copy())
        with self.assertRaises(ValueError):
            publisher.prepare(plan)

    @patch.object(publisher, "command")
    @patch.object(publisher, "local_digest", return_value=DIGEST)
    def test_collision_never_pushes(self, _local, command):
        with patch.object(publisher, "remote_digest", return_value=OTHER):
            with self.assertRaisesRegex(ValueError, "overwrite"):
                publisher.publish([self.image()])
        command.assert_not_called()

    @patch.object(publisher, "command")
    @patch.object(publisher, "local_digest", return_value=DIGEST)
    def test_remote_graph_mismatch_never_returns_values(self, _local, command):
        with patch.object(publisher, "remote_digest", side_effect=[None, OTHER]):
            with self.assertRaisesRegex(ValueError, "differs"):
                publisher.publish([self.image()])
        self.assertEqual(command.call_args_list[-1].args[:2], ("docker", "push"))

    @patch.object(publisher, "command")
    @patch.object(publisher, "local_digest", return_value=DIGEST)
    def test_idempotent_verification_and_digest_resolution(self, _local, command):
        with patch.object(publisher, "remote_digest", return_value=DIGEST) as remote:
            values = publisher.publish([self.image()])
        command.assert_not_called()
        self.assertEqual(values["api"]["image"]["digest"], DIGEST)
        self.assertEqual(remote.call_args.args[0], "example.com/team/api@" + DIGEST)

    def test_auth_error_is_not_missing_tag(self):
        for error in ["403 forbidden", "401 unauthorized", "denied: not found"]:
            result = subprocess.CompletedProcess([], 1, "", error)
            with patch.object(publisher.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(RuntimeError, "authorization"):
                    publisher.remote_digest("example.com/team/api:dev")


class HelmImageDigestTests(unittest.TestCase):
    def test_cnpg_receives_private_image_credentials(self):
        result = self.render("postgres.embedded=false", "postgres.cloudnativepg.enabled=true",
                             "image.pullSecrets[0].name=registry-reader")
        self.assertEqual(result.returncode, 0, result.stderr)
        cluster = next(doc for doc in result.stdout.split("---") if "kind: Cluster\n" in doc)
        self.assertIn("  imagePullSecrets:\n    - name: registry-reader", cluster)
        public = self.render("postgres.embedded=false", "postgres.cloudnativepg.enabled=true")
        self.assertEqual(public.returncode, 0, public.stderr)
        cluster = next(doc for doc in public.stdout.split("---") if "kind: Cluster\n" in doc)
        self.assertNotIn("imagePullSecrets:", cluster)

    def render(self, *values):
        args = ["helm", "template", "release", str(ROOT / "deploy/charts/constellation")]
        for value in values:
            args.extend(["--set", value])
        return subprocess.run(args, capture_output=True, text=True, check=False)

    def test_digest_overrides_tag_for_deployment_and_init(self):
        result = self.render("api.image.repository=example.com/team/api", "api.image.tag=mutable",
                             "api.image.digest=" + DIGEST, "image.tag=global")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("image: example.com/team/api@" + DIGEST), 2)
        self.assertNotIn("example.com/team/api:mutable", result.stdout)
        self.assertIn("/scanner:global", result.stdout)

    def test_jobs_and_daemonset_use_their_own_digest(self):
        result = self.render("runtimeAgent.enabled=true", "runtimeAgent.image.digest=" + DIGEST,
                             "migrate.image.digest=" + OTHER)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("/runtime-agent@" + DIGEST, result.stdout)
        self.assertIn("/migrate@" + OTHER, result.stdout)

    def test_invalid_digest_rejected(self):
        for digest in ["latest", "sha256:abc", "sha256:" + "A" * 64]:
            result = self.render("api.image.digest=" + digest)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("api.image.digest", result.stderr)


class HelmReleaseReferenceTests(unittest.TestCase):
    """Compare actual chart output with the publishing workflow's image matrix."""
    def render(self, chart, *values):
        args = ['helm', 'template', 'release', str(chart), '--set', 'postgres.mode=cnpg',
                '--set', 'auditArchiver.enabled=true', '--set', 'auditArchiver.bucket=fixture',
                '--set', 'kubeBenchWorker.enabled=true', '--set', 'kubeBenchWorker.state.existingClaim=fixture',
                '--set', 'kubeBenchWorker.image.repository=ghcr.io/alphabravo-oss/constellation/kube-bench-runner']
        for value in values:
            args.extend(['--set', value])
        return subprocess.check_output(args, text=True)

    def release_images(self, rendered):
        import re
        return set(re.findall(r'^\s*(?:image|imageName):\s*["\']?(ghcr.io/alphabravo-oss/constellation/[^\s"\']+)', rendered, re.M))

    def expected(self, version):
        import re
        workflow = (ROOT/'.github/workflows/release.yml').read_text()
        rows = re.findall(r'-\s*\{\s*role:\s*([a-z-]+),\s*dockerfile:\s*[^,}\n]+(?:,\s*tag_prefix:\s*"([^"]+)")?\s*\}', workflow)
        self.assertEqual(len(rows), len(re.findall(r'\brole:', workflow)), 'release matrix format changed; update contract reader')
        self.assertGreater(len(rows), 0)
        return {'ghcr.io/alphabravo-oss/constellation/'+role+':'+prefix+'v'+version for role,prefix in rows}

    def test_every_release_role_renders_the_published_tag(self):
        import re
        chart = ROOT/'deploy/charts/constellation'
        version = re.search(r'^appVersion:\s*"?([^"\s]+)', (chart/'Chart.yaml').read_text(), re.M)[1]
        self.assertEqual(self.release_images(self.render(chart)), self.expected(version))

    def test_version_bump_updates_all_roles_including_cnpg(self):
        import re
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            chart = pathlib.Path(directory)/'chart'
            shutil.copytree(ROOT/'deploy/charts/constellation', chart)
            metadata = chart/'Chart.yaml'
            metadata.write_text(re.sub(r'^appVersion:.*$', 'appVersion: "9.8.7"', metadata.read_text(), flags=re.M))
            self.assertEqual(self.release_images(self.render(chart)), self.expected('9.8.7'))
            metadata.write_text(re.sub(r'^appVersion:.*$', 'appVersion: "v9.8.7"', metadata.read_text(), flags=re.M))
            self.assertEqual(self.release_images(self.render(chart)), self.expected('9.8.7'))

    def test_explicit_app_tag_does_not_select_an_unpublished_database_tag(self):
        chart = ROOT/'deploy/charts/constellation'
        rendered = self.render(chart, 'image.tag=development', 'api.image.tag=canary',
                               'migrate.image.digest='+DIGEST)
        self.assertIn('/scanner:development', rendered)
        self.assertIn('/api:canary', rendered)
        self.assertIn('/migrate@'+DIGEST, rendered)
        expected_postgres = next(ref for ref in self.release_images(self.render(chart)) if '/postgres:' in ref)
        self.assertIn(expected_postgres, rendered)
        custom = 'example.test/postgres:16.14-custom@'+DIGEST
        rendered = self.render(chart, 'postgres.cloudnativepg.imageName='+custom)
        self.assertIn('imageName: '+custom, rendered)

    def test_cnpg_default_registry_matches_application_registry(self):
        chart = ROOT/'deploy/charts/constellation'
        mirrored = self.render(chart, 'image.registry=mirror.example.test/constellation')
        self.assertIn('imageName: mirror.example.test/constellation/postgres:16.14-v', mirrored)
        self.assertIn('image: mirror.example.test/constellation/api:v', mirrored)
        empty = self.render(chart, 'image.registry=')
        self.assertIn('imageName: ghcr.io/alphabravo-oss/constellation/postgres:16.14-v', empty)
        self.assertIn('image: ghcr.io/alphabravo-oss/constellation/api:v', empty)
