"""Render the durable PCAP claim contract without cluster credentials or writes."""
import pathlib
import subprocess
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy/charts/constellation"


class PcapStorageChartTests(unittest.TestCase):
    def render(self, *values, string_values=(), fails=False):
        command = ["helm", "template", "pcap-proof", str(CHART)]
        for value in values:
            command.extend(["--set", value])
        for value in string_values:
            command.extend(["--set-string", value])
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        if fails:
            self.assertNotEqual(result.returncode, 0, result.stdout)
            return result.stderr
        self.assertEqual(result.returncode, 0, result.stderr)
        resources = list(yaml.safe_load_all(result.stdout))
        return next(row for row in resources if row and row.get("kind") == "Deployment"
                    and row["metadata"]["name"] == "pcap-proof-constellation-api")

    def pod(self, deployment):
        return deployment["spec"]["template"]["spec"]

    def test_disabled_preserves_existing_environment_without_durability_claim(self):
        pod = self.pod(self.render())
        api = pod["containers"][0]
        self.assertNotIn("pcap-evidence", [v["name"] for v in pod["volumes"]])
        self.assertNotIn("CONSTELLATION_DATA_DIR", [e["name"] for e in api["env"]])
        self.assertTrue(api["securityContext"]["readOnlyRootFilesystem"])

    def test_single_replica_rwo_recreates_with_private_writable_pvc_only(self):
        deployment = self.render("api.replicas=1", "api.pcapStorage.enabled=true",
                                 "api.pcapStorage.existingClaim=owned-pcap")
        self.assertEqual(deployment["spec"]["strategy"], {"type": "Recreate"})
        pod = self.pod(deployment)
        api = pod["containers"][0]
        self.assertEqual(next(v for v in pod["volumes"] if v["name"] == "pcap-evidence"),
                         {"name": "pcap-evidence", "persistentVolumeClaim": {"claimName": "owned-pcap"}})
        self.assertIn({"name": "pcap-evidence", "mountPath": "/var/lib/constellation-pcap"},
                      api["volumeMounts"])
        self.assertIn({"name": "CONSTELLATION_DATA_DIR", "value": "/var/lib/constellation-pcap"}, api["env"])
        self.assertTrue(api["securityContext"]["readOnlyRootFilesystem"])
        self.assertTrue(api["securityContext"]["runAsNonRoot"])
        self.assertEqual(api["securityContext"]["runAsUser"], 10001)
        self.assertEqual(pod["securityContext"]["fsGroup"], 10001)

    def test_multi_replica_rwx_keeps_default_rolling_strategy(self):
        deployment = self.render("api.replicas=2", "api.pcapStorage.enabled=true",
                                 "api.pcapStorage.existingClaim=shared-pcap",
                                 "api.pcapStorage.accessMode=ReadWriteMany")
        self.assertNotIn("strategy", deployment["spec"])
        self.assertEqual(deployment["spec"]["replicas"], 2)

    def test_missing_claim_and_multiple_rwo_replicas_fail(self):
        self.assertIn("existing durable PVC", self.render("api.pcapStorage.enabled=true", fails=True))
        for replicas in (0, 2, 3):
            with self.subTest(replicas=replicas):
                failure = self.render("api.pcapStorage.enabled=true",
                                      "api.pcapStorage.existingClaim=owned-pcap",
                                      f"api.replicas={replicas}", fails=True)
                self.assertIn("replica", failure.lower())

    def test_conflicting_path_override_fails_and_matching_override_is_unique(self):
        values = ("api.replicas=1", "api.pcapStorage.enabled=true",
                  "api.pcapStorage.existingClaim=owned-pcap")
        self.assertIn("conflicts", self.render(*values, "api.env.CONSTELLATION_DATA_DIR=/tmp", fails=True))
        pod = self.pod(self.render(*values, "api.env.CONSTELLATION_DATA_DIR=/var/lib/constellation-pcap"))
        self.assertEqual(sum(e["name"] == "CONSTELLATION_DATA_DIR" for e in pod["containers"][0]["env"]), 1)

    def test_invalid_modes_names_and_boolean_strings_are_rejected(self):
        for field in ("api.pcapStorage.accessMode=ReadOnlyMany",
                      "api.pcapStorage.existingClaim=../foreign"):
            with self.subTest(field=field):
                self.assertIn("pcapStorage", self.render(field, fails=True))
        self.assertIn("boolean", self.render(string_values=("api.pcapStorage.enabled=true",), fails=True))


if __name__ == "__main__":
    unittest.main()
