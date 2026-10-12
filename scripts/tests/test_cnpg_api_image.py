import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("cnpg_render_api", ROOT / "deploy/dev/cnpg-rustfs/render_api.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CNPGAPIImageTests(unittest.TestCase):
    def setUp(self):
        self.pod = {"containers": [{"name": "api", "image": "old"}],
                    "initContainers": [{"name": "wait-for-migrations", "image": "old",
                                        "args": ["--check-schema"]}]}
        self.deployment = {"kind": "Deployment", "spec": {"template": {"spec": self.pod}}}
        self.service = {"kind": "Service", "metadata": {"name": "recovery-api"}}

    def test_updates_api_and_gate_for_json_stream_and_list(self):
        entries = [self.deployment, self.service]
        for raw in ("\n".join(json.dumps(item) for item in entries),
                    json.dumps({"kind": "List", "items": entries})):
            with self.subTest(raw=raw):
                result = MODULE.render(raw, "fixture/api@sha256:" + "a" * 64)
                self.assertEqual(result["items"][1], self.service)
                pod = result["items"][0]["spec"]["template"]["spec"]
                self.assertEqual(pod["containers"][0]["image"], pod["initContainers"][0]["image"])
                self.assertTrue(pod["containers"][0]["image"].startswith("fixture/api@sha256:"))

    def test_rejects_missing_wrong_or_duplicate_schema_gate(self):
        for gates in ([], [{"name": "wait-for-migrations", "args": []}],
                      self.pod["initContainers"] * 2):
            deployment = copy.deepcopy(self.deployment)
            deployment["spec"]["template"]["spec"]["initContainers"] = gates
            with self.subTest(gates=gates), self.assertRaises(ValueError):
                MODULE.render(json.dumps(deployment), "fixture/api:test")

    def test_rejects_empty_or_multiple_deployments_and_invalid_images(self):
        for raw in ("", json.dumps(self.service), json.dumps(self.deployment) * 2):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                MODULE.render(raw, "fixture/api:test")
        for image in ("", "fixture/api:test extra"):
            with self.subTest(image=image), self.assertRaises(ValueError):
                MODULE.render(json.dumps(self.deployment), image)


if __name__ == "__main__":
    unittest.main()
