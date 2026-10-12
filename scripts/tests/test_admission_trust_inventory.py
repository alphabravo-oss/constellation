"""Verify certificate matching and secret-safe public-field inventory failures."""
import base64
import importlib.util
import io
import json
import pathlib
import subprocess
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("admission_inventory", ROOT / "scripts/audit-admission-tls-trust.py")
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class AdmissionTrustInventoryTests(unittest.TestCase):
    def test_historical_ca_match_and_chain_count(self):
        pem = (ROOT / "scripts/tests/fixtures/historical-admission-ca.crt").read_bytes()
        value = base64.b64encode(pem + pem).decode()
        report = inventory.audit_records([("secrets:fixture/cert", "ca.crt", value, True)])
        self.assertEqual(report["certificates_checked"], 2)
        self.assertEqual(len(report["historical_certificate_matches"]), 2)
        self.assertEqual(len(report["historical_public_key_matches"]), 2)
        self.assertEqual(report["historical_certificate_matches"][0]["certificate"], "admission-ca")
        self.assertEqual(report["errors"], [])
        self.assertNotIn("BEGIN CERTIFICATE", json.dumps(report))

    def test_known_public_key_matches_without_exact_certificate_match(self):
        pem = (ROOT / "scripts/tests/fixtures/historical-admission-ca.crt").read_text()
        with patch.dict(inventory.HISTORICAL_CERTIFICATES, {}, clear=True):
            report = inventory.audit_records([("configmaps:fixture/ca", "ca.crt", pem, False)])
        self.assertEqual(report["historical_certificate_matches"], [])
        self.assertEqual(len(report["historical_public_key_matches"]), 1)
        self.assertEqual(report["historical_public_key_matches"][0]["key"], "admission-ca")

    def test_cli_exit_status_distinguishes_matches_and_unverified_inventory(self):
        pem = (ROOT / "scripts/tests/fixtures/historical-admission-ca.crt").read_text()
        for records, expected in (([], 0), ([("configmaps:fixture/ca", "ca.crt", pem, False)], 1),
                                  ([("secrets:fixture/invalid", "ca.crt", "invalid!", True)], 2)):
            with self.subTest(expected=expected), patch.object(inventory.sys, "argv", ["audit"]), \
                    patch.object(inventory, "read_records", return_value=records), \
                    patch.object(inventory.sys, "stdout", new_callable=io.StringIO) as output:
                self.assertEqual(inventory.main(), expected)
                self.assertNotIn("BEGIN CERTIFICATE", output.getvalue())
                self.assertEqual(len(json.loads(output.getvalue())["inventories"]), 3)

    def test_unverifiable_fields_fail_without_disclosing_contents(self):
        for value, encoded in (("private-looking-fixture", False), ("not-valid-base64!", True)):
            with self.subTest(encoded=encoded):
                report = inventory.audit_records([("secrets:fixture/cert", "ca.crt", value, encoded)])
                self.assertEqual(len(report["errors"]), 1)
                self.assertNotIn(value, json.dumps(report))
                self.assertEqual(report["historical_certificate_matches"], [])

    def test_multiline_public_field_output_and_omitted_fields(self):
        fields = [json.dumps("public\ncertificate"), '""', '""', '""', '""']
        result = subprocess.CompletedProcess([], 0, "fixture/cert\t" + "\t".join(fields) + "\n", "")
        with patch.object(inventory.subprocess, "run", return_value=result) as run:
            records = inventory.read_records(["kubectl"], "configmaps")
        self.assertEqual(records, [("configmaps:fixture/cert", "ca.crt", "public\ncertificate", False)])
        command = run.call_args.args[0]
        self.assertNotIn("tls.key", " ".join(command))
        self.assertNotIn("private-key", " ".join(command))

    def test_kubectl_error_does_not_reproduce_output(self):
        result = subprocess.CompletedProcess([], 1, "sensitive fixture", "sensitive fixture")
        with patch.object(inventory.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "could not inventory") as caught:
                inventory.read_records(["kubectl"], "secrets")
        self.assertNotIn("sensitive fixture", str(caught.exception))
