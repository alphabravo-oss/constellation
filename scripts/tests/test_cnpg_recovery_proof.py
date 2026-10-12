"""Recovery assertions must reject missing credentials and broken audit evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("cnpg_proof", ROOT / "deploy/dev/cnpg-rustfs/check_api.py")
proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proof)


class RecoveryProofTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.anchor = {"id": 7, "chain_hash": "public-chain-hash", "target_id": "registry-fixture"}
        self.bad_credentials = False
        self.broken_audit = False
        self.missing_anchor = False
        self.missing_receipt = False
        self.wrong_error = False
        proof.check("prepare", self.root, None)
        proof.check("source", self.root, self.request)

    def request(self, path, token=None, data=None, expected=200):
        if path == "/auth/login":
            return {"token": "synthetic-session-fixture"}
        if path == "/auth/me":
            return {"user_id": "fixture-user"}
        if path == "/system/config":
            return {"revision": 3}
        if path == "/registries":
            self.credentials = data["credentials"]
            self.assertEqual(expected, 201)
            self.assertEqual(data["scan_cadence"], "manual")
            return {"id": "registry-fixture"}
        if path.startswith("/scanner/registry-credentials?"):
            self.assertEqual(token, proof.read(self.root, "scanner-token.json"))
            if expected == 500:
                return {"error": "database unavailable" if self.wrong_error else "decrypt credentials: fixture rejection"}
            return {"registry_id": "registry-fixture", **({} if self.bad_credentials else self.credentials)}
        if path == "/audit/verify":
            return {"status": "broken" if self.broken_audit else "verified", "events": 7}
        if path.startswith("/audit/events?event_id="):
            return {"events": [] if self.missing_anchor else [self.anchor]}
        if path.startswith("/audit/events?action="):
            return {"events": [] if self.missing_receipt else [self.anchor]}
        if path == "/audit/events?limit=1":
            return {"events": [self.anchor]}
        self.fail("Unexpected recovery request")

    def test_source_restore_and_wrong_key_checks_keep_material_private(self):
        proof.check("restored", self.root, self.request)
        proof.check("wrong-key", self.root, self.request)
        for path in self.root.iterdir():
            if path.suffix == ".json":
                self.assertEqual(path.stat().st_mode & 0o077, 0)
        raw = proof.read(self.root, "scanner-token.json")
        self.assertNotIn(raw, (self.root / "scanner.sql").read_text())

    def test_restore_rejects_lost_or_incorrect_credential(self):
        self.bad_credentials = True
        with self.assertRaisesRegex(RuntimeError, "did not decrypt"):
            proof.check("restored", self.root, self.request)

    def test_restore_rejects_broken_chain_or_missing_original_anchor(self):
        for field in ("broken_audit", "missing_anchor", "missing_receipt"):
            with self.subTest(field=field):
                setattr(self, field, True)
                with self.assertRaises(RuntimeError):
                    proof.check("restored", self.root, self.request)
                setattr(self, field, False)

    def test_wrong_key_check_rejects_unrelated_server_failure(self):
        self.wrong_error = True
        with self.assertRaisesRegex(RuntimeError, "not decryption rejection"):
            proof.check("wrong-key", self.root, self.request)

    def test_invalid_mode_does_not_silently_pass(self):
        with self.assertRaisesRegex(RuntimeError, "Expected prepare"):
            proof.check("unknown", self.root, self.request)
