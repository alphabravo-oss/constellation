"""Run packet-evidence verifier contracts in the regular tooling gate."""
import importlib.util
from pathlib import Path


def load_tests(loader, _tests, _pattern):
    path = Path(__file__).resolve().parents[2] / "tests/flannel-policy/verify_evidence.py"
    spec = importlib.util.spec_from_file_location("flannel_evidence_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return loader.loadTestsFromModule(module)
