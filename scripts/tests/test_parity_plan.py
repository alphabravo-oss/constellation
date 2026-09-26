"""Run: python3 -B -m unittest discover -s scripts/tests -p test_parity_plan.py"""

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("check_parity_plan", ROOT / "scripts/check_parity_plan.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class ParityPlanCountTests(unittest.TestCase):
    def test_current_plan_matches_reported_counts(self):
        _, _, errors = checker.check_counts(checker.PLAN.read_text(encoding="utf-8"))
        self.assertEqual(errors, [])

    def test_stale_counts_are_rejected(self):
        document = "Acceptance backlog: **2 open**. The checklist contains **1 checked rows**.\n- [x] done\n- [ ] open\n"
        checked, open_items, errors = checker.check_counts(document)
        self.assertEqual((checked, open_items), (1, 1))
        self.assertEqual(len(errors), 1)
        self.assertIn("open count", errors[0])

    def test_missing_counts_are_rejected(self):
        _, _, errors = checker.check_counts("- [x] done\n- [ ] open\n")
        self.assertEqual(len(errors), 2)


if __name__ == "__main__":
    unittest.main()
