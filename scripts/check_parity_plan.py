#!/usr/bin/env python3
"""Verify the parity plan's published checklist totals."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs/NEUVECTOR-PARITY-PLAN.md"


def check_counts(document):
    checked = len(re.findall(r"^- \[x\] ", document, re.MULTILINE))
    open_items = len(re.findall(r"^- \[ \] ", document, re.MULTILINE))
    reported_open = re.search(r"Acceptance backlog: \*\*(\d+) open\*\*", document)
    reported_checked = re.search(r"checklist contains \*\*(\d+) checked", document)
    errors = []
    if reported_open is None or int(reported_open.group(1)) != open_items:
        errors.append(f"open count: reported {reported_open.group(1) if reported_open else 'missing'}, actual {open_items}")
    if reported_checked is None or int(reported_checked.group(1)) != checked:
        errors.append(f"checked count: reported {reported_checked.group(1) if reported_checked else 'missing'}, actual {checked}")
    return checked, open_items, errors


def main():
    checked, open_items, errors = check_counts(PLAN.read_text(encoding="utf-8"))
    for error in errors:
        print(f"{PLAN}: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"parity plan: {checked} checked, {open_items} open")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
