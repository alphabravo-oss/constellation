"""Remove duplicate SARIF stacks emitted by govulncheck, preserving every finding."""

import json
import sys
from pathlib import Path


def normalize(report):
    for run in report.get("runs", []):
        for result in run.get("results", []):
            if "stacks" in result:
                unique = {}
                for stack in result["stacks"]:
                    unique.setdefault(json.dumps(stack, sort_keys=True), stack)
                result["stacks"] = list(unique.values())
    return report


if __name__ == "__main__":
    path = Path(sys.argv[1])
    path.write_text(json.dumps(normalize(json.loads(path.read_text())), indent=2) + "\n")
