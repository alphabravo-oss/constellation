"""Restore module-relative SARIF paths from the same gosec scan's JSON output."""

import json
import sys
from pathlib import Path
from urllib.parse import quote


def rebase(report, source, root):
    # gosec uses each explicit package directory as a SARIF root, flattening
    # cmd/api/main.go and cmd/worker/main.go to the same URI. Both formatters
    # iterate the same issue list; validate that identity before changing paths.
    results = [item for run in report["runs"] for item in run.get("results", [])]
    issues = source["Issues"] or []
    if len(results) != len(issues):
        raise ValueError("gosec JSON/SARIF finding counts differ")
    for result, issue in zip(results, issues, strict=True):
        locations = result["locations"]
        if len(locations) != 1:
            raise ValueError("unexpected gosec location shape")
        location = locations[0]["physicalLocation"]
        if (result["ruleId"] != issue["rule_id"] or
                result["message"]["text"] != issue["details"] or
                location["region"]["startLine"] != int(issue["line"].split("-")[0])):
            raise ValueError("gosec JSON/SARIF finding identity differs")
        relative = Path(issue["file"]).resolve().relative_to(root.resolve())
        location["artifactLocation"]["uri"] = quote(relative.as_posix(), safe="/")
    return report


if __name__ == "__main__":
    sarif, source = map(Path, sys.argv[1:3])
    report = rebase(json.loads(sarif.read_text()), json.loads(source.read_text()), Path.cwd())
    sarif.write_text(json.dumps(report, indent=2) + "\n")
