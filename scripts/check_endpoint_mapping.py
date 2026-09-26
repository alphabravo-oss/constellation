#!/usr/bin/env python3
"""Check the NeuVector endpoint map against OpenAPI and the registered router.

Run from anywhere: python3 scripts/check_endpoint_mapping.py
The router check uses the existing Go OpenAPI tests and needs a working Go toolchain.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
MAPPING = Path("docs/NEUVECTOR-ENDPOINT-MAPPING-2026-08.md")
OPENAPI = Path("internal/handler/openapi.json")
ROUTE_TESTS = "^(TestGenerateOpenAPI|TestOpenAPICompleteness)$"
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
CODE_SPAN = re.compile(r"`([^`\n]+)`")
API_REFERENCE = re.compile(r"^(?:(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+)?(/api/v1/\S+)$")
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def references(document):
    """Return explicit API references, and reject map rows with no target path."""
    found = []
    errors = []
    in_map = False
    rows = 0
    for line_number, line in enumerate(document.splitlines(), 1):
        if line == "## Primary Endpoint Map":
            in_map = True
            continue
        if in_map and line.startswith("## "):
            in_map = False
        map_row = in_map and line.startswith("|") and not line.startswith("| ---")
        if map_row:
            columns = [column.strip() for column in line.strip().strip("|").split("|")]
            if len(columns) != 5:
                errors.append(f"{MAPPING}:{line_number}: malformed endpoint map row")
                continue
            if columns[0] == "NeuVector family":
                continue
            rows += 1
            source = columns[2]
        else:
            source = line
        line_refs = []
        for code in CODE_SPAN.findall(source):
            match = API_REFERENCE.fullmatch(code)
            if match:
                method, path = match.groups()
                line_refs.append((line_number, method, path.split("?", 1)[0]))
        found.extend(line_refs)
        if map_row and not line_refs:
            errors.append(f"{MAPPING}:{line_number}: endpoint map row has no explicit API path")
    if rows == 0:
        errors.append(f"{MAPPING}: no endpoint map rows found")
    return found, errors


def path_pattern(reference):
    parts = re.split(r"(\{[^{}]+\}|\*)", reference)
    expression = "".join("[^/]+" if part.startswith("{") else ".*" if part == "*" else re.escape(part)
                         for part in parts)
    return re.compile(f"^{expression}$")


def check_endpoints(document, paths):
    refs, errors = references(document)
    for line_number, method, path in refs:
        pattern = path_pattern(path)
        matches = [route for route in paths if pattern.fullmatch(route)]
        label = f"{method} {path}" if method else path
        if not matches:
            errors.append(f"{MAPPING}:{line_number}: {label} has no OpenAPI path")
        elif method and not any(method.lower() in paths[route] for route in matches):
            errors.append(f"{MAPPING}:{line_number}: {label} has no OpenAPI operation")
    return len(refs), errors


def check_links(document, root):
    errors = []
    count = 0
    for line_number, line in enumerate(document.splitlines(), 1):
        for target in MARKDOWN_LINK.findall(line):
            target = target.split(' "', 1)[0].strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc:
                continue
            count += 1
            if not parsed.path:
                destination = root / MAPPING
            else:
                destination = root / MAPPING.parent / unquote(parsed.path)
            if not destination.is_file():
                errors.append(f"{MAPPING}:{line_number}: broken local link {target}")
            elif parsed.fragment and not heading_exists(destination, unquote(parsed.fragment)):
                errors.append(f"{MAPPING}:{line_number}: broken local anchor {target}")
    return count, errors


def heading_exists(destination, anchor):
    seen = {}
    for line in destination.read_text(encoding="utf-8").splitlines():
        heading = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", line)
        if not heading:
            continue
        name = re.sub(r"[^\w\- ]", "", heading.group(1).lower()).replace(" ", "-")
        count = seen.get(name, 0)
        seen[name] = count + 1
        if anchor == (f"{name}-{count}" if count else name):
            return True
    return False


def check_routes(root):
    command = ["go", "test", "./internal/server", "-run", ROUTE_TESTS, "-count=1"]
    try:
        result = subprocess.run(command, cwd=root, capture_output=True, text=True,
                                env={**os.environ, "GOWORK": "off"}, check=False)
    except OSError as error:
        return [f"router/OpenAPI check could not start: {error}"]
    if result.returncode:
        details = (result.stdout + result.stderr).strip()
        return [f"router/OpenAPI check failed (exit {result.returncode}):\n{details}"]
    return []


def check_repository(root):
    document = (root / MAPPING).read_text(encoding="utf-8")
    spec = json.loads((root / OPENAPI).read_text(encoding="utf-8"))
    paths = spec["paths"]
    reference_count, endpoint_errors = check_endpoints(document, paths)
    link_count, link_errors = check_links(document, root)
    route_errors = check_routes(root)
    return reference_count, link_count, endpoint_errors + link_errors + route_errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT,
                        help="repository root (default: parent of scripts)")
    args = parser.parse_args()
    try:
        references_checked, links_checked, errors = check_repository(args.repo_root.resolve())
    except (OSError, ValueError, KeyError) as error:
        print(f"endpoint mapping check could not read inputs: {error}", file=sys.stderr)
        return 1
    for error in errors:
        print(error, file=sys.stderr)
    print(f"Endpoint mapping: {references_checked} API references, {links_checked} local links; "
          f"{'FAILED' if errors else 'PASS'}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
