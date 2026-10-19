#!/usr/bin/env python3
"""Promote a scanned immutable candidate without rebuilding or overwriting releases."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT/file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

gate = load('image_gate', 'gate-image-release.py')
publisher = load('image_publisher', 'publish-dev-images.py')


def promote(image, tag, report_path, receipt_path):
    identity = gate.image_identity(image)
    repository, digest = image.rsplit('@', 1)
    if not tag.startswith(repository+':') or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', tag[len(repository)+1:]):
        raise ValueError('release tag must belong to the scanned repository')
    raw = report_path.read_bytes()
    receipt = json.loads(receipt_path.read_text())
    if receipt.get('passed') is not True or receipt.get('report_sha256') != hashlib.sha256(raw).hexdigest() or any(receipt.get(k) != v for k, v in identity.items()):
        raise ValueError('passing receipt does not bind this image and report')
    # Recheck the report instead of trusting a boolean or an expired receipt.
    if not gate.evaluate(json.loads(raw), identity)['passed']:
        raise ValueError('image does not pass the current release gate')
    existing = publisher.remote_digest(tag)
    if existing is not None and existing != digest:
        raise ValueError('refusing to overwrite an existing release tag')
    if existing is None:
        gate.checked('docker', 'buildx', 'imagetools', 'create', '--prefer-index=false', '--tag', tag, image)
    if publisher.remote_digest(tag) != digest:
        raise ValueError('promoted release differs from scanned OCI digest')
    return {'image': image, 'release_tag': tag, 'verified': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--report', required=True, type=pathlib.Path)
    parser.add_argument('--receipt', required=True, type=pathlib.Path)
    args = parser.parse_args()
    print(json.dumps(promote(args.image, args.tag, args.report, args.receipt)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, gate.subprocess.CalledProcessError) as exc:
        print('Release promotion failed: '+str(exc), file=sys.stderr)
        sys.exit(1)
