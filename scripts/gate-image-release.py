#!/usr/bin/env python3
"""Gate a digest-pinned linux/amd64 release image using unsuppressed Grype JSON.

Candidate images may exist in the registry; release tags must only be promoted
following a successful gate. This evaluates known fixes, not exploitability.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
MAX_DB_AGE = dt.timedelta(days=5)


def checked(*args):
    return subprocess.check_output(args, text=True)


def image_identity(image):
    repository, sep, digest = image.rpartition('@')
    if not sep or not repository or repository.startswith('-') or not DIGEST.fullmatch(digest):
        raise ValueError('release image must be a repository@sha256 digest')
    root = json.loads(checked('docker', 'buildx', 'imagetools', 'inspect', '--raw', image))
    runtime_digest = digest
    if 'manifests' in root:
        runtimes = [m for m in root['manifests']
                    if m.get('annotations', {}).get('vnd.docker.reference.type') != 'attestation-manifest']
        if len(runtimes) != 1 or runtimes[0].get('platform', {}).get('os') != 'linux' or runtimes[0].get('platform', {}).get('architecture') != 'amd64':
            raise ValueError('gate currently requires exactly one linux/amd64 runtime; other platforms need separate scans')
        runtime_digest = runtimes[0]['digest']
        if not DIGEST.fullmatch(runtime_digest):
            raise ValueError('invalid runtime manifest digest')
        root = json.loads(checked('docker', 'buildx', 'imagetools', 'inspect', '--raw', repository+'@'+runtime_digest))
    config = root['config']['digest']
    if not DIGEST.fullmatch(config):
        raise ValueError('invalid image configuration digest')
    return {'image': image, 'runtime_manifest': runtime_digest, 'configuration': config}


def evaluate(report, identity, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    source = report['source']
    if source['type'] != 'image' or source['target']['userInput'] != identity['image'] or source['target']['imageID'] != identity['configuration']:
        raise ValueError('scan report does not match the selected immutable image')
    if source['target']['os'] != 'linux' or source['target']['architecture'] != 'amd64':
        raise ValueError('report must cover linux/amd64')
    configuration = report['descriptor']['configuration']
    for option in ['exclude', 'only-fixed', 'only-notfixed', 'ignore-wontfix', 'vex-documents', 'vex-add', 'distro']:
        if configuration.get(option):
            raise ValueError('filtered scan configuration is not permitted: '+option)
    if configuration['search']['scope'] != 'squashed':
        raise ValueError('report must scan the final filesystem')
    if report.get('ignoredMatches'):
        raise ValueError('suppressed findings are not permitted in release evidence')
    descriptor = report['descriptor']
    if descriptor['name'] != 'grype':
        raise ValueError('unsupported vulnerability report')
    database = descriptor['db']['status']
    if database['valid'] is not True:
        raise ValueError('invalid vulnerability database')
    built = dt.datetime.fromisoformat(database['built'].replace('Z', '+00:00'))
    if built.tzinfo is None or now-built > MAX_DB_AGE or built-now > dt.timedelta(minutes=5):
        raise ValueError('vulnerability database is stale or has an invalid build time')
    if not database.get('from'):
        raise ValueError('database provenance is missing')
    matches = report['matches']
    if not isinstance(matches, list):
        raise ValueError('matches must be an explicit list, including for clean scans')
    blockers = []
    counts = {}
    for match in matches:
        vulnerability, artifact = match['vulnerability'], match['artifact']
        severity = vulnerability['severity'].lower()
        if severity not in {'unknown', 'negligible', 'low', 'medium', 'high', 'critical'}:
            raise ValueError('unrecognized severity')
        fix = vulnerability['fix']
        versions = fix['versions']
        if not isinstance(versions, list) or any(not isinstance(v, str) or not v for v in versions):
            raise ValueError('invalid fix versions')
        if fix.get('state') == 'fixed' and not versions:
            raise ValueError('fixed finding is missing its fixed version')
        counts[severity] = counts.get(severity, 0)+1
        if severity in {'critical', 'high'} and versions:
            blockers.append({'id': vulnerability['id'], 'severity': severity,
                             'package': artifact['name'], 'version': artifact['version'],
                             'fixed_versions': versions})
    return {**identity, 'passed': not blockers, 'policy': 'no-fixable-critical-or-high',
            'scanner_version': descriptor['version'], 'database': database,
            'counts': counts, 'blockers': blockers, 'evaluated_at': now.isoformat()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--report', type=pathlib.Path, required=True)
    parser.add_argument('--receipt', type=pathlib.Path, required=True)
    parser.add_argument('--reuse-report', action='store_true', help='validate an existing report against the registry image')
    args = parser.parse_args()
    # A failed rerun must not leave a previous passing receipt behind.
    args.receipt.unlink(missing_ok=True)
    identity = image_identity(args.image)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    if not args.reuse_report:
        args.report.unlink(missing_ok=True)
        # Ignore user/CI Grype and Syft policy overrides, including ignore rules,
        # package exclusions, VEX suppressions, and stale-database overrides.
        env = {k: v for k, v in os.environ.items() if not k.startswith(('GRYPE_', 'SYFT_'))}
        with tempfile.TemporaryDirectory() as scratch:
            config = pathlib.Path(scratch)/'grype.yaml'
            config.write_text('{}\n')
            subprocess.run(['grype', 'registry:'+args.image, '--platform', 'linux/amd64',
                            '--config', str(config), '--scope', 'squashed', '--output', 'json',
                            '--file', str(args.report)], env=env, check=True)
    raw = args.report.read_bytes()
    receipt = evaluate(json.loads(raw), identity)
    receipt['report_sha256'] = hashlib.sha256(raw).hexdigest()
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps({'passed': receipt['passed'], 'counts': receipt['counts'], 'blockers': len(receipt['blockers'])}))
    return 0 if receipt['passed'] else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as exc:
        print('Release image gate failed: '+str(exc), file=sys.stderr)
        sys.exit(1)
