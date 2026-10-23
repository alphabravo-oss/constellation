#!/usr/bin/env bash
# Durable audit progress requires signer trust and a bounded catch-up job.
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chart=deploy/charts/constellation
base=(--set auditArchiver.enabled=true --set auditArchiver.bucket=evidence)
helm template constellation "$chart" > "$work/disabled.yaml"
helm template constellation "$chart" "${base[@]}" \
  --set auditArchiver.sign.keySecretName=audit-keys > "$work/static.yaml"
helm template constellation "$chart" "${base[@]}" \
  --set auditArchiver.sign.keyPath=/keys/private \
  --set auditArchiver.sign.verifyKeyPath=/keys/public \
  --set auditArchiver.batchSize=17 --set auditArchiver.endpoint=https://objects.example \
  > "$work/paths.yaml"
helm template constellation "$chart" "${base[@]}" \
  --set auditArchiver.sign.mode=keyless \
  --set auditArchiver.sign.verifyIdentity=archiver@example.com > "$work/keyless.yaml"
for scenario in unsigned unknown missing-key missing-public missing-identity zero huge; do
  extra=()
  case "$scenario" in
    unsigned) extra+=(--set auditArchiver.sign.mode=none) ;;
    unknown) extra+=(--set auditArchiver.sign.mode=typo) ;;
    missing-key) extra+=(--set auditArchiver.sign.verifyKeyPath=/keys/public) ;;
    missing-public) extra+=(--set auditArchiver.sign.keyPath=/keys/private) ;;
    missing-identity) extra+=(--set auditArchiver.sign.mode=keyless) ;;
    zero) extra+=(--set auditArchiver.sign.keySecretName=keys --set auditArchiver.batchSize=0) ;;
    huge) extra+=(--set auditArchiver.sign.keySecretName=keys --set auditArchiver.batchSize=10001) ;;
  esac
  if helm template constellation "$chart" "${base[@]}" "${extra[@]}" > /dev/null 2> "$work/error"; then
    echo "audit archive accepted invalid $scenario configuration" >&2
    exit 1
  fi
  grep -q 'auditArchiver' "$work/error"
done
python3 - "$work" <<'PY'
import pathlib
import sys
import yaml
root = pathlib.Path(sys.argv[1])

def job(name):
    docs = [d for d in yaml.safe_load_all((root / (name + '.yaml')).read_text()) if d]
    jobs = [d for d in docs if d['kind'] == 'CronJob' and d['metadata']['name'].endswith('-audit-archiver')]
    if name == 'disabled':
        assert not jobs
        return None
    assert len(jobs) == 1
    assert jobs[0]['spec']['concurrencyPolicy'] == 'Forbid'
    return jobs[0]['spec']['jobTemplate']['spec']['template']['spec']

job('disabled')
for name in ('static', 'paths', 'keyless'):
    pod = job(name)
    container = next(c for c in pod['containers'] if c['name'] == 'audit-archiver')
    args = dict(a[2:].split('=', 1) for a in container['args'])
    assert 'window' not in args
    assert args['bucket'] == 'evidence'
    if name == 'static':
        assert args['sign-mode'] == 'static-key'
        assert args['sign-key'] == '/etc/constellation/audit-signing/cosign.key'
        assert args['verify-key'] == '/etc/constellation/audit-signing/cosign.pub'
        assert next(v for v in pod['volumes'] if v['name'] == 'audit-signing-key')['secret']['secretName'] == 'audit-keys'
        assert next(v for v in container['volumeMounts'] if v['name'] == 'audit-signing-key')['readOnly']
    elif name == 'paths':
        assert args['sign-key'] == '/keys/private' and args['verify-key'] == '/keys/public'
        assert args['batch-size'] == '17' and args['endpoint'] == 'https://objects.example'
    else:
        assert args['sign-mode'] == 'keyless' and args['verify-identity'] == 'archiver@example.com'
        assert 'sign-key' not in args and 'verify-key' not in args
print('audit archive: 4 rendered configurations and 7 rejected configurations passed')
PY
