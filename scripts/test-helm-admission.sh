#!/usr/bin/env bash
# Admission DSNs must resolve to the configured database Secret or explicit value.
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chart=deploy/charts/constellation
cluster_id=11111111-1111-4111-8111-111111111111
common=(--set admission.enabled=true --set admission.quarantine.enabled=true
  --set "admission.quarantine.clusterId=$cluster_id"
  --set admission.policies.enabled=true --set admission.audit.enabled=true)
render() {
  local name="$1"
  shift
  helm template constellation "$chart" "${common[@]}" "$@" > "$work/$name.yaml"
}
render cnpg --set postgres.cloudnativepg.password=fixture-password
render renamed --set fullnameOverride=custom --set postgres.cloudnativepg.password=fixture-password
render external --set postgres.mode=external --set postgres.dsn=postgres://fixture:password@db.example/test
render existing --set postgres.mode=external --set postgres.existingSecret=customer-database
render custom-key --set postgres.mode=external --set postgres.existingSecret=customer-database \
  --set postgres.existingSecretKey=connection
render overrides --set postgres.mode=external --set postgres.existingSecret=customer-database \
  --set admission.quarantine.dsn=postgres://quarantine:password@db.example/quarantine \
  --set admission.policies.dsn=postgres://policies:password@db.example/policies \
  --set admission.audit.dsn=postgres://audit:password@db.example/audit
helm template constellation "$chart" --set admission.enabled=true > "$work/disabled.yaml"

python3 - "$work" "$cluster_id" <<'PY'
import pathlib
import sys
import yaml

root, cluster_id = pathlib.Path(sys.argv[1]), sys.argv[2]
dsn_names = {
    'quarantine': 'CONSTELLATION_QUARANTINE_DSN',
    'policies': 'CONSTELLATION_ADMISSION_POLICY_DSN',
    'audit': 'CONSTELLATION_ADMISSION_AUDIT_DSN',
}

def load(name):
    documents = [d for d in yaml.safe_load_all((root / f'{name}.yaml').read_text()) if d]
    deployments = [d for d in documents if d['kind'] == 'Deployment'
                   and d['metadata']['labels'].get('app.kubernetes.io/component') == 'admission']
    assert len(deployments) == 1, f'{name}: missing or duplicate admission deployment'
    container = next(c for c in deployments[0]['spec']['template']['spec']['containers']
                     if c['name'] == 'admission')
    env = {e['name']: e for e in container['env']}
    assert len(env) == len(container['env']), f'{name}: duplicate environment variables'
    secrets = {d['metadata']['name']: d for d in documents if d['kind'] == 'Secret'}
    return env, container['args'], secrets

for name, secret, key, expected_dsn in [
    ('cnpg', 'constellation-database-url', 'url',
     'postgres://constellation:fixture-password@constellation-postgres-rw:5432/constellation?sslmode=disable'),
    ('renamed', 'custom-database-url', 'url',
     'postgres://constellation:fixture-password@custom-postgres-rw:5432/constellation?sslmode=disable'),
    ('external', 'constellation-database-url', 'url', 'postgres://fixture:password@db.example/test'),
    ('existing', 'customer-database', 'url', None),
    ('custom-key', 'customer-database', 'connection', None),
]:
    env, args, secrets = load(name)
    for variable in dsn_names.values():
        assert env[variable] == {
            'name': variable, 'valueFrom': {'secretKeyRef': {'name': secret, 'key': key}}
        }, f'{name}: {variable} must use the required configured Secret/key'
    if expected_dsn is not None:
        assert secrets[secret]['stringData'][key] == expected_dsn, f'{name}: DSN does not resolve'
    else:
        assert secret not in secrets, f'{name}: chart overwrites a customer-owned Secret'
        assert 'constellation-database-url' not in secrets, f'{name}: unexpected generated DSN'
    for flag in ('quarantine-cluster-id', 'policy-cluster-id', 'audit-cluster-id'):
        assert f'--{flag}={cluster_id}' in args, f'{name}: missing cluster scope for {flag}'

env, args, _ = load('overrides')
for feature, variable in dsn_names.items():
    assert env[variable] == {
        'name': variable, 'value': f'postgres://{feature}:password@db.example/{feature}'
    }, f'explicit {feature} DSN did not override the shared database Secret'

env, args, _ = load('disabled')
assert not set(dsn_names.values()) & env.keys(), 'disabled admission features receive database DSNs'
assert not any(a.startswith(('--quarantine-', '--policy-', '--audit-')) for a in args), \
    'disabled admission features receive database flags'
print('admission chart: CNPG, renamed, external, existing/custom-key Secrets, overrides and disabled passed')
PY
