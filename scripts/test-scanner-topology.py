#!/usr/bin/env python3
"""Render cache topology without accessing a cluster or modifying any PVC."""
import pathlib
import subprocess

import yaml

chart = pathlib.Path('deploy/charts/constellation')
count = 0


def render(release='constellation', settings=(), error=None):
    global count
    count += 1
    args = ['helm', 'template', release, str(chart), '--namespace', 'cache-topology-tests']
    for setting in settings:
        args += ['--set', setting]
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if error:
        assert result.returncode != 0 and error in result.stderr, result.stderr
        return []
    assert result.returncode == 0, result.stderr
    return [d for d in yaml.safe_load_all(result.stdout) if d]


def objects(docs, kind):
    return [d for d in docs if d['kind'] == kind and d['metadata'].get('labels', {}).get('app.kubernetes.io/component') == 'scanner']


def scanner(docs):
    return objects(docs, 'Deployment')[0]


def volumes(docs):
    return {v['name']: v for v in scanner(docs)['spec']['template']['spec']['volumes']}


def persistent(docs, claim, managed=True, retained=True):
    deployment = scanner(docs)
    assert deployment['spec']['strategy'] == {'type': 'Recreate'}
    assert volumes(docs)['scanner-cache'] == {'name': 'scanner-cache', 'persistentVolumeClaim': {'claimName': claim}}
    claims = objects(docs, 'PersistentVolumeClaim')
    assert len(claims) == int(managed)
    if managed:
        pvc = claims[0]
        assert pvc['metadata']['name'] == claim
        assert pvc['spec']['accessModes'] == ['ReadWriteOnce']
        assert (pvc['metadata'].get('annotations', {}).get('helm.sh/resource-policy') == 'keep') == retained


base = render()
assert not objects(base, 'PersistentVolumeClaim')
assert volumes(base)['scanner-cache'] == {'name': 'scanner-cache', 'emptyDir': {}}
assert volumes(base)['tmp'] == {'name': 'tmp', 'emptyDir': {}}
assert 'strategy' not in scanner(base)['spec']
container = scanner(base)['spec']['template']['spec']['containers'][0]
env = {e['name']: e.get('value') for e in container['env']}
assert env['CONSTELLATION_SCANNER_OFFLINE_DB'] == 'true'
for key in ('XDG_CACHE_HOME', 'SYFT_CACHE_DIR', 'GRYPE_DB_CACHE_DIR', 'TRIVY_CACHE_DIR', 'TUF_ROOT'):
    assert env[key].startswith('/var/lib/scanner-cache/')
assert next(m for m in container['volumeMounts'] if m['name'] == 'scanner-cache')['mountPath'] == '/var/lib/scanner-cache'

settings = ('scanner.cache.persistent=true', 'scanner.replicas=1')
persistent(render(settings=settings), 'constellation-scanner-cache')
persistent(render('other', settings), 'other-constellation-scanner-cache')
persistent(render('other', settings + ('scanner.cache.managedClaimName=constellation-scanner-cache',)), 'constellation-scanner-cache')
persistent(render(settings=settings + ('scanner.cache.existingClaim=operator-cache',)), 'operator-cache', managed=False)
persistent(render(settings=settings + ('scanner.cache.existingClaim=operator.cache',)), 'operator.cache', managed=False)
persistent(render(settings=settings + ('scanner.cache.retain=false',)), 'constellation-scanner-cache', retained=False)
custom = render(settings=settings + ('scanner.cache.size=16Gi', 'scanner.cache.storageClass=fast'))
persistent(custom, 'constellation-scanner-cache')
claim = objects(custom, 'PersistentVolumeClaim')[0]
assert claim['spec']['resources']['requests']['storage'] == '16Gi'
assert claim['spec']['storageClassName'] == 'fast'
override = render(settings=settings + ('fullnameOverride=security-suite',))
persistent(override, 'security-suite-scanner-cache')

for extra in (('scanner.enabled=false',), ('scanner.enabled=false', 'scanner.cache.persistent=true', 'scanner.replicas=1'), ('scanner.enabled=false', 'scanner.cache.persistent=true', 'scanner.autoscaling.enabled=true')):
    docs = render(settings=extra)
    assert not objects(docs, 'Deployment') and not objects(docs, 'PersistentVolumeClaim') and not objects(docs, 'Service')

limited = render(settings=('scanner.cache.emptyDirSizeLimit=12Gi', 'scanner.tmp.sizeLimit=8Gi'))
assert volumes(limited)['scanner-cache']['emptyDir'] == {'sizeLimit': '12Gi'}
assert volumes(limited)['tmp']['emptyDir'] == {'sizeLimit': '8Gi'}
persistent_tmp = render(settings=settings + ('scanner.tmp.sizeLimit=4Gi',))
persistent(persistent_tmp, 'constellation-scanner-cache')
assert volumes(persistent_tmp)['tmp']['emptyDir'] == {'sizeLimit': '4Gi'}
autoscaled = render(settings=('scanner.autoscaling.enabled=true',))
assert not objects(autoscaled, 'PersistentVolumeClaim')
assert len(objects(autoscaled, 'HorizontalPodAutoscaler')) == 1
assert 'replicas' not in scanner(autoscaled)['spec']
assert 'emptyDir' in volumes(autoscaled)['scanner-cache']

for settings, error in [
    (('scanner.cache.persistent=true',), 'scanner.replicas=1'),
    (('scanner.cache.persistent=true', 'scanner.replicas=0'), '/scanner/replicas'),
    (('scanner.cache.persistent=true', 'scanner.replicas=-1'), '/scanner/replicas'),
    (('scanner.cache.persistent=true', 'scanner.replicas=1.5'), '/scanner/replicas'),
    (('scanner.cache.persistent=true', 'scanner.replicas=1', 'scanner.autoscaling.enabled=true'), 'scanner.autoscaling.enabled=false'),
    (('scanner.cache.persistent=true', 'scanner.replicas=1', 'scanner.cache.emptyDirSizeLimit=12Gi'), 'emptyDirSizeLimit requires'),
    (('scanner.cache.existingClaim=operator-cache',), 'claim names require'),
    (('scanner.cache.managedClaimName=legacy-cache',), 'claim names require'),
    (('scanner.cache.persistent=true', 'scanner.replicas=1', 'scanner.cache.managedClaimName=managed', 'scanner.cache.existingClaim=external'), 'mutually exclusive'),
    (('scanner.cache.emptyDirSizeLimit=0Gi',), '/scanner/cache/emptyDirSizeLimit'),
    (('scanner.tmp.sizeLimit=-1Gi',), '/scanner/tmp/sizeLimit'),
    (('scanner.cache.existingClaim=invalid/name',), '/scanner/cache/existingClaim'),
]:
    render(settings=settings, error=error)

# Service routing is narrowed with a pod label; the Deployment selector remains
# unchanged so existing Deployments do not require an immutable-selector replacement.
left, right = render('left'), render('right')
for docs, other, release in ((left, right, 'left'), (right, left, 'right')):
    deployment = scanner(docs)
    selector = objects(docs, 'Service')[0]['spec']['selector']
    pod_labels = deployment['spec']['template']['metadata']['labels']
    assert selector['app.kubernetes.io/instance'] == release
    assert all(pod_labels[k] == v for k, v in selector.items())
    assert not all(scanner(other)['spec']['template']['metadata']['labels'].get(k) == v for k, v in selector.items())
    assert deployment['spec']['selector']['matchLabels'] == {
        'app.kubernetes.io/name': 'constellation', 'app.kubernetes.io/component': 'scanner'}
print(f'scanner topology: {count} renders validate explicit persistence, lifecycle, limits and release routing')
