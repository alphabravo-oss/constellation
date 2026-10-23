#!/usr/bin/env bash
# H8: policy-controller permissions must reach the deployed operator account.
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chart=deploy/charts/constellation
for scope in cluster namespaced; do
  namespaced=false
  [[ "$scope" != namespaced ]] || namespaced=true
  for name in default custom; do
    extra=()
    [[ "$name" != custom ]] || extra+=(--set fullnameOverride=custom)
    helm template constellation "$chart" --include-crds --namespace policy-system \
      --set operator.enabled=true --set "namespaced=$namespaced" "${extra[@]}" \
      > "$work/$scope-$name.yaml"
  done
done
helm template constellation "$chart" --set operator.enabled=false > "$work/disabled.yaml"

python3 - "$work" <<'PY'
import pathlib
import sys
import yaml

root = pathlib.Path(sys.argv[1])
group = 'constellation.alphabravo.io'
resources = ('constellationadmissionrules', 'constellationresponserules')
required = {
    '': {'get', 'list', 'watch', 'update', 'patch'},
    '/status': {'get', 'update', 'patch'},
    '/finalizers': {'update'},
}

def load(name):
    return [d for d in yaml.safe_load_all((root / f'{name}.yaml').read_text()) if d]

def unique(documents, kind, name):
    matches = [d for d in documents if d['kind'] == kind and d['metadata']['name'] == name]
    assert len(matches) == 1, f'expected one {kind}/{name}, found {len(matches)}'
    return matches[0]

for scope in ('cluster', 'namespaced'):
    for naming, fullname in (('default', 'constellation'), ('custom', 'custom')):
        scenario = f'{scope}-{naming}'
        documents = load(scenario)
        name = f'{fullname}-operator'
        deployment = unique(documents, 'Deployment', name)
        pod = deployment['spec']['template']['spec']
        assert pod['serviceAccountName'] == name, f'{scenario}: wrong deployed account'
        account = unique(documents, 'ServiceAccount', name)
        assert account['metadata'].get('namespace', 'policy-system') == 'policy-system'
        assert pod.get('automountServiceAccountToken', True), f'{scenario}: account token disabled'
        assert account.get('automountServiceAccountToken', True), f'{scenario}: account token disabled'
        binding = unique(documents, 'ClusterRoleBinding', name)
        assert binding['roleRef'] == {
            'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': name
        }, f'{scenario}: wrong policy role reference'
        assert binding['subjects'] == [{
            'kind': 'ServiceAccount', 'name': name, 'namespace': 'policy-system'
        }], f'{scenario}: wrong policy binding subject'
        role = unique(documents, 'ClusterRole', name)
        for rule in role['rules']:
            for field in ('apiGroups', 'resources', 'verbs'):
                assert not any('*' in value for value in rule.get(field, [])), \
                    f'{scenario}: wildcard permission in policy role'
        for resource in resources:
            crd = unique(documents, 'CustomResourceDefinition', f'{resource}.{group}')
            assert crd['spec']['group'] == group and crd['spec']['names']['plural'] == resource
            assert crd['spec']['scope'] == 'Cluster', f'{scenario}: policy CR scope changed'
            assert any(v['served'] and 'status' in v.get('subresources', {})
                       for v in crd['spec']['versions']), f'{scenario}: missing status subresource'
            for suffix, verbs in required.items():
                granted = set()
                for rule in role['rules']:
                    if group in rule['apiGroups'] and resource + suffix in rule['resources']:
                        assert not rule.get('resourceNames'), f'{scenario}: policy names restricted'
                        granted.update(rule['verbs'])
                missing = verbs - granted
                assert not missing, f'{scenario}: {resource}{suffix} missing verbs {sorted(missing)}'
        container = next(c for c in pod['containers'] if c['name'] == 'operator')
        env = {e['name']: e for e in container['env']}
        expected_watch = 'policy-system' if scope == 'namespaced' else ''
        assert env['WATCH_NAMESPACE']['value'] == expected_watch, f'{scenario}: wrong watch scope'

assert not any(d['metadata']['name'].startswith('constellation-operator')
               for d in load('disabled')), 'disabled operator still renders resources'
print('operator chart: policy RBAC, account bindings, CRD scope, namespaced/custom and disabled passed')
PY
