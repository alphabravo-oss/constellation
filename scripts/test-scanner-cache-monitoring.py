#!/usr/bin/env python3
"""Validate real chart wiring and generate executable scanner-cache alert cases."""
import copy
import json
import pathlib
import sys

import yaml

root = pathlib.Path(sys.argv[1])


def docs(name):
    return [d for d in yaml.safe_load_all((root / (name + '.yaml')).read_text()) if d]


def rules(name):
    return [d for d in docs(name) if d['kind'] == 'PrometheusRule' and d['metadata']['name'].endswith('-scanner-cache')]


for name in ('default', 'disabled', 'no-scanner'):
    assert not rules(name)
rule_doc = rules('enabled')[0]
assert len(rules('enabled')) == 1
rule_spec = rule_doc['spec']
alerts = {r['alert']: r for g in rule_spec['groups'] for r in g['rules']}
assert len(alerts) == 8
for rule in alerts.values():
    assert 'namespace="cache-tests"' in rule['expr'] and 'service="constellation-scanner"' in rule['expr']
assert rules('other-namespace')[0]['metadata']['namespace'] == 'monitoring'
assert rules('other-namespace')[0]['spec'] == rule_spec
monitor = next(d for d in docs('enabled') if d['kind'] == 'ServiceMonitor' and d['metadata']['name'].endswith('-scanner'))
assert monitor['spec']['namespaceSelector']['matchNames'] == ['cache-tests']
assert monitor['spec']['endpoints'][0]['path'] == '/metrics'
assert monitor['spec']['endpoints'][0]['port'] == 'http'
service = next(d for d in docs('enabled') if d['kind'] == 'Service' and d['metadata']['name'] == 'constellation-scanner')
assert all(service['metadata']['labels'][k] == v for k, v in monitor['spec']['selector']['matchLabels'].items())
deployment = next(d for d in docs('enabled') if d['kind'] == 'Deployment' and d['metadata']['name'] == 'constellation-scanner')
assert all(deployment['spec']['template']['metadata']['labels'][k] == v for k, v in service['spec']['selector'].items())
assert service['spec']['ports'][0]['name'] == 'http'
(root / 'rules.yaml').write_text(yaml.safe_dump(rule_spec))

labels = {'namespace': 'cache-tests', 'service': 'constellation-scanner', 'job': 'scanner', 'instance': 'scanner-1'}


def series(name, value, extra=None):
    all_labels = dict(labels)
    if name != 'up':
        all_labels['cache'] = 'grype'
        name = 'constellation_scanner_cache_' + name
    all_labels.update(extra or {})
    return {'series': name + '{' + ','.join(k + '=' + json.dumps(v) for k, v in all_labels.items()) + '}',
            'values': str(value) + '+0x60'}


healthy = [series(name, value) for name, value in {
    'up': 1, 'enabled': 1, 'configured': 1, 'collection_success': 1, 'present': 1,
    'capacity_known': 1, 'available_bytes': 4294967296, 'capacity_bytes': 8589934592,
    'inodes_known': 1, 'capacity_inodes': 1000, 'free_inodes': 900,
}.items()]


def case(name, alert, changes=(), firing=False, extra=None, entries=None, at='30m'):
    inputs = copy.deepcopy(healthy if entries is None else entries)
    for replacement in changes:
        inputs = [old for old in inputs if old['series'] != replacement['series']] + [replacement]
    expected = []
    if firing:
        out_labels = dict(labels, severity='warning')
        if alert != 'MetricsUnavailable':
            out_labels['cache'] = 'grype'
        out_labels.update(extra or {})
        expected = [{'exp_labels': out_labels, 'exp_annotations': alerts['ConstellationScannerCache' + alert]['annotations']}]
    return {'name': name, 'interval': '1m', 'input_series': inputs,
            'alert_rule_test': [{'eval_time': at, 'alertname': 'ConstellationScannerCache' + alert, 'exp_alerts': expected}]}


tests = []
for alert, changes in {
    'BytesLow': [series('available_bytes', 0)],
    'FreeRatioLow': [series('available_bytes', 1)],
    'InodesLow': [series('free_inodes', 0)],
    'CollectionFailed': [series('collection_success', 0)],
    'CapacityUnknown': [series('capacity_known', 0)],
    'PathMissing': [series('present', 0)],
    'PathUnconfigured': [series('configured', 0)],
    'MetricsUnavailable': [series('up', 0)],
}.items():
    tests.append(case(alert + ' fires', alert, changes, True))
    tests.append(case(alert + ' healthy', alert))

tests += [
    case('unknown inode capacity is not exhaustion', 'InodesLow', [series('free_inodes', 0), series('inodes_known', 0)]),
    case('zero inode total is not exhaustion', 'InodesLow', [series('free_inodes', 0), series('capacity_inodes', 0)]),
    case('zero byte total excludes ratio', 'FreeRatioLow', [series('available_bytes', 0), series('capacity_bytes', 0)]),
    case('disabled engine unconfigured is quiet', 'PathUnconfigured', [series('configured', 0), series('enabled', 0)]),
    case('lazy scratch directory missing is quiet', 'PathMissing', [series('present', 0, {'cache': 'syft'}), series('collection_success', 1, {'cache': 'syft'})]),
    case('failed sample suppresses stale bytes', 'BytesLow', [series('available_bytes', 0), series('collection_success', 0)]),
    case('healthy sibling cache cannot mask failure', 'BytesLow', [series('available_bytes', 0), series('collection_success', 0), series('collection_success', 1, {'cache': 'trivy'})]),
    case('healthy replica cannot mask failure', 'BytesLow', [series('available_bytes', 0), series('collection_success', 0), series('collection_success', 1, {'instance': 'scanner-2'})]),
    case('healthy other cluster cannot mask failure', 'BytesLow', [series('available_bytes', 0), series('collection_success', 0), series('collection_success', 1, {'cluster': 'other'})]),
    case('other cluster exporter does not hide missing exporter', 'MetricsUnavailable', entries=[series('up', 1), series('enabled', 1, {'cluster': 'other'})], firing=True),
    case('down target suppresses stale bytes', 'BytesLow', [series('available_bytes', 0), series('up', 0)]),
    case('other namespace cannot warn here', 'BytesLow', [series('available_bytes', 0, {'namespace': 'other'})]),
    case('warning waits for hold period', 'BytesLow', [series('available_bytes', 0)], at='5m'),
    case('missing exporter on healthy target', 'MetricsUnavailable', entries=[series('up', 1)], firing=True),
    case('healthy replica does not hide missing exporter', 'MetricsUnavailable', entries=[series('up', 1), series('up', 1, {'instance': 'scanner-2'}), series('enabled', 1, {'instance': 'scanner-2'})], firing=True),
]
absent = case('discovery entirely absent', 'MetricsUnavailable', entries=[])
absent['alert_rule_test'][0]['exp_alerts'] = [{
    'exp_labels': {'namespace': 'cache-tests', 'service': 'constellation-scanner', 'severity': 'warning'},
    'exp_annotations': alerts['ConstellationScannerCacheMetricsUnavailable']['annotations'],
}]
tests.append(absent)
recovery = series('available_bytes', 0)
recovery['values'] = '0+0x15 4294967296+0x45'
tests.append(case('capacity recovery clears warning', 'BytesLow', [recovery]))
(root / 'tests.yaml').write_text(yaml.safe_dump({'rule_files': [str(root / 'rules.yaml')], 'evaluation_interval': '1m', 'tests': tests}))
print(f'scanner-cache chart wiring and {len(tests)} PromQL scenarios generated')
