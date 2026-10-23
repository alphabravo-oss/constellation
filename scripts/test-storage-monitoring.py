#!/usr/bin/env python3
"""Validate chart wiring and write deterministic promtool failure fixtures."""
import copy
import json
import pathlib
import sys

import yaml

root = pathlib.Path(sys.argv[1])


def docs(name):
    return [d for d in yaml.safe_load_all((root / (name + '.yaml')).read_text()) if d]


def storage_rules(name):
    return [d for d in docs(name) if d['kind'] == 'PrometheusRule' and d['metadata']['name'].endswith('-storage')]


assert not storage_rules('default') and not storage_rules('disabled') and not storage_rules('no-api')
assert not [d for d in docs('default') if d['metadata']['name'].endswith('-storage-dashboard')]
rules = storage_rules('enabled')
assert len(rules) == 1
rule_spec = rules[0]['spec']
(root / 'rules.yaml').write_text(yaml.safe_dump(rule_spec))
alert_rules = {r['alert']: r for g in rule_spec['groups'] for r in g['rules']}
assert len(alert_rules) == 12
for rule in alert_rules.values():
    assert 'namespace="storage-tests"' in rule['expr'] and 'service="constellation-api"' in rule['expr']


def env(name):
    deployment = next(d for d in docs(name) if d['kind'] == 'Deployment' and d['metadata']['name'] == 'constellation-api')
    container = next(c for c in deployment['spec']['template']['spec']['containers'] if c['name'] == 'api')
    return {e['name']: e for e in container['env']}


assert env('default')['CONSTELLATION_STORAGE_ARCHIVE_ENABLED']['value'] == 'false'
secret = env('archive-secret')
assert secret['CONSTELLATION_STORAGE_ARCHIVE_ENABLED']['value'] == 'true'
assert secret['CONSTELLATION_STORAGE_ARCHIVE_BUCKET']['value'] == 'evidence'
assert secret['CONSTELLATION_STORAGE_ARCHIVE_PREFIX']['value'] == '/private/audit/'
assert secret['CONSTELLATION_STORAGE_ARCHIVE_ENDPOINT_S3']['valueFrom'] == {
    'secretKeyRef': {'name': 'archive-endpoint', 'key': 'endpoint'}
}
assert secret['CONSTELLATION_STORAGE_ARCHIVE_ENDPOINT_DEFAULT']['value'] == 'https://generic.example'
assert env('archive-explicit')['CONSTELLATION_STORAGE_ARCHIVE_ENDPOINT']['value'] == 'https://explicit.example'
cm = next(d for d in docs('enabled') if d['metadata']['name'].endswith('-storage-dashboard'))
assert cm['metadata']['labels']['grafana_dashboard'] == '1'
dashboard = json.loads(cm['data']['constellation-storage.json'])
assert len(dashboard['panels']) == 14
# Parse the real dashboard expressions too, substituting only Grafana variables.
expressions = [target['expr'].replace('$namespace', 'storage-tests').replace('$service', 'constellation-api').replace('$__rate_interval', '5m')
               for panel in dashboard['panels'] for target in panel['targets']]
(root / 'dashboard-rules.yaml').write_text(yaml.safe_dump({'groups': [{'name': 'dashboard-syntax', 'rules': [
    {'record': f'dashboard_query_{i}', 'expr': expr} for i, expr in enumerate(expressions)
]}]}))

labels = {'namespace': 'storage-tests', 'service': 'constellation-api', 'job': 'api', 'instance': 'api-1'}
prefix = 'constellation_storage_'


def series(name, values, extra=None):
    all_labels = dict(labels, **(extra or {}))
    return {'series': prefix + name + '{' + ','.join(k + '=' + json.dumps(v) for k, v in all_labels.items()) + '}', 'values': values}


# Evaluate after 2 hours so every rule's hold period and stall window has elapsed.
# Values have one sample per minute; timestamp baselines keep healthy watermarks current.
healthy = [series('collector_up', '1+0x180'), series('database_bytes', '1000000+0x180'),
           series('rollup_watermark_timestamp_seconds', '0+60x180'),
           series('archive_enabled', '0+0x180'), series('archive_pending_id_distance', '0+0x180'),
           series('archive_updated_timestamp_seconds', '0+60x180'),
           series('backup_failed_schedules', '0+0x180'), series('backup_oldest_due_timestamp_seconds', '0+0x180')]


def scenario(name, replacements, alert, extra=None, firing=True):
    entries = copy.deepcopy(healthy)
    for entry in replacements:
        entries = [old for old in entries if old['series'] != entry['series']] + [entry]
    expected = []
    if firing:
        rule = alert_rules[alert]
        expected = [{'exp_labels': dict(labels, severity='warning', **(extra or {})),
                     'exp_annotations': rule['annotations']}]
    return {'name': name, 'interval': '1m', 'input_series': entries,
            'alert_rule_test': [{'eval_time': '120m', 'alertname': alert, 'exp_alerts': expected}]}


tests = [
    scenario('collection failure', [series('collector_up', '0+0x180')], 'ConstellationStorageCollectorFailed'),
    scenario('database warning', [series('database_bytes', '20000000000+0x180')], 'ConstellationDatabaseSizeHigh'),
    scenario('relation warning', [series('relation_bytes', '3000000000+0x180', {'table': 'events', 'kind': 'total'})], 'ConstellationRelationSizeHigh', {'table': 'events', 'kind': 'total'}),
    scenario('dead tuple warning', [series('relation_rows_estimate', '20000+0x180', {'table': 'cve_records', 'kind': 'dead'}), series('relation_rows_estimate', '1000+0x180', {'table': 'cve_records', 'kind': 'live'})], 'ConstellationDeadRowsHigh', {'table': 'cve_records', 'kind': 'dead'}),
    scenario('default partition warning', [series('default_partition_bytes', '200000000+0x180', {'table': 'findings'})], 'ConstellationDefaultPartitionLarge', {'table': 'findings'}),
    scenario('stalled rollup', [series('rollup_watermark_timestamp_seconds', '0+0x180')], 'ConstellationFlowRollupLagging'),
    scenario('archive never published', [series('archive_enabled', '1+0x180'), series('archive_pending_id_distance', '10+0x180'), series('archive_updated_timestamp_seconds', '0+0x180')], 'ConstellationAuditArchiveLagging'),
    scenario('archive backlog grows despite progress', [series('archive_enabled', '1+0x180'), series('archive_pending_id_distance', '20000+0x180')], 'ConstellationAuditArchiveLagging'),
    scenario('backup overdue', [series('backup_oldest_due_timestamp_seconds', '1+0x180')], 'ConstellationBackupScheduleOverdue'),
    scenario('backup failed', [series('backup_failed_schedules', '1+0x180')], 'ConstellationBackupScheduleFailed'),
    scenario('WAL rate warning', [series('postgres_wal_generated_bytes_total', '0+12000000000x180')], 'ConstellationWALGenerationHigh'),
]
error_series = series('collector_errors_total', '0+1x180')
error_series['series'] = error_series['series'].replace('constellation_storage_collector_errors_total', 'constellation_db_health_scrape_errors_total')
tests.append(scenario('existing feed collector failure', [error_series], 'ConstellationDBHealthCollectionFailing'))
tests.append({'name': 'metric absent', 'interval': '1m', 'input_series': [], 'alert_rule_test': [{
    'eval_time': '120m', 'alertname': 'ConstellationStorageMetricsAbsent', 'exp_alerts': [{
        'exp_labels': {'namespace': 'storage-tests', 'service': 'constellation-api', 'severity': 'warning'},
        'exp_annotations': alert_rules['ConstellationStorageMetricsAbsent']['annotations']
    }]
}]})
# Healthy defaults, exact replica joins, disabled/idle archives and small dead-row
# populations must not fire, even when another instance reports trouble.
tests += [
    scenario('healthy collector', [], 'ConstellationStorageCollectorFailed', firing=False),
    scenario('healthy rollup', [], 'ConstellationFlowRollupLagging', firing=False),
    scenario('idle archive', [series('archive_enabled', '1+0x180'), series('archive_updated_timestamp_seconds', '0+0x180')], 'ConstellationAuditArchiveLagging', firing=False),
    scenario('disabled archive', [series('archive_pending_id_distance', '99999+0x180'), series('archive_updated_timestamp_seconds', '0+0x180')], 'ConstellationAuditArchiveLagging', firing=False),
    scenario('small dead population', [series('relation_rows_estimate', '100+0x180', {'table': 'cve_records', 'kind': 'dead'}), series('relation_rows_estimate', '1+0x180', {'table': 'cve_records', 'kind': 'live'})], 'ConstellationDeadRowsHigh', firing=False),
    scenario('failed collector withholds data alert', [series('collector_up', '0+0x180'), series('database_bytes', '20000000000+0x180')], 'ConstellationDatabaseSizeHigh', firing=False),
    scenario('healthy other replica cannot validate failed replica', [series('collector_up', '0+0x180'), series('collector_up', '1+0x180', {'instance': 'api-2'}), series('database_bytes', '20000000000+0x180')], 'ConstellationDatabaseSizeHigh', firing=False),
    scenario('fresh archive progressing', [series('archive_enabled', '1+0x180'), series('archive_pending_id_distance', '10+0x180')], 'ConstellationAuditArchiveLagging', firing=False),
    scenario('no overdue schedules', [], 'ConstellationBackupScheduleOverdue', firing=False),
]
tests.append({'name': 'healthy installation has no storage alerts', 'interval': '1m', 'input_series': healthy,
              'alert_rule_test': [{'eval_time': '120m', 'alertname': alert, 'exp_alerts': []} for alert in alert_rules]})
(root / 'tests.yaml').write_text(yaml.safe_dump({'rule_files': ['rules.yaml'], 'evaluation_interval': '1m', 'tests': tests}))
print(f'storage chart: wiring and dashboard passed; evaluating {len(tests)} PromQL scenarios')
