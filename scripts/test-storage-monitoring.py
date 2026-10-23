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
assert len(alert_rules) == 21
for rule in alert_rules.values():
    assert 'namespace="storage-tests"' in rule['expr'] and 'service="constellation-api"' in rule['expr']


def env(name):
    deployment = next(d for d in docs(name) if d['kind'] == 'Deployment' and d['metadata']['name'] == 'constellation-api')
    container = next(c for c in deployment['spec']['template']['spec']['containers'] if c['name'] == 'api')
    return {e['name']: e for e in container['env']}


assert env('default')['CONSTELLATION_STORAGE_ARCHIVE_ENABLED']['value'] == 'false'
secret = env('archive-secret')
assert secret['CONSTELLATION_STORAGE_K8S_AUDIT_SOURCES']['value'] == '11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222'
assert secret['CONSTELLATION_STORAGE_K8S_AUDIT_MAX_GAP']['value'] == '30m'
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
assert len(dashboard['panels']) == 18
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
    metric = name if name == 'up' or name.startswith('constellation_') else prefix + name
    return {'series': metric + '{' + ','.join(k + '=' + json.dumps(v) for k, v in all_labels.items()) + '}', 'values': values}


# Evaluate after 2 hours so every rule's hold period and stall window has elapsed.
# Values have one sample per minute; timestamp baselines keep healthy watermarks current.
healthy = [series('constellation_session_cleanup_active_workers', '0+0x180'), series('constellation_session_cleanup_last_success_timestamp_seconds', '0+60x180'), series('constellation_session_cleanup_failures_total', '0+0x180'), series('k8s_audit_expected_sources', '0+0x180'), series('k8s_audit_missing_sources', '0+0x180'), series('k8s_audit_stale_sources', '0+0x180'), series('k8s_audit_delayed_sources', '0+0x180'), series('k8s_audit_unknown_reported_sources', '0+0x180'), series('k8s_audit_future_reported_sources', '0+0x180'), series('postgres_wal_occupancy_known', '1+0x180'), series('up', '1+0x180'), series('collector_up', '1+0x180'), series('database_bytes', '1000000+0x180'),
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
    scenario('active cleanup stalled', [series('constellation_session_cleanup_active_workers', '1+0x180'), series('constellation_session_cleanup_last_success_timestamp_seconds', '0+0x180')], 'ConstellationSessionCleanupStalled'),
    scenario('active cleanup failing', [series('constellation_session_cleanup_active_workers', '1+0x180'), series('constellation_session_cleanup_failures_total', '0+1x180')], 'ConstellationSessionCleanupFailing'),
    scenario('idle replica has no cleanup obligation', [series('constellation_session_cleanup_last_success_timestamp_seconds', '0+0x180')], 'ConstellationSessionCleanupStalled', firing=False),
    scenario('former worker failures do not alert idle replica', [series('constellation_session_cleanup_failures_total', '0+1x180')], 'ConstellationSessionCleanupFailing', firing=False),

    scenario('missing audit source', [series('k8s_audit_expected_sources', '2+0x180'), series('k8s_audit_missing_sources', '1+0x180')], 'ConstellationKubernetesAuditSourceGap'),
    scenario('stale audit source', [series('k8s_audit_expected_sources', '2+0x180'), series('k8s_audit_stale_sources', '1+0x180')], 'ConstellationKubernetesAuditSourceGap'),
    scenario('delayed audit source', [series('k8s_audit_expected_sources', '2+0x180'), series('k8s_audit_delayed_sources', '1+0x180')], 'ConstellationKubernetesAuditDeliveryDelayed'),
    scenario('missing audit timestamp', [series('k8s_audit_expected_sources', '2+0x180'), series('k8s_audit_unknown_reported_sources', '1+0x180')], 'ConstellationKubernetesAuditTimestampUnknown'),
    scenario('future audit timestamp', [series('k8s_audit_expected_sources', '2+0x180'), series('k8s_audit_future_reported_sources', '1+0x180')], 'ConstellationKubernetesAuditTimestampUnknown'),
    scenario('audit observation unconfigured', [series('k8s_audit_missing_sources', '1+0x180')], 'ConstellationKubernetesAuditSourceGap', firing=False),

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
    scenario('retained WAL warning', [series('postgres_wal_retained_bytes', '5000000000+0x180')], 'ConstellationWALRetainedHigh'),
    scenario('WAL occupancy unknown', [series('postgres_wal_occupancy_known', '0+0x180')], 'ConstellationWALOccupancyUnknown'),
    scenario('raw retention stalled', [series('retention_enabled', '1+0x180', {'table': 'network_flows'}), series('retention_cutoff_timestamp_seconds', '0+60x180', {'table': 'network_flows'}), series('raw_flow_pruned_before_timestamp_seconds', '0+0x180')], 'ConstellationRawFlowRetentionLagging', {'table': 'network_flows'}),
    scenario('partition expiry stalled', [series('retention_enabled', '1+0x180', {'table': 'events'}), series('retention_cutoff_timestamp_seconds', '0+60x180', {'table': 'events'}), series('oldest_expired_partition_upper_timestamp_seconds', '1+0x180', {'table': 'events'}), series('expired_partitions', '1+0x180', {'table': 'events'})], 'ConstellationPartitionExpiryLagging', {'table': 'events'}),
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

# Exercise each of the nine data alerts with all target labels preserved.
# Reuse their existing positive fixtures so warning inputs and expected dimensions
# remain realistic (including table/kind and WAL rates).
data_alerts = {
    "ConstellationSessionCleanupStalled", "ConstellationSessionCleanupFailing",
    "ConstellationKubernetesAuditSourceGap", "ConstellationKubernetesAuditDeliveryDelayed", "ConstellationKubernetesAuditTimestampUnknown",
    'ConstellationDatabaseSizeHigh', 'ConstellationRelationSizeHigh',
    'ConstellationDeadRowsHigh', 'ConstellationDefaultPartitionLarge',
    'ConstellationFlowRollupLagging', 'ConstellationAuditArchiveLagging',
    'ConstellationBackupScheduleOverdue', 'ConstellationBackupScheduleFailed',
    'ConstellationWALGenerationHigh', 'ConstellationWALRetainedHigh', 'ConstellationWALOccupancyUnknown',
    'ConstellationRawFlowRetentionLagging', 'ConstellationPartitionExpiryLagging',
}
# Explicit holds/unknown samples must suppress data-pressure alerts.
tests.append(scenario('unknown WAL never implies measured pressure', [series('postgres_wal_retained_bytes', '5000000000+0x180'), series('postgres_wal_occupancy_known', '0+0x180')], 'ConstellationWALRetainedHigh', firing=False))
tests.append(scenario('raw retention hold', [series('retention_enabled', '0+0x180', {'table': 'network_flows'}), series('retention_cutoff_timestamp_seconds', '0+60x180', {'table': 'network_flows'}), series('raw_flow_pruned_before_timestamp_seconds', '0+0x180')], 'ConstellationRawFlowRetentionLagging', firing=False))
tests.append(scenario('empty expiry backlog', [series('retention_enabled', '1+0x180', {'table': 'events'}), series('retention_cutoff_timestamp_seconds', '0+60x180', {'table': 'events'}), series('oldest_expired_partition_upper_timestamp_seconds', '0+0x180', {'table': 'events'}), series('expired_partitions', '0+0x180', {'table': 'events'})], 'ConstellationPartitionExpiryLagging', firing=False))
positive = {}
for test in tests:
    check = test['alert_rule_test'][0]
    if check['alertname'] in data_alerts and check['exp_alerts']:
        positive.setdefault(check['alertname'], test)
assert set(positive) == data_alerts


def replace_series(test, replacement):
    test['input_series'] = [old for old in test['input_series'] if old['series'] != replacement['series']] + [replacement]


for alert, original in positive.items():
    for dimension, other in [('cluster', 'other-cluster'), ('prometheus', 'other-prometheus'), ('instance', 'api-2')]:
        test = copy.deepcopy(original)
        test['name'] = alert + ' rejects health from another ' + dimension
        replace_series(test, series('collector_up', '0+0x180'))
        replace_series(test, series('collector_up', '1+0x180', {dimension: other}))
        test['alert_rule_test'][0]['exp_alerts'] = []
        tests.append(test)
    down = copy.deepcopy(original)
    down['name'] = alert + ' rejects other-cluster scrape health after local failure'
    replace_series(down, series('up', '0+0x180'))
    replace_series(down, series('up', '1+0x180', {'cluster': 'other-cluster'}))
    down['alert_rule_test'][0]['exp_alerts'] = []
    tests.append(down)
    scoped = copy.deepcopy(original)
    scoped['name'] = alert + ' fires with matching extra target labels'
    for entry in scoped['input_series']:
        entry['series'] = entry['series'].replace('{', '{cluster="same-cluster",prometheus="same-prometheus",', 1)
    scoped['alert_rule_test'][0]['exp_alerts'][0]['exp_labels'].update(cluster='same-cluster', prometheus='same-prometheus')
    tests.append(scoped)

absent_alert = 'ConstellationStorageMetricsAbsent'
for name, inputs in [
    ('failed scrape', [series('up', '0+0x180')]),
    ('healthy scrape missing exporter', [series('up', '1+0x180')]),
    ('another replica exporter does not hide missing exporter', [series('up', '1+0x180'), series('up', '1+0x180', {'instance': 'api-2'}), series('collector_up', '1+0x180', {'instance': 'api-2'})]),
    ('another cluster exporter does not hide missing exporter', [series('up', '1+0x180'), series('collector_up', '1+0x180', {'cluster': 'other-cluster'})]),
]:
    test = scenario(name, [], absent_alert)
    test['input_series'] = inputs
    tests.append(test)
# An exporter with a failed DB snapshot is still present; its own failure rule
# covers that state, rather than misreporting discovery failure.
tests.append(scenario('failed database snapshot is not missing exporter', [series('collector_up', '0+0x180')], absent_alert, firing=False))
# Archive control/progress must belong to the same full target too.
tests.append(scenario('other cluster cannot enable disabled archive', [series('archive_pending_id_distance', '99999+0x180'), series('archive_enabled', '1+0x180', {'cluster': 'other-cluster'})], 'ConstellationAuditArchiveLagging', firing=False))
tests.append(scenario('other cluster cannot supply stale archive timestamp', [series('archive_enabled', '1+0x180'), series('archive_pending_id_distance', '10+0x180'), series('archive_updated_timestamp_seconds', '0+0x180', {'cluster': 'other-cluster'})], 'ConstellationAuditArchiveLagging', firing=False))
(root / 'tests.yaml').write_text(yaml.safe_dump({'rule_files': ['rules.yaml'], 'evaluation_interval': '1m', 'tests': tests}))
print(f'storage chart: wiring and dashboard passed; evaluating {len(tests)} PromQL scenarios')
