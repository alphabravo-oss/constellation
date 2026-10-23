# Scanner cache metrics and alerts

The scanner exports local cache filesystem observations on its existing `/metrics`
endpoint. The collector performs only path/statfs reads: it does not write a probe,
enumerate cache contents, create directories, refresh databases or evict data.
The existing heartbeat diagnostics are separate and still probe writability and
perform their bounded usage walk; readiness checks omit that walk. This corrects
an earlier documentation statement that ordinary heartbeats skipped enumeration.

## Ten scoped implementation items

| Item | Behavior |
| --- | --- |
| 1. Byte capacity | Total filesystem bytes and bytes available to unprivileged processes, with checked counter arithmetic. Reserved blocks are excluded from available bytes. |
| 2. Inode headroom | Total/free inodes and explicit knowledge state. Zero free inodes with a known total means exhaustion; zero or unsupported totals mean unknown. |
| 3. Path states | Distinguishes configured, disabled, missing and failed observations. Missing directories are successfully observed absence; permission/type/statfs errors are failures. |
| 4. Bounded scrape work | One serialized refresh per minute for at most four fixed paths. Concurrent scrapes share a cached snapshot; failure uses the same retry interval. |
| 5. Failed-sample invalidation | A failed cache observation withholds its old capacity/presence, increments its error counter and retains its last-success timestamp. Healthy sibling caches remain available. |
| 6. Bounded private labels | Only `xdg`, `syft`, `grype`, `trivy` become labels. Paths and unknown map keys never appear in metrics. Disabled engines are not inspected. |
| 7. Byte pressure alerts | Absolute available bytes and available/total ratio warnings, joined to the same cache and target's successful collection and healthy scrape. |
| 8. Inode/unknown-capacity alerts | Low inode ratio warnings exclude unknown/zero totals. Unknown byte capacity gets its own warning rather than appearing as zero free space. |
| 9. Configuration/path alerts | Enabled Trivy/Grype caches warn for unconfigured or persistently missing paths. Missing lazy XDG/Syft directories are excluded. |
| 10. Collection/discovery alerts | Failed observations, failed target scrapes, missing collectors on healthy targets and completely absent discovery are visible. Another healthy target cannot validate a failed target's data. |

This completes the scoped monitoring implementation, not all DB-21/23 operational
acceptance. The [explicit topology implementation](scanner-cache-topology.md) is available;
installation selection, refresh/offline/restart capacity qualification, live scrape,
notification delivery and installation-specific budgets remain open.

## Metric contract

All metrics have the prefix `constellation_scanner_cache_` and one application
label, `cache`. Prometheus adds `namespace`, `service`, `job` and `instance`.

- `enabled`, `configured` always exist for all four fixed cache names. XDG is
  enabled independently; the other names follow their engine flags. Configuration
  uses the scanner's explicit `XDG_CACHE_HOME`, `SYFT_CACHE_DIR`,
  `GRYPE_DB_CACHE_DIR`, and `TRIVY_CACHE_DIR` paths. Implicit engine defaults are
  not guessed. The chart sets those paths.
- Enabled, configured caches emit `collection_success`,
  `collection_errors_total` and `last_success_timestamp_seconds`. A failed
  observation retains the timestamp; before success it is zero. Error counters
  reset on scanner restart. Disabled/unconfigured caches emit no data gauges.
- A successful observation emits `present`; a missing directory is zero and has
  no capacity gauges. An invalid path type is a collection failure.
- Existing directories emit `capacity_known` and `inodes_known`. Known byte
  counters emit `capacity_bytes` and `available_bytes`; known inode counters emit
  `capacity_inodes` and `free_inodes`. Invalid, zero-total or unrepresentable
  counters omit the corresponding values. Byte/inode validity is independent.

Snapshots can be up to one minute old between refreshes. The bounds limit syscall
count, enumeration and concurrency, not kernel syscall latency; a stalled mount
can stall the scrape. The target-health warning covers failed/timed-out scrapes.
No goroutine is abandoned to simulate cancellation of an uninterruptible statfs.

Capacity belongs to the underlying filesystem. It is neither a PVC quota nor an
engine's private allocation. Multiple engine paths can report the same capacity;
do not sum them. These metrics do not prove the path is writable or an engine DB
is fresh. Use the separate readiness/engine freshness signals too.

## Helm configuration

```yaml
metrics:
  serviceMonitor:
    enabled: true
    labels: { release: kube-prometheus-stack }
  prometheusRule:
    enabled: true
    labels: { release: kube-prometheus-stack }
    scannerCache:
      enabled: true
      availableBytes: 1073741824
      availableRatio: 0.10
      freeInodeRatio: 0.05
```

PrometheusRule and ServiceMonitor parent toggles remain off by default. Scanner
cache rules render only when the parent rule toggle, this rule group and scanner
are enabled. Thresholds must be positive; ratios must be below one. Review these
warning budgets against simultaneous Trivy/Grype refreshes and extraction space.
They do not gate scan admission or trigger cleanup.

Rules select this release's scanner Service and namespace even when the rule
resource lives in a separate monitoring namespace. Standard ServiceMonitor
scraping supplies the target labels. Annotation scraping must supply matching
labels. Joins retain all target labels, including optional cluster labels,
so identical addresses in different clusters cannot validate each other.
Absolute/ratio/inode/unknown-capacity warnings hold for ten minutes,
collection failures for five minutes, and missing/unconfigured engine paths for
fifteen minutes. Target/exporter absence holds for ten minutes.

A completely missing discovery set fires the absent rule; a discovered unhealthy
target or missing collector fires per target. The rules do not infer expected
replica counts or detect one removed discovery target while others remain. Use
Kubernetes workload availability alerts for desired replicas.

## Response

For low bytes or inodes, inspect mount capacity and shared consumers, recent
refreshes and temporary extraction growth. Avoid deleting active engine databases.
Choose any storage expansion or topology change against measured refresh working
space and offline recovery requirements. For unknown capacity or collection
failure, inspect path types, permissions and filesystem health; absent gauges
must not be interpreted as zero usage or healthy headroom. For missing paths,
check cache environment variables, mounts and offline provisioning. For missing
metrics, check the existing scanner ServiceMonitor, target labels and binary
version. Verify notification routing after enabling the rules.

## Verification

Real filesystem and HTTP metrics tests cover read-only behavior, label privacy,
configuration copying, missing/disabled/unconfigured caches, TTL sharing across
32 concurrent gathers, failed-sample invalidation/recovery and failure isolation.
Counter tests exercise overflow, inconsistent values, reserved blocks, unknown
inode totals and exhaustion. The Helm smoke suite renders discovery/Service
selectors, group toggles, disabled scanner and a separate rule namespace; it
rejects invalid thresholds. Actual `promtool` evaluates 33 positive/negative,
hold-period and recovery scenarios for all eight alert rules.

Run `make helm-lint helm-template-smoke` with Helm 4. Set `PROMTOOL` to a local
binary or preload the digest-pinned Prometheus image used by the test script;
tests never pull images implicitly. Live cluster configuration is unchanged.
