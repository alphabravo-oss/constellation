# Scale hardening guide

Constellation's design target is **mid-market self-hosted** (100 clusters, 10k nodes,
100k images, 100M findings on a single Postgres 16 instance) and **SaaS small tier**
(10 clusters, 500 nodes, 5k images, 5M findings).

## Postgres

| Concern | Production default |
|---|---|
| Partitioning | `findings` + `events` partitioned **monthly**. Auto-rotate via `pg_partman` cron. |
| Indexes | `idx_findings_org_riskscore_lastseen` is load-bearing — most reads filter on `(org, lifecycle, risk_score DESC)`. |
| Connection pool | `pgxpool` capped at `cores × 4`; on a c5.2xlarge that's 32. |
| Vacuum | `autovacuum_vacuum_scale_factor = 0.05` for findings (hotter than default). |
| Backup | `cmd/constellation-backup` every 1h + WAL streaming for RPO ≤ 15 min. |
| pgvector | `findings.embedding vector(1536)`; HNSW index with `m=16`, `ef_construction=64`. |

## Scanner workers

- Scale on **queue depth**, not CPU. Operator HPA watches `scan_jobs.pending` via the Prometheus adapter.
- ~1 GB RAM during Trivy DB load + ~500 MB during scan. Default `1 CPU / 2 GiB`.
- Trivy DB pre-warmed at image-build (in `Dockerfile.scanner`).
- Start with `CONSTELLATION_SCANNER_MAX_CONCURRENT=1` for Syft+Trivy+Grype deployments. Raise it only with matching memory headroom, or set `0` to auto-size from CPU count on dedicated scanner nodes.

## API

- Stateless. 2-3 replicas. < 256 MiB per replica even with 1M findings.
- `/api/v1/findings` paginates (default 100, max 1000). Dashboard widgets read `metrics_daily` MV, not `findings`.
- OTLP batches: traces 2s, metrics 15s, logs batched.

## Operator

- One replica with leader election. Idempotent reconciler.
- HPA spec on the CR controls scanner HPA (default min=2, max=10, target CPU 70%).

## Multi-tenant SaaS

- Every query uses `WHERE org_id = $1` — CI lints for this. Cross-tenant leaks are the #1 risk.
- Per-tenant read-only DB roles for embedded BI.
- Row-level security wired but disabled by default; enable with `ALTER TABLE findings ENABLE ROW LEVEL SECURITY;` once `auth.tenant_id` is populated.

## Out-of-scope at v1

- Wiz-class (1K clusters / 1B findings) — needs sharded Postgres + ClickHouse + multi-region (v2 roadmap).
- Cross-region replication for resident orgs — off by default; customers run two deployments bridged at the Abbot layer.
