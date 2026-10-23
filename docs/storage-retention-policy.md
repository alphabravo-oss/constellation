# Conservative retention decisions

The owner supplied no required retention periods, legal holds or RPO/RTO targets
on October 23. These are engineering defaults and implementation boundaries,
not a claim of regulatory compliance or a recovery SLA. Existing stored choices
are preserved. The live 3/7/7-day raw-flow/event/job settings were not rewritten.

| Data family | Owning domain | Policy and evidence exception |
| --- | --- | --- |
| Control-plane audit, including runtime detection and scan completion receipts | audit / auditarchive | Retain every existing receipt in the append-only chain. Do not suppress high-rate actions or migrate their consumers merely to reduce volume. Signed archive is additional evidence; no source-chain pruning until independent archive/query-anchor qualification. |
| Raw flows / ordinary event history | network / event ingest | Existing configured windows remain in force. Fresh defaults are 14/30 days. Zero holds deletion. Raw expiry stays behind completed folding. |
| Hourly flow aggregates | flowrollup | Fresh default 90 days; missing existing setting remains zero. Raw-boundary gate, bounded deletion and explicit unavailable-range responses apply. |
| Kubernetes audit JSON and signals | k8saudit | Retain pending verified export and a separately qualified ingestion-freshness policy. A missing webhook stream must not be presented as an empty healthy stream. No age-only deletion is introduced. |
| Runtime threats, packet payloads and forensic snapshots | runtime | Preserve case evidence pending verified export/reference protection. Existing explicitly expired PCAP cleanup requires a verified durable store and retains receipts on file failure. No shared retention window is assumed for threats, packet bytes and forensic snapshots. |
| Findings and triage decisions | findings | Preserve open, suppressed, accepted and resolved decisions until an archive can restore their dependencies. Repository cleanup may not cascade-delete findings. Resolved/orphaned archival remains implementation work. |
| Jobs / attempts / image results | scanretention | Keep live/latest jobs and results plus every evidence reference. Only older eligible terminal jobs and superseded unnamed replaceable cache history may expire through the bounded workers. |
| Inventory payloads, SBOM artifacts, attestations and verification records | scanning | Preserve current/referenced evidence. Payload caps and archival need a verified restore contract before deleting retained decisions' inputs. |
| Expired identity login/session state and transient network-session commands | lifecycle | Existing bounded expiry applies; live identities and audit receipts survive. |
| Delivery, compliance, support, restart and admission histories | their producer domains | Do not treat all operational metadata as disposable: compliance and admission rows can be decision evidence, delivery rows may represent pending retries, and support records may own files. Hold pending per-family archive/file/reference handling. DB-17 is not closed by this decision. |
| CVE reference catalog | cvecatalog | Keep PostgreSQL; sources/aliases/KEV are historical observations. EPSS freshness uses its score timestamp. Optional historical NVD import is resumable and does not outrank current updates. Catalog backups include feed checkpoints. |
| Scanner databases / staging files | scannercache / scanner | Rebuildable cache follows the explicit pod-local or single-PVC topology, freshness and capacity policy. Bounded stale-staging cleanup does not remove active or referenced evidence. Offline/restart acceptance remains a deployment check. |
| Organization backup artifacts | backup | Retention is opt-in and preserves at least the newest successful local catalog copy, plus the configured keep-last floor. Remote receipts and failed artifacts remain held until independent remote lifecycle/recovery is qualified. A successful upload/read-back alone does not prove restoration. |
| PostgreSQL base backups and WAL | CloudNativePG / operator | Keep the existing archive policy. Preserve the newest recoverable base-backup/WAL set; do not shorten retention based on application artifact TTL. Off-host restore and node-failure testing remain explicitly deferred. |

DB-06's classification decision is to retain the existing audit receipt contract;
there is no evidence-suppression migration to ship. DB-20's storage decision is
PostgreSQL, supported by the restored-catalog profile and index measurement.
Neither decision closes the separate archive, deployment or fleet-capacity gates.

Recovery evidence: the October 23 isolated CNPG database became Ready in 10m17s,
including an initial test network-policy failure. This is database readiness, not
application RTO. Counts survived migrations 190–192 and 192–194. No marker-based
RPO, independent-host restore or complete historical audit integrity was proven:
the source and restored database share the pre-existing row-53 chain break.
Temporary recovery resources were subsequently removed.

The release guide requires trusted signatures and source-bound SLSA provenance
for published role images. The owner explicitly directed that GitHub Actions remain disabled and work
continue through code and local verification only. Release publishing and live
rollout are deferred, alongside off-host recovery and real node-failure tests. Local/source tests and merged PRs
are not evidence that the live release runs the new workers or alert rules.
