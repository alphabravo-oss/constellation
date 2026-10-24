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
| Receiver deliveries | receivers / notifications | Preserve pending retries and terminal receipts, including artifact references, until archive/reference handling is implemented. No age-only cleanup. |
| Compliance runs and attempts | compliance | Retain decision evidence and its inputs/results; no age-only cleanup. Schedule deletion is a separate explicit operator action. |
| Support-bundle jobs | support | Existing seven-day payload expiration remains: at most 100 terminal jobs per pass lose payload/error bytes while job metadata and audit receipts remain. This does not bound retained metadata or provide an evidence archive. |
| Component restarts | component inventory | Preserve diagnostic/recovery history pending export and an explicit bounded policy. |
| Admission dry-run history | admissionhistory / policy | Automatic age retention remains held. An explicit operator clear removes at most 1,000 scoped rows per request and commits its permanent audit receipt atomically. Locked rows survive for a later request; a failed receipt rolls back deletion. This manual clear is not evidence archival. |
| CVE reference catalog | cvecatalog | Keep PostgreSQL; sources/aliases/KEV are historical observations. EPSS freshness uses its score timestamp. Optional historical NVD import is resumable and does not outrank current updates. Catalog backups include feed checkpoints. |
| Scanner databases / staging files | scannercache / scanner | Rebuildable cache follows the explicit pod-local or single-PVC topology, freshness and capacity policy. Bounded stale-staging cleanup does not remove active or referenced evidence. Local network-isolated package matching across process replacement is qualified; PVC attachment, refresh capacity and live notifications remain deployment checks. |
| Organization backup artifacts | backup | Retention is opt-in and preserves at least the newest successful local catalog copy, plus the configured keep-last floor. Remote receipts and failed artifacts remain held pending object lifecycle/off-host qualification. Independent signed local-file and local-object-store configuration restoration are locally qualified; this is separate from full PostgreSQL recovery. |
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

## Local organization-backup cleanup bounds

An enabled policy protects `max(1, keep-last)` newest successful local catalog
entries. Cleanup now holds if any protected entry lacks a path or its file is
missing, empty, unreadable, or not a safe regular file. File availability does
not establish signature validity or successful restoration; retain independent
verification/recovery evidence. Historical catalog success alone is insufficient
to allow removal of older available files.

A pass locks the protected entries and at most 100 oldest older candidates, skips
locked rows, and uses a per-organization transaction lock to avoid concurrent
maintenance. The transaction has a five-second context deadline. Policy values
over 10,000 protected entries or 36,500 age days hold with an error rather than
allocating an unbounded maintenance batch. Existing zero policy remains a hold.
Age never overrides the protected floor. Remote receipts and failed artifacts
remain held; manual successful local org-backups already participate in the same
catalog policy when their organization's scheduled maintenance runs.

Catalog locks prevent path/status changes during cleanup. Shared paths remain
until no other catalog entry references them. Application exports use unique
paths, but arbitrary external filesystem writers or direct database alias
insertion are not serialized by this protocol. Filesystem removal and SQL commit
are not atomic: a failed commit can leave an old receipt with an already-removed
file. The receipt survives for retry, and the protected floor is never removed.
A retry treats an already-missing eligible old file as removed. File errors keep
that receipt; repeatedly failing old artifacts may delay later candidates within
the bounded batch and should be investigated from the maintenance logs.

## Support payload expiry and incomplete audit receipts

The existing seven-day support-bundle payload TTL now also requires
`audit_pending IS NULL` and a non-null `audit_event_id`. A pending or missing
receipt holds the payload/error even after its TTL. After audit reconciliation
links the receipt, a later pass can expire it. The worker retains job metadata,
uses a five-second deadline and at most 100 terminal rows, and skips locked rows.
This preserves evidence during audit outages; it does not make an expired bundle
downloadable or extend its download TTL. Held metadata/payload growth still needs
operational monitoring and the separate DB-17 archive/lifecycle work.
