# Scanner cache diagnostics

Scanner heartbeats report cache path readiness and filesystem capacity. An
explicit status request additionally samples cache file usage. These are local
observations from each scanner, not PVC quotas or database-recovery evidence.

## Ten implementation items (2026-10-23)

1. **Exclusive write probes.** Random, exclusively created temporary files replace
   the predictable process-ID filename. Concurrent probes cannot truncate each
   other's files; an existing symlink at the old probe name remains untouched.
2. **Probe lifecycle errors.** Write, close and removal failures all prevent a
   writable result. Probe success checks ordinary write access, not fsync durability.
3. **Path error classification.** Only not-found errors report `missing`. Other
   stat failures report `unavailable`; non-directories remain `not-directory`.
   Probe failures report `write-failed`, covering full disks as well as permissions.
4. **Filesystem byte capacity.** `capacity_bytes`, `filesystem_free_bytes` and
   `free_bytes` distinguish total, all free blocks and blocks available to the
   scanner. `capacity_known` is false for failed, inconsistent or unrepresentable
   counters. Capacity arithmetic is checked before publishing any byte values.
5. **Inode headroom.** `capacity_inodes` and `free_inodes` accompany
   `inodes_known`. Zero/unrepresentable totals mean unknown capacity; zero free
   inodes with a known total means exhaustion. Zero values survive API encoding.
6. **Bounded directory enumeration.** Usage reads at most 64 entries per directory
   batch and visits at most 2,000 entries, including directories and skipped
   entries. It retains at most 20 file records. The old whole-directory read could
   allocate for an arbitrarily large directory before reaching its visit limit.
7. **Root confinement and special files.** Directory opens and file metadata reads
   use `os.Root`. Directory opens reject a final symlink or non-directory; usage
   skips symlinks, FIFOs, sockets and devices. Files are never opened for content.
   A configured root may itself be a symlink; confinement starts at its target.
8. **Explicit partial usage.** `usage_complete` separates complete file totals
   from a truncated top-20 preview. It is false after a read/stat/open/close error,
   overflow or visit-limit truncation, and absent when usage was not requested.
   `usage_error` preserves a diagnostic and `usage_entries_visited` records work.
9. **Stable records and safe totals.** The largest observed regular files sort by
   size, then relative path for ties. Negative sizes or signed total overflow stop
   sampling without publishing a wrapped total. An empty successful scan returns
   an empty record array. Symlink sizes never masquerade as cached artifacts.
10. **API propagation.** Cache statistics preserve completeness and capacity-known
    flags, errors, available bytes and inode values. Inventory's safe metadata
    projection carries the numeric/boolean signals while excluding raw errors and
    paths. Frontend API types expose the same fields; legacy heartbeat completeness
    remains unknown rather than being invented as false or true.

## Interpretation and operating limits

`record_size_bytes` sums logical file lengths. It is not allocated disk space:
sparse allocation, compression and hard links can make those differ. A partial
walk reports only its observed subtotal, and its top records are largest only
among observed entries. Cache mutation during collection prevents a transactional
snapshot even when `usage_complete=true`. Ignore symlinks when comparing totals.

Multiple engine directories may share one filesystem. Do not add their capacity
or free-space values. `free_bytes` is the filesystem's available-block count, not
an enforced per-engine or per-PVC quota. Filesystem operations can block at the
kernel; the entry limit bounds enumeration and memory, not wall-clock latency.

`records_truncated=true` means the displayed records omit information; it does
not by itself imply partial totals. Inspect `usage_complete` separately. Ordinary
heartbeats do not enumerate cache files. Write probes create and remove only their
own temporary files. They do not evict caches, update engine databases, change
scanner topology, or enforce admission thresholds.

For unavailable or write-failed paths, inspect mount configuration, permissions,
bytes and inodes. For partial usage, resolve the reported error before treating
subtotals as complete. Existing engine readiness/freshness checks remain necessary.
DB-21 still requires a topology decision, filesystem alerts, restart/offline
qualification and a measured Trivy/Grype refresh margin. This batch adds diagnostic
prerequisites; no live deployment or cache eviction was performed.

## Validation

Real temporary-filesystem tests cover a pre-existing symlink trap, 32 concurrent
probes with no leftovers, unavailable/missing/non-directory paths, byte and inode
counter semantics, wide directories above and exactly at the visit limit, nested
files, deterministic largest-file previews, symlinks/FIFOs and failed enumeration.
API metadata tests verify partial/unknown distinctions and explicit zero values.
The full repository quality gate and PostgreSQL integration suite are required
before merge; results are recorded in `docs/security-testing.md`.
