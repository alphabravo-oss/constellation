# Image build hardening

Constellation vulnerability totals include its own images, supporting services
and historical workload records. Compare exact currently running image digests
with a fixed scanner/database before attributing totals or claiming reductions.

## Build policy

- Use multi-stage builds. Keep compilers, development headers, download utilities
  and package caches out of final images. Copy final binaries once to avoid
  retaining old binaries in earlier image layers.
- Prefer a minimal static runtime for static Go services. Preserve CA roots,
  timezone behavior, identity, home and temporary-storage requirements. Services
  needing native libraries or host tooling require a tailored runtime and tests.
- Update the Go compiler and application modules, then rebuild all affected
  roles. Updating application modules does not patch prebuilt third-party tools:
  each bundled executable has its own compiler and dependency inventory.
- Pin approved base digests and tool checksums, verify provenance/signatures,
  and regularly refresh the pins. Pinning alone does not keep an image patched.
- Keep scanners and diagnostic tools out of unrelated service images. Remove
  runtime packages only after checking real callers and exercising workflows.
- Run as non-root with read-only filesystems and dropped capabilities where the
  role supports them. These controls limit impact but do not remove CVEs; native
  enforcement roles need their documented privileges.

## Release evidence and remaining automation

For each role, retain an SBOM and vulnerability report for the exact release
digest. Scan OS packages and every embedded executable. Compare before/after
with the same database and retain advisory timestamps. Check reachable use when
triaging findings, without suppressing package records merely to improve counts.

A release gate rejecting newly introduced fixable critical/high findings remains
planned; it is not yet established across all roles. Exceptions should identify
the affected digest, reason, owner and expiry. Scheduled rebuilds and pin-update
automation also remain open. New advisories require rescanning previously built
images, even when source code has not changed.

Before rollout, test the affected contracts: TLS and timezones for API services;
scan formats, database refresh, private registries and signature verification for
scanner tools; BPF/TC/NFQUEUE for native enforcement; backup/restore and upgrades
for infrastructure images. Canary each role, verify the running digest and keep
rollback artifacts.

Current measurements and deployment limits are recorded in the
[canonical parity plan](NEUVECTOR-PARITY-PLAN.md).

## Scanner acceptance

The scanner runtime bundles static Syft, Trivy, Grype, Cosign and ORAS binaries;
Git and the Debian package-management stack are absent. Cosign 3 verification is
checked against a legacy Cosign 2 signature and SLSA v1 attestation, plus a keyless
Distroless signature. Negative checks reject a different key, identity and
predicate. The attestation parser accepts verified in-toto v0.1/v1 statements and
multiple JSON envelopes, while rejecting malformed output and unknown versions.

Run `scripts/test-scanner-runtime.py --help` for required fixture and cache paths.
It compiles integration probes, runs them against the actual bundled binaries as
the image's normal user with a read-only root and dropped capabilities, and tests
both image scans and inventory-based matching. The fixture must contain known
vulnerabilities so an empty/broken result cannot pass. Use a disposable local
registry containing an image signed and attested with a test key; provide a
second public key for rejection checks. Cache paths must contain current DBs,
with the Grype cache writable by UID 10001. No Docker socket is mounted. `--docker-config` exercises a private registry using
a caller-provided test credential directory. The home directory remains read-only;
`TUF_ROOT` points into the same writable cache location used by the Helm chart.

`BAKE_VULN_DB=1` now prepares optional air-gap databases in a build stage. A failed
DB download fails that build instead of silently producing an unusable offline
image. The default remains runtime DB refresh or operator-preloaded caches.
