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

The tagged release workflow gates each of its 12 image roles before promoting a
versioned tag or signing the image. It publishes a candidate, scans its immutable
OCI digest with checksum-pinned Grype 0.120.1, and rejects any fixable Critical or
High finding. Unfixed findings and lower severities remain in the retained JSON
report. There is currently no suppression or exception override.

The gate requires a valid database built within five days, the exact requested
image and configuration digest, and one linux/amd64 runtime. Additional platforms
require separate scan coverage. Scan failures, filtered reports, and suppressed
matches fail closed. Promotion revalidates the report and its SHA-256 receipt,
refuses to overwrite a different release digest, and verifies the resulting tag.
Failed candidates can remain in the registry; they receive no versioned release
tag through this workflow. The chart waits for every image job to succeed.

This gate applies to the tagged release workflow, not the development publisher.
Development rollouts still require their recorded scan and validation checks.
Local tests cover passing and rejected real frontend images; a remote tagged
release run has not yet exercised the new workflow. Scheduled rebuilds and
pin-update automation remain open. New advisories require rescanning previously
built images, even when source code has not changed.

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

## Patched scanner tool builds

The scanner Dockerfile rebuilds Syft 1.54.1, Grype 0.120.1 and Cosign 3.1.3
from checksum-pinned upstream source modules with Go 1.26.9. Their upstream
release binaries still embed vulnerable Go runtimes/dependencies. Reviewed
`go.mod`/`go.sum` locks update x/net to 0.60.0 and Cosign's gRPC to 1.83.2;
transitive x/* upgrades follow the module graph. Versions carry a
`-constellation.1` suffix and the upstream source commit remains recorded.

See [source locks and rebuild procedure](../deploy/docker/scanner-tools/README.md).
This changes actual embedded code and preserves package evidence. It does not
suppress advisories or relabel vulnerable dependency versions. Trivy and ORAS
retain checksum-verified upstream binaries. The release-check CLI installer is
separate and still uses the pinned upstream Grype binary.

The Helm 124 deployment passes real-tool acceptance and a queued production scan
with Syft, Grype and Trivy successful. Same-database standalone Grype counts drop
from 9 Critical / 48 High to 0 Critical / 1 High. The combined live scan retains
5 High records without listed fixes; these are not the same measurement as the
standalone Grype comparison. Exact identities and evidence are recorded in
`deploy/dev/registry-release/validation-scanner-tools-20261019.json`.

## Frontend runtime refresh (2026-10-19)

The frontend Dockerfile updates libexpat, zlib, libx11, and libxpm from its
configured signed Alpine repositories during the runtime build, then restores UID
101. This catches fixes published after the nginx base image. The deployed refresh
preserves the existing SPA bytes and nginx configuration. Minimum fixed versions
are encoded in the Dockerfile; the resulting release is pinned by image digest.

Using the same Grype database built 2026-10-19T06:39:15Z, the original frontend
image had 3 High and 8 Medium findings; the refreshed image had 0 High and 3 Medium.
The three remaining records are CVE-2025-60876 on busybox, busybox-binsh, and
ssl_client 1.37.0-r31. The configured Alpine repository had no newer BusyBox build.
They remain visible and unsuppressed. Alpine's tracker lists this version as
possibly vulnerable: https://security.alpinelinux.org/vuln/CVE-2025-60876.

Earlier six-finding live results used a different database vintage and are not the
before/after comparison. New advisories for X11/Xpm became visible after refreshing
Grype. Exact image digests, database metadata, package versions and validation are
recorded in the development release evidence.

## Static Kubernetes service runtimes

Discoverer, admission, and operator use the same digest-pinned Distroless static
Debian 13 base as the API. Their Go builds disable CGO and embed timezone data,
including legacy location aliases. The operator image also carries the network
policy applier and Kubernetes compliance collector; all three executables must
remain static. CA roots come from the base image. Account files and an empty
home are copied from the build stage, without shipping a shell, package manager,
or account-management utilities.

All three images run as UID/GID 10001, matching the chart's security context.
Discoverer's standalone image previously used Debian's dynamically assigned
system-account UID; external bind mounts relying on that UID must be adjusted.
These images support in-cluster service-account authentication. Custom kubeconfig
exec authentication requires a separately supplied executable; the minimal images
do not bundle cloud-provider login utilities.

Validate every executable and the affected Kubernetes workflows before rollout.
The native runtime-agent needs networking tools and libraries and is not covered
by this static-runtime conversion. Removing OS packages does not remove findings
in embedded Go modules; retain those findings and rebuild with reviewed fixes.

### Builds on the development Kubernetes node

This development workspace shares a filesystem with Kubernetes. Check available
space and the kubelet's eviction settings before large builds or scans. Reserve
the eviction threshold **plus minimum reclaim**, then add the expected build and
scan scratch-space budget; the recovery requirement can be much higher than the
threshold that first triggers eviction. On the current node these settings are
5% eviction and 10% minimum reclaim, with a five-minute pressure transition.
A successful image build is not evidence that the node has adequate capacity.

Prefer a separate builder. On the shared node, stop builds if disk pressure is
reported. Reclaim regenerable compiler/module and unused Docker build caches;
preserve application volumes, backup data, image rollback artifacts and scan
evidence. Verify node pressure clears and database, storage, controllers, API,
scanner and runtime agents recover before starting another rollout.

The `Static runtime candidates` workflow builds discoverer, admission and operator
on GitHub-hosted runners. It runs for changes to those Dockerfiles, module pins or
the workflow on main/implementation branches, and supports manual dispatch. Each
artifact contains an OCI archive and source/digest identity, with build provenance
and an SBOM. The workflow has read-only repository permissions and does not
publish or deploy. Download the artifacts for runtime checks, publish their exact
digests using the development publisher, then run the image gate and rollout
validation. Changes elsewhere in application source require manual dispatch when
no matching path triggered the workflow.

The first hosted rollout is Helm 127. Live scans reduced discoverer from 255 to
zero findings, admission from 256 to one informational finding, and operator
from 256 to zero. All three scan engines succeeded for each image. Exact image
identities, package counts, remaining advisory and runtime checks are recorded in
`deploy/dev/registry-release/validation-static-runtimes-20261019.json`.

## Migration runtime hardening

The migration image builds Goose v3.27.1 with Go 1.26.9, verifies the upstream
module archive checksum, and applies the checked-in `deploy/docker/goose` module
locks. The PostgreSQL-only build excludes unused database drivers and their
transitive dependencies. Dependency locks also pin patched x/net, x/text and gRPC
versions; builds use `-mod=readonly`.

The runtime uses digest-pinned Alpine 3.24, refreshes its signed distribution
packages and runs as UID/GID 10001. Shell and psql remain available for existing
operator workflows. Alpine 3.20 in the previous image is beyond normal support;
a passing fixable-Critical/High gate alone does not establish complete coverage
for an end-of-life distribution. See [Alpine's support table](https://alpinelinux.org/releases/).

The hosted `Scanner lease candidates` migration job tests the actual OCI runtime
against a disposable PostgreSQL database: fresh upgrade, idempotent repeat,
migration 184 rollback and reapply. It uses a read-only root filesystem and drops
all capabilities. This recipe is shared by development and tagged releases;
publication still requires an immutable-image vulnerability gate, and tagged
release workflow acceptance remains separate from development deployment evidence.
