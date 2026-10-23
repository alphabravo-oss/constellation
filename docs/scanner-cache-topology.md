# Scanner cache topology and lifecycle

The chart supports two explicit cache modes. The default is one disk-backed
`emptyDir` per scanner pod, suitable for multiple replicas and autoscaling.
Persistent mode uses exactly one non-autoscaled scanner replica with a managed
or externally managed claim and the `Recreate` update strategy. It never silently
falls back to ephemeral storage.

## Upgrade existing persistent installations deliberately

Before upgrading, compare the rendered cache volume and claim name with the
existing release. The old chart defaulted `persistent=true` but silently selected
`emptyDir` for multiple replicas or autoscaling. The new default is explicitly
`false`, preserving the old two-replica default's actual storage behavior.
**An existing single-replica persistent installation must explicitly set
`scanner.cache.persistent=true`, keep `scanner.replicas=1` and disable autoscaling.**
Do not rely on the new default to preserve an old implicit PVC selection.

The old chart always named its managed claim `constellation-scanner-cache`.
For an installation using that claim, set
`scanner.cache.managedClaimName=constellation-scanner-cache` during upgrade.
This retains the managed resource's identity even when the Helm release has a
custom name. Omitting that override for a custom release can select a new empty
claim and remove the old resource. Back up/re-provisionable offline databases
before any storage transition; changing values does not copy cache contents.

Managed claims now request Helm retention by default. This does not retroactively
protect a claim removed from an older release manifest that lacks the keep policy.
First upgrade with the same managed claim name and retention enabled, verifying
the new release manifest and PVC. Only then consider changing ownership/mode.
Switching directly to `existingClaim` is not protection from Helm deleting a
previously managed resource. External claims must already exist in the release
namespace, be mountable and writable by the configured scanner UID/fsGroup, and
contain the required offline databases. Rendering does not inspect those facts.

The scanner Service now selects this release's pod label. The Deployment's
immutable selector remains unchanged. During the first upgrade, old pods lack
that label, so Service endpoints can be empty until replacement pods are ready.
Persistent deployments already use `Recreate` and require a planned scan-worker
interruption. No cluster rollout is performed by this source change.

## Ten implementation items

| Item | Contract |
| --- | --- |
| 1. Explicit pod-local default | `scanner.cache.persistent=false` selects `emptyDir`; the schema/editor default agrees with values.yaml. |
| 2. Persistent replica validation | Persistence requires exactly one replica. Invalid combinations fail rendering instead of selecting ephemeral storage. The existing schema minimum of one replica is preserved. |
| 3. Persistent autoscaling validation | Persistence rejects HPA enablement, including an HPA configured with a one-replica minimum. |
| 4. Disabled scanner lifecycle | Disabling the scanner renders no scanner Deployment, Service, HPA or managed cache PVC. Retention from a previous release must be handled as described above. |
| 5. Managed claim identity | New managed claims use `<fullname>-scanner-cache`; `managedClaimName` preserves an explicit/legacy identity. Deployment and claim use the same helper. |
| 6. External claims | `existingClaim` mounts an operator-owned claim without rendering or annotating a PVC. It requires persistence and conflicts with `managedClaimName`. Both persistent paths keep `Recreate`. |
| 7. Managed claim retention | `retain=true` adds `helm.sh/resource-policy: keep`; `false` opts back into Helm's ordinary resource lifecycle. Kept claims require explicit operator cleanup and can affect later reinstalls. |
| 8. Pod-local cache limits | `emptyDirSizeLimit` configures disk-backed cache storage. It is rejected with persistence, preventing an ignored limit. |
| 9. Extraction limits | `scanner.tmp.sizeLimit` separately configures disk-backed `/tmp` for either cache mode. No memory-backed cache is introduced. |
| 10. Release-specific scanner routing | Scanner pods carry the release instance label and the Service selects it, avoiding cross-release scanner endpoints. Existing Deployment selectors remain unchanged. This is not a claim that every chart component supports multiple releases in one namespace. |

## Examples

Pod-local caches (the default topology):

```yaml
scanner:
  replicas: 2
  cache:
    persistent: false
    emptyDirSizeLimit: 12Gi
  tmp:
    sizeLimit: 8Gi
```

Those example limits are inputs to size and test, not a measured safe Trivy/Grype
refresh budget. EmptyDir limits are kubelet-managed bounds, not reserved disk
space or engine-specific quotas. Size ephemeral-storage requests/limits through
`scanner.resources` for the combined writable layers, logs, cache and extraction
workload. Filesystem metrics do not prove an exclusive emptyDir quota. Leaving
limits empty preserves the prior unlimited-volume specification.

Managed persistence:

```yaml
scanner:
  replicas: 1
  autoscaling:
    enabled: false
  cache:
    persistent: true
    size: 16Gi
    storageClass: fast
    retain: true
    # For an existing legacy managed claim:
    # managedClaimName: constellation-scanner-cache
```

External persistence:

```yaml
scanner:
  replicas: 1
  autoscaling:
    enabled: false
  cache:
    persistent: true
    existingClaim: scanner-databases
```

`size`, `storageClass` and `retain` apply only to a chart-managed claim. They do
not resize, inspect or take ownership of an external claim. Optional emptyDir
limits accept positive integral Mi/Gi/Ti quantities. Cache path environment
variables and mount locations remain unchanged. Offline mode remains enabled by
default; changing cache topology does not enable internet downloads.

## Validation and remaining work

The render matrix checks defaults, persistent/external/legacy/custom-name claims,
retention on/off, scanner disablement, limits, HPA behavior, invalid configurations,
schema rejection and release-specific routing. The complete Helm smoke suite also
checks existing scanner ServiceMonitor selectors and capacity alerts. These are
manifest-level proofs, not live attachment, retention, eviction or restart tests.

DB-21's explicit topology implementation is available. Installation-specific
selection, PVC attachment/permissions, simultaneous refresh headroom, offline
pod replacement, live alerts and restart qualification remain open. Use the
[cache monitoring guide](scanner-cache-monitoring.md) and
[offline provisioning instructions](offline-scanning.md) when qualifying a rollout.

## October 23 local offline process-replacement qualification

`TestBundledPackageMatchersOffline` now exercises the current Trivy/Grype package
matcher wrappers with actual tools and preloaded databases. It is opt-in through
`CONSTELLATION_TEST_OFFLINE_MATCHERS=true`; the ordinary suite skips it explicitly.
Both cache paths must be configured. A known-vulnerable lodash 4.17.19 package is
matched twice per engine; finding identities must remain stable and a separate
empty cache must fail instead of returning a successful empty scan.

Local qualification compiled the current test into a static executable and ran
it in two successive fresh containers using the existing scanner image
`sha256:4cd3d0bbb98cd0e04ea1216518f76454593b1306aaed4f0718a530ab8d2e79f0`.
Both runs used `--network none`, a read-only container root, a 256 MiB writable
`/tmp`, two CPUs, a 2 GiB memory limit, and the image's UID 10001. The test used
isolated copies of the preloaded engine DB directories; it did not mount the
live scanner cache or replace the running scanner. The image's Grype reports
0.120.1-constellation.2 and the source commit pinned by scanner-tools/sources.json.

All five copied database files (4,954,046,907 bytes, approximately 4.61 GiB)
retained identical SHA-256 values after both runs. Both engines reported five
findings each with stable per-engine finding digests across process replacement.
The first complete test took 32.41 seconds and the second 5.80 seconds; the shared
host page cache affects these timings. These are a one-package fixture result,
not cold-host, full-image, sustained concurrency or p95/p99 performance results.
The missing-database assertions passed on both runs. Logs, before hashes and the
machine-readable result are in the October 23 lifecycle evidence directory. The
temporary containers and isolated cache copies were removed after verification.

To repeat, compile `go test -c ./internal/scanner` with `CGO_ENABLED=0`, mount the
binary read-only into the digest-pinned scanner image and mount a private writable
copy of the prepared cache. Set `TRIVY_CACHE_DIR`, `GRYPE_DB_CACHE_DIR`,
`CONSTELLATION_TEST_OFFLINE_MATCHERS=true`, `CONSTELLATION_SCANNER_OFFLINE_DB=true`
and `GRYPE_DB_AUTO_UPDATE=false`. Run only `^TestBundledPackageMatchersOffline$`
with networking disabled; remove that container and run a new one against the
same private cache. Compare finding digests and DB file hashes. Never point this
qualification at a live writable cache.

This closes the local package-matching/offline process-replacement rehearsal.
It does not prove Kubernetes PVC attachment, eviction behavior, simultaneous DB
refresh headroom, image extraction capacity or live notification delivery. The
existing 8 GiB cache request must not be declared sufficient from steady-state
DB bytes alone; archive download and replacement staging require additional room.
Publishing and live rollout remain deferred with Actions disabled.
