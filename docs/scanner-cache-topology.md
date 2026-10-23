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
