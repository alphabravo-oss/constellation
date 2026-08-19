# Offline (Air-Gapped) Vulnerability Database Updates

This runbook explains how to keep the Constellation scanner's vulnerability
data current in an **air-gapped / offline** deployment, where the scanner pods
have **no internet access** and an operator must supply the databases by hand.

It applies to the two matchers Constellation runs today:

- **Trivy** — image vuln + secret + IaC/misconfig scanning
  (`internal/scanner/trivy.go`).
- **Grype** — the primary image vuln matcher *and* the host/platform package
  matcher (`internal/scanner/grype.go`, `internal/scanner/grype_matcher.go`).
  Grype fills the `PackageMatcher` slot for host/platform scans while the
  bundled `constellation-vulndb` engine is disabled.

> The scanner image ships the `trivy`, `grype`, and `oras` CLIs
> (`deploy/docker/Dockerfile.scanner`), so everything below runs inside the
> scanner container as well as on a normal admin workstation.

---

## 1. Overview — how vuln data flows offline

Online, the scanner refreshes its DBs itself: a background loop
(`cmd/constellation-scanner/dbrefresh.go`) periodically runs
`trivy image --download-db-only` and `grype db update`. **In offline mode this
loop is a no-op** — the scanner will never reach the internet, so *you* are
responsible for delivering fresh DBs on a cadence.

Offline mode also changes the scan-time invocation:

- **Trivy** runs with `--skip-db-update --skip-java-db-update`, so it uses only
  the local DB cache (or an internal OCI mirror, see below) and never phones
  home (`internal/scanner/trivy.go`).
- **Grype** runs with `GRYPE_DB_AUTO_UPDATE=false`, so it uses only the
  pre-loaded local DB (`grypeEnv` in `internal/scanner/grype_matcher.go`).

There are **two supported mechanisms** for getting data in:

| Engine | Mechanism | How the scanner consumes it |
| --- | --- | --- |
| **Trivy** | (a) Internal **OCI mirror** of `trivy-db` / `trivy-java-db` | `TRIVY_DB_REPOSITORY` / `TRIVY_JAVA_DB_REPOSITORY` point Trivy at your registry; `--skip-db-update` keeps it from updating |
| **Trivy** | (b) **File/archive import** into the Trivy cache dir | `TRIVY_CACHE_DIR=/tmp/trivy` (pre-populated) |
| **Grype** | (b) **File/archive import** into the Grype cache dir | `grype db import` / files under `GRYPE_DB_CACHE_DIR=/tmp/grype/db` |

Trivy supports **both** (a) and (b). Grype has no OCI-mirror mode, so it always
uses the file/archive path (b).

> **Cache-dir caveat (important).** The scanner deployment
> (`deploy/charts/constellation/templates/scanner-deployment.yaml`) points both
> cache dirs at an **ephemeral `emptyDir`**:
>
> - `TRIVY_CACHE_DIR=/tmp/trivy`
> - `GRYPE_DB_CACHE_DIR=/tmp/grype/db`
>
> The `emptyDir` is **wiped on every pod restart**. So for offline mode you must
> either persist these dirs (PVC) or re-load the DB on each start (baked image or
> init job). See [section 5](#5-getting-dbs-into-the-air-gapped-scanner-pods).

---

## 2. Enable offline mode

Set these Helm values (chart `deploy/charts/constellation`, key
`scanner.vulnDB`):

```yaml
scanner:
  vulnDB:
    # Air-gapped: disable the background refresh loop and add
    # --skip-db-update/--skip-java-db-update (Trivy) + GRYPE_DB_AUTO_UPDATE=false (Grype).
    offline: true

    # OPTIONAL — Trivy OCI mirror (mechanism a). Point Trivy at your internal
    # registry instead of ghcr.io. Leave empty to use the file-cache path only.
    trivyDBRepository: "registry.internal.example.com/mirror/trivy-db"
    trivyJavaDBRepository: "registry.internal.example.com/mirror/trivy-java-db"

    # refreshInterval is ignored while offline (the loop is a no-op), but leave
    # it as-is; it takes over again if you ever set offline: false.
    refreshInterval: 6h
```

What each value wires up (see `scanner-deployment.yaml`):

| Helm value | Env var on the pod | Effect |
| --- | --- | --- |
| `scanner.vulnDB.offline: true` | `CONSTELLATION_SCANNER_OFFLINE_DB=true` | Trivy `--skip-db-update --skip-java-db-update`; Grype `GRYPE_DB_AUTO_UPDATE=false`; refresh loop no-op |
| `scanner.vulnDB.trivyDBRepository` | `TRIVY_DB_REPOSITORY` | Trivy pulls its DB from this OCI repo |
| `scanner.vulnDB.trivyJavaDBRepository` | `TRIVY_JAVA_DB_REPOSITORY` | Trivy pulls its Java DB from this OCI repo |

`CONSTELLATION_SCANNER_OFFLINE_DB` accepts `1`, `true`, `yes`, or `on`
(`scannerOfflineDB()` in `internal/scanner/grype_matcher.go`).

> Offline mode can also be toggled at runtime from the UI (system_config
> `offline_db`, polled via `GET /api/v1/scanner/config`), which forces the
> refresh loop off even if the Helm value is `false`. The Helm value is the
> durable, declarative setting — prefer it.

Apply:

```bash
helm upgrade --install constellation deploy/charts/constellation \
  --namespace constellation \
  -f your-values.yaml
```

---

## 3. Trivy DB — internet-connected side

Do this on a machine (or CI runner) that **has** internet access, then move the
artifacts across the air gap.

### Option (a): mirror into an internal OCI registry (recommended for Trivy)

Trivy distributes its DBs as OCI artifacts. Pull them from GHCR and re-push them
to your internal registry with `oras` (already in the scanner image).

```bash
# 1. Pull the upstream Trivy DB artifacts (public GHCR).
oras pull ghcr.io/aquasecurity/trivy-db:2 \
  --output ./trivy-db
oras pull ghcr.io/aquasecurity/trivy-java-db:1 \
  --output ./trivy-java-db

# 2. Log in to your internal registry and push them in.
oras login registry.internal.example.com -u "$USER" -p "$TOKEN"

oras push registry.internal.example.com/mirror/trivy-db:2 \
  ./trivy-db/db.tar.gz:application/vnd.aquasec.trivy.db.layer.v1.tar+gzip

oras push registry.internal.example.com/mirror/trivy-java-db:1 \
  ./trivy-java-db/javadb.tar.gz:application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip
```

> Tip: if `oras pull` layer filenames differ for your Trivy version, run
> `oras manifest fetch ghcr.io/aquasecurity/trivy-db:2` to see the exact layer
> media type and blob, and match those on push. Simplest alternative: mirror the
> whole repo with a tool your registry already supports (Harbor proxy-cache,
> `skopeo copy`, `crane copy`) — the end state is the same OCI tag living in your
> internal registry.

With `scanner.vulnDB.trivyDBRepository` /
`trivyJavaDBRepository` set to those internal repos (section 2), the scanner
pulls the DB from your registry and — because offline mode adds
`--skip-db-update --skip-java-db-update` — never tries to update it afterward.
**This path is already fully wired**; no per-pod file copy needed for Trivy.

### Option (b): export the Trivy cache and import it as files

If you don't want to run an OCI mirror, ship the whole Trivy cache dir instead.

```bash
# On the connected side: download only the DB into a known cache dir.
TRIVY_CACHE_DIR=./trivy-cache trivy image --download-db-only --quiet
TRIVY_CACHE_DIR=./trivy-cache trivy image --download-java-db-only --quiet

# Package it for transfer.
tar -czf trivy-cache.tgz -C ./trivy-cache .
```

Transfer `trivy-cache.tgz` across the air gap and unpack it into the pod's
`TRIVY_CACHE_DIR` (`/tmp/trivy`) — see [section 5](#5-getting-dbs-into-the-air-gapped-scanner-pods).

---

## 4. Grype DB — internet-connected side

Grype has no OCI-mirror mode, so always use the file/archive path.

```bash
# 1. Update Grype's DB into a known cache dir.
GRYPE_DB_CACHE_DIR=./grype-cache grype db update

# 2. Find where the DB landed (prints the cache path + build/checksum).
GRYPE_DB_CACHE_DIR=./grype-cache grype db status
#   Location:  ./grype-cache/<schema-version>/
#   Built:     ...
#   Status:    valid

# 3. Archive the DB directory that `db status` reported.
tar -czf grype-db.tgz -C ./grype-cache .
```

Transfer `grype-db.tgz` across the air gap. On the offline side you have two
equivalent ways to install it:

```bash
# Preferred: let Grype import the archive into its cache.
GRYPE_DB_CACHE_DIR=/tmp/grype/db grype db import ./grype-db.tgz

# Or: unpack the directory straight into the cache dir.
mkdir -p /tmp/grype/db
tar -xzf grype-db.tgz -C /tmp/grype/db
```

Verify:

```bash
GRYPE_DB_CACHE_DIR=/tmp/grype/db GRYPE_DB_AUTO_UPDATE=false grype db status
```

---

## 5. Getting DBs into the air-gapped scanner pods

The scanner's cache dirs live on an **ephemeral `emptyDir`** that is wiped on
pod restart (see the caveat in section 1). Pick one of the strategies below so
the DBs survive restarts and land in `/tmp/trivy` and `/tmp/grype/db`.

For **Trivy specifically**, using the OCI mirror (section 3a) sidesteps this
entirely — the DB is re-pulled from your internal registry on demand. The
strategies below matter most for **Grype** (and for Trivy if you chose the file
path).

### Option A — bake the DBs into a custom scanner image (simplest, static)

Extend the scanner image and pre-load the DBs at a path that isn't the
ephemeral `emptyDir`, then copy them into place at start. The stock Dockerfile
already pre-warms both DBs at build time (`trivy image --download-db-only`,
`grype db update` in `deploy/docker/Dockerfile.scanner`) — but those land under
the build user's home, and the Helm deployment overrides the cache dirs to
`/tmp`, so you must copy on start:

```dockerfile
FROM registry.internal.example.com/constellation/scanner:<tag>
# Bake DBs into a non-ephemeral path.
COPY trivy-cache /opt/vulndb/trivy
COPY grype-db    /opt/vulndb/grype
```

Then wrap startup (via `scanner.args`/entrypoint or an init step) to
`cp -a /opt/vulndb/trivy/* /tmp/trivy/` and
`cp -a /opt/vulndb/grype/* /tmp/grype/db/` before the scanner starts.

**Downside:** DB freshness is tied to image rebuilds. Fine for slow cadences,
awkward for weekly refreshes.

### Option B — mount a PVC for the cache dirs and pre-populate it (recommended)

Mirror the existing vulndb PVC pattern in the chart
(`deploy/charts/constellation/templates/vulndb-pvc.yaml`,
`vulndb.storage.type: pvc`). Give the scanner a durable volume for its caches so
a pod restart keeps the DBs.

1. Create a PVC (RWX if you run more than one scanner replica):

   ```yaml
   apiVersion: v1
   kind: PersistentVolumeClaim
   metadata:
     name: constellation-scanner-vulndb-cache
     namespace: constellation
   spec:
     accessModes: [ReadWriteMany]
     resources:
       requests:
         storage: 5Gi
     # storageClassName: <your-rwx-class>
   ```

2. Mount it over the cache dirs. The stock deployment mounts an `emptyDir`
   named `tmp` at `/tmp`; the cleanest override is to add the scanner cache
   subpaths from your PVC. If you fork the chart, replace the `tmp` `emptyDir`
   volume for the scanner with:

   ```yaml
   volumes:
     - name: db-cache
       persistentVolumeClaim:
         claimName: constellation-scanner-vulndb-cache
   # ...
   volumeMounts:
     - name: db-cache
       mountPath: /tmp/trivy
       subPath: trivy
     - name: db-cache
       mountPath: /tmp/grype/db
       subPath: grype
   ```

   (Keep a writable `/tmp` for scratch — e.g. leave the `emptyDir` mounted at
   `/tmp` and mount the PVC subpaths *over* the two DB dirs.)

3. Pre-populate the PVC once, then refresh on cadence, with a short Job that
   mounts the same PVC and unpacks the transferred archives:

   ```yaml
   apiVersion: batch/v1
   kind: Job
   metadata:
     name: scanner-db-load
     namespace: constellation
   spec:
     template:
       spec:
         restartPolicy: Never
         containers:
           - name: load
             image: registry.internal.example.com/constellation/scanner:<tag>
             command: ["/bin/sh", "-c"]
             args:
               - |
                 set -eux
                 mkdir -p /cache/trivy /cache/grype
                 tar -xzf /import/trivy-cache.tgz -C /cache/trivy
                 GRYPE_DB_CACHE_DIR=/cache/grype grype db import /import/grype-db.tgz
             volumeMounts:
               - { name: db-cache, mountPath: /cache }
               - { name: import,   mountPath: /import, readOnly: true }
         volumes:
           - name: db-cache
             persistentVolumeClaim:
               claimName: constellation-scanner-vulndb-cache
           - name: import
             configMap:            # or a secret / preloaded PVC holding the archives
               name: scanner-db-archives
   ```

   Re-running this Job (e.g. after each transfer) is how you refresh offline.

### Option C — initContainer that imports the DB on start

If you'd rather not manage a separate Job, add an `initContainer` to the
scanner pod that unpacks the archives into the shared `tmp`/cache volume before
the scanner container starts. Same commands as Option B's Job; the tradeoff is
the import runs on every pod start (so keep the archive small / local).

---

## 6. Verification and refresh cadence

### Confirm offline mode is active

```bash
# Env is set on the running pod.
kubectl -n constellation exec deploy/constellation-scanner -- \
  sh -c 'env | grep -E "OFFLINE_DB|TRIVY_DB_REPOSITORY|TRIVY_CACHE_DIR|GRYPE_DB_CACHE_DIR"'
```

You should see `CONSTELLATION_SCANNER_OFFLINE_DB=true` and the cache dirs
(`/tmp/trivy`, `/tmp/grype/db`).

### Confirm the DBs are present and valid

```bash
kubectl -n constellation exec deploy/constellation-scanner -- \
  sh -c 'GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_CACHE_DIR=/tmp/grype/db grype db status'

kubectl -n constellation exec deploy/constellation-scanner -- \
  sh -c 'TRIVY_CACHE_DIR=/tmp/trivy trivy image --skip-db-update --skip-java-db-update --download-db-only --quiet; echo "trivy DB ok"'
```

### Run a test scan offline

Scan a known image and confirm findings come back **without** any network DB
pull in the logs:

```bash
# Grype (should NOT log a DB download).
kubectl -n constellation exec deploy/constellation-scanner -- \
  sh -c 'GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_CACHE_DIR=/tmp/grype/db grype <some-image-in-your-registry> -o json -q | head'

# Trivy (offline flags mirror what the scanner passes).
kubectl -n constellation exec deploy/constellation-scanner -- \
  sh -c 'TRIVY_CACHE_DIR=/tmp/trivy trivy image --skip-db-update --skip-java-db-update --format json --quiet <some-image-in-your-registry> | head'
```

Then check the scanner logs — a healthy offline scanner logs scan activity but
**no** "vuln DB refreshed" / download lines (that log comes from the refresh
loop, which is suppressed offline — `refreshVulnDBs` returns early when
`offline` is true, `cmd/constellation-scanner/dbrefresh.go`):

```bash
kubectl -n constellation logs deploy/constellation-scanner --tail=100
```

### Refresh cadence

Because the auto-refresh loop is disabled offline, **you** must repeat the
transfer periodically (recommended: at least weekly, matching how often upstream
Trivy/Grype publish DBs). For each refresh:

1. On the connected side, re-run section 3 (Trivy) and section 4 (Grype).
2. Transfer the new archives / re-push the OCI tags.
3. Install them:
   - **OCI mirror (Trivy):** re-push the tag; scanners pick it up on the next
     scan with no restart needed.
   - **PVC (Option B):** re-run the `scanner-db-load` Job. No pod restart needed
     if the scanner reads the DB per-scan; restart if you want to be certain.
   - **Baked image (Option A):** rebuild and roll the deployment.
4. Verify with the checks above.

> Staleness is the main offline risk: an old DB silently misses new CVEs. Track
> the DB build date (`grype db status` "Built", Trivy DB metadata) and alert if
> it exceeds your refresh SLA.
