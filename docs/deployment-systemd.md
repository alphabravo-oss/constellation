# Deploying Constellation as native systemd services

This is the "no-Docker, no-Kubernetes" install path. Use it for:

- **Airgap environments** where pulling container images is impractical.
- **FIPS-validated hosts** where the OS-blessed Go toolchain + libc must own the binaries
  (no glibc-musl mixing, no scratch base images).
- **Regulated shops** whose change-management requires plain RPM/DEB-style binaries
  managed by the OS init system, with `journalctl` as the audit trail.
- **Edge nodes** that already run a hardened image and can't bring in Docker / containerd.

For Kubernetes deployments, see `deploy/charts/constellation/` (Helm). For local-dev with
Docker, see `docker-compose.yaml`. This document is strictly the systemd path.

---

## Quickstart

```bash
git clone https://github.com/alphabravocompany/constellation
cd constellation/deploy/systemd
sudo bash install.sh --from-source
```

The installer is interactive: it asks which roles to enable, prompts for `DATABASE_URL`,
generates `JWT_KEYS` and scanner/runtime-agent tokens, and `systemctl enable --now`s the
selected units. A 30-second active-state check runs per unit.

Non-interactive / scripted install:

```bash
sudo bash install.sh --from-source --non-interactive \
  --roles=api,scanner,discoverer \
  --database-url='postgres://constellation:secret@db.internal:5432/constellation?sslmode=require' \
  --listen-addr=:8080
```

---

## Roles

| Role | Unit file | Use when |
|---|---|---|
| `api` | `constellation-api.service` | Always — the control plane. |
| `scanner` | `constellation-scanner.service` / `@N.service` | Image scan workers (Syft+Trivy+Grype). |
| `operator` | `constellation-operator.service` | **Kubernetes-only.** No-op on pure-systemd hosts; the unit exists for hybrid deployments where you still want a uniform install story. |
| `runtime-agent` | `constellation-runtime-agent.service` | Per-host eBPF data plane (exec/network/file events). |
| `discoverer` | `constellation-discoverer.service` / `@<cluster>.service` | One per Kubernetes cluster you want inventoried. |
| `audit-archiver` | `constellation-audit-archiver.service` + `.timer` | Daily archive of audit log to S3 with cosign signature. |
| `scanner-driver` | `constellation-scanner-driver.service` | Out-of-cluster scan harness; useful when the in-cluster scanner pool is offline or absent. |

Scaling the scanner pool — use the templated unit and start N instances:

```bash
sudo systemctl enable --now constellation-scanner@1.service
sudo systemctl enable --now constellation-scanner@2.service
sudo systemctl enable --now constellation-scanner@3.service
```

Multiple clusters for the discoverer:

```bash
sudo cp /etc/constellation/discoverer.env /etc/constellation/discoverer-prod-us.env
sudo cp /etc/constellation/discoverer.env /etc/constellation/discoverer-edge-eu.env
# edit each, then:
sudo systemctl enable --now constellation-discoverer@prod-us.service
sudo systemctl enable --now constellation-discoverer@edge-eu.service
```

---

## Postgres prerequisite

Constellation requires Postgres ≥ 14 with the `pgvector` extension.

### Ubuntu / Debian

```bash
sudo apt-get install -y postgresql-16 postgresql-16-pgvector
sudo systemctl enable --now postgresql
sudo -u postgres psql -c "CREATE USER constellation WITH PASSWORD 'changeme';"
sudo -u postgres psql -c "CREATE DATABASE constellation OWNER constellation;"
sudo -u postgres psql -d constellation -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

### RHEL / Rocky / Alma 9

```bash
sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm
sudo dnf install -y postgresql16-server postgresql16-contrib pgvector_16
sudo /usr/pgsql-16/bin/postgresql-16-setup initdb
sudo systemctl enable --now postgresql-16
sudo -u postgres psql -c "CREATE USER constellation WITH PASSWORD 'changeme';"
sudo -u postgres psql -c "CREATE DATABASE constellation OWNER constellation;"
sudo -u postgres psql -d constellation -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

### SLES 15

```bash
sudo zypper -n in postgresql16-server postgresql16-contrib postgresql16-pgvector
sudo systemctl enable --now postgresql
sudo -u postgres psql -c "CREATE USER constellation WITH PASSWORD 'changeme';"
sudo -u postgres psql -c "CREATE DATABASE constellation OWNER constellation;"
sudo -u postgres psql -d constellation -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

### External Postgres

Set the `DATABASE_URL` in `install.sh --database-url=...` to point at the external server.
Required permissions: `CREATE`/`USAGE` on the target schema and ability to install the
`vector` extension (typically `postgres` superuser does this once).

---

## Env file reference

All env files live under `/etc/constellation/` (mode 0640, owner root, group `constellation`).

### `api.env` — `constellation-api.service`

| Variable | Required | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | yes | – | Postgres connection URL. |
| `JWT_KEYS` | yes | – | Comma-list of signing keys (≥32B each); first = active signer; install.sh generates 48 random bytes hex-encoded. |
| `LISTEN_ADDR` | no | `:8080` | HTTP bind address. |
| `JWT_ISSUER` | no | `constellation` | JWT `iss` claim. |
| `JWT_AUDIENCE` | no | `constellation-api` | JWT `aud` claim. |
| `JWT_TTL` | no | `1h` | Token lifetime. |
| `CORS_ORIGINS` | no | `http://localhost:5173` | Comma-list. |
| `ASTRONOMER_JWKS_URL` | no | – | External JWKS for SSO. |
| `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URL` | no | – | OIDC SSO (set all four to enable). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | – | OpenTelemetry collector. |

### `scanner.env` — `constellation-scanner.service`

| Variable | Required | Default | Notes |
|---|---|---|---|
| `CONSTELLATION_CONTROL_PLANE_URL` | yes | – | Where the API is. |
| `CONSTELLATION_SCANNER_TOKEN` | yes | – | Bearer token registered with the API. |
| `CONSTELLATION_SCANNER_MAX_CONCURRENT` | no | `1` | Concurrent scans cap; set `0` to auto-size from CPU count after memory is sized. |
| `XDG_CACHE_HOME`, `TRIVY_CACHE_DIR`, `GRYPE_DB_CACHE_DIR` | no | `/var/lib/constellation/.cache/...` | Persist scanner DBs across restarts. |

### `runtime-agent.env` — `constellation-runtime-agent.service`

| Variable | Required | Default | Notes |
|---|---|---|---|
| `CONSTELLATION_API_URL` | yes¹ | – | Control-plane URL. |
| `RUNTIME_AGENT_TOKEN` | yes¹ | – | Bearer token. |
| `CONSTELLATION_BPF_OBJ` | yes | `/opt/constellation/runtime.bpf.o` | eBPF object compiled by the build. |
| `CONSTELLATION_BATCH_SIZE` | no | `200` | Max events per POST. Cap: 1000. |
| `CONSTELLATION_BATCH_INTERVAL_MS` | no | `2000` | Flush interval. |
| `CONSTELLATION_NODE_NAME` | no | `$HOSTNAME` | Node label on events. |
| `CONSTELLATION_LOG_EVERY` | no | `50` | One log line per N events. |

¹ Without these, the agent runs in stdout-only mode (no upload). Useful for debug.

### `discoverer.env` — `constellation-discoverer[@cluster].service`

| Variable | Required | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | yes | – | |
| `KUBECONFIG` | yes | – | |
| `CLUSTER_NAME` | yes | – | Must match a `clusters.name` row. |
| `ORG_ID` | yes | – | UUID of owning org. |
| `NAMESPACE_FILTER` | no | `*` | Comma-list globs; `kube-system` always excluded. |
| `RECONCILE_INTERVAL` | no | `30s` | |
| `ONE_SHOT` | no | `false` | Single pass + exit (integration tests). |

### `audit-archiver.env` — `constellation-audit-archiver.service`

| Variable | Required | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | yes | – | |
| `AUDIT_BUCKET` | yes (unless dry-run) | – | S3 / S3-compatible bucket. |
| `AUDIT_PREFIX` | no | `audit` | Object key prefix. |
| `FREEZE_WINDOW` | no | `24h` | Window per run. |
| `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_ENDPOINT_URL_S3` | as required by SDK | – | |
| `COSIGN_KEY`, `COSIGN_PASSWORD`, `COSIGN_EXPERIMENTAL` | one of | – | Cosign signing config. |

### `scanner-driver.env` — `constellation-scanner-driver.service`

| Variable | Required | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | yes | – | |
| `API_URL` | yes | `http://localhost:18080` | Control-plane URL. |
| `SCANNER_DRIVER_MAX` | no | `50` | Max jobs per tick. |
| `SCANNER_DRIVER_JOB_TIMEOUT` | no | `8m` | Per-image timeout. |

### `operator.env` — `constellation-operator.service` (k8s-only)

| Variable | Required | Default |
|---|---|---|
| `KUBECONFIG` | yes | – |
| `OPERATOR_METRICS_ADDR`, `OPERATOR_PROBE_ADDR`, `OPERATOR_NAMESPACE`, `OPERATOR_AGENT_IMAGE` | no | see binary `--help` |

---

## JWT_KEYS rotation

`JWT_KEYS` accepts a comma-separated list of keys. The **first** entry is the active
signer; **all** entries are accepted as verifiers. To rotate without downtime:

1. Generate a new key: `openssl rand -hex 48`.
2. Prepend it to `JWT_KEYS` in `/etc/constellation/api.env`:
   ```
   JWT_KEYS=<NEW>,<OLD>
   ```
3. `sudo systemctl restart constellation-api` (or `bash reconfigure.sh api`).
4. Wait until the longest possible token lifetime (`JWT_TTL`, default 1h) plus a safety
   margin so all old tokens have expired.
5. Remove `<OLD>` from `JWT_KEYS`, restart again.

---

## Scanner / runtime-agent token rotation

The tokens generated by `install.sh` are random 32-byte hex strings. Each must be
registered with the API once (the scanner-token table). To rotate:

1. Issue a new token:
   ```bash
   /usr/local/bin/constellationctl tokens issue scanner --org <org-id>
   # or for runtime: ... issue runtime-agent --org <org-id>
   ```
2. Update the corresponding env file with the new value.
3. `sudo systemctl restart <unit>`.
4. Revoke the old token via the API.

---

## Inspecting logs

```bash
journalctl -u constellation-api -f                      # follow
journalctl -u constellation-api --since "10 min ago"    # window
journalctl -u 'constellation-scanner@*' -f              # all scanner instances
journalctl --user -u constellation-api -f               # user-mode install
```

Service stdout/stderr both flow into the journal (`StandardOutput=journal`).

---

## Upgrade procedure

```bash
cd /path/to/constellation
git pull
sudo bash deploy/systemd/install.sh --upgrade
```

`--upgrade` rebuilds binaries, drops them into `/usr/local/bin`, and re-`daemon-reload`s
systemd. **Env files are not overwritten** (operator edits preserved). Each enabled unit
is restarted by `enable --now` (a no-op for already-enabled units except that the new
binary takes effect at the next restart — the installer triggers that for you).

---

## Firewall guidance

| Port | Direction | Who | Purpose |
|---|---|---|---|
| 8080/tcp | in | dashboards, agents | constellation-api HTTP |
| 8443/tcp | in | k8s apiservers | admission webhook (only if `constellation-admission` is run) |
| 8090/tcp | in | prometheus | scanner /metrics + healthz |
| 8081/tcp, 8082/tcp | in | prometheus | operator metrics + probes (k8s only) |
| 5432/tcp | out | postgres | DB |
| 443/tcp  | out | S3/registry | audit archive, image pulls |

Sample `firewalld` for an api-only host:

```bash
sudo firewall-cmd --add-port=8080/tcp --permanent
sudo firewall-cmd --reload
```

---

## SELinux

On RHEL/Rocky with SELinux in `enforcing`, the runtime-agent's eBPF + ambient-capability
behaviour can trip `bpf_t` and `cap_sys_admin` denials. The default `unconfined_service_t`
domain often suffices, but a hardened MLS host needs a policy module. Workflow:

```bash
# 1. Switch to permissive briefly to collect AVCs.
sudo setenforce 0
sudo systemctl restart constellation-runtime-agent
# generate some traffic, then:
sudo ausearch -m AVC --start recent | sudo audit2allow -M constellation-runtime
# Inspect constellation-runtime.te. It will look roughly like:
#   require { type init_t, bpf_t; class bpf { prog_load map_create ... }; }
#   allow init_t self:bpf { prog_load map_create ... };
sudo semodule -i constellation-runtime.pp
sudo setenforce 1
```

The other services (`api`, `scanner`, `discoverer`, `audit-archiver`) typically run clean
under stock `targeted` policy.

---

## Uninstall

```bash
sudo bash deploy/systemd/uninstall.sh             # stop+disable, keep data
sudo bash deploy/systemd/uninstall.sh --purge     # also wipe env, /var/lib, user, binaries
```
