# Deployment — `docker compose` (single-VM)

The `docker-compose.yaml` at the repo root brings up the full Constellation control plane
on one Linux/macOS host. It is the recommended path for:

- **Sales / customer demos** — a 30-second boot of every service.
- **Single-VM dev** — laptop and t3.medium-class development.
- **End-to-end smoke** before promoting a build into the Helm chart.

For production multi-node deployments, use the Helm chart in
[`deploy/charts/constellation/`](../deploy/charts/constellation/). For systemd-on-bare-metal
deployments, use [`deploy/systemd/`](../deploy/systemd/).

---

## 30-second quickstart

```sh
make compose-images                # builds constellation/<role>:dev locally
docker compose --profile seed up -d
curl http://localhost:18080/healthz # → 200
open  http://localhost:3000        # SPA  (admin@demo.test / Constellation!1)
```

`make compose-images` pre-builds:

| Image                                | Role                                            |
| ------------------------------------ | ----------------------------------------------- |
| `constellation/api:dev`              | Control-plane HTTP API                          |
| `constellation/scanner:dev`          | In-cluster scanner worker (trivy+syft+grype)    |
| `constellation/operator:dev`         | K8s reconciler (idle in compose)                |
| `constellation/frontend:dev`         | Vite SPA in nginx                               |
| `constellation/seed:dev`             | One-shot demo data load                         |
| `constellation/discoverer:dev`       | K8s workload watcher                            |
| `constellation/scanner-driver:dev`   | Compose-native scanner (mounts docker.sock)     |
| `constellation/runtime-agent:dev`    | eBPF kernel data-plane                          |

The compose file references all images by these `:dev` tags so a fresh checkout boots
without internet pulls after the build step.

---

## Profiles

| Profile (none)                           | What you get                                                        |
| ---------------------------------------- | ------------------------------------------------------------------- |
| _default_                                | postgres, migrate, bootstrap-tokens, api, scanner, scanner-driver, operator, discoverer, frontend |
| `--profile seed`                         | _default_ + one-shot demo data load (`seed` service)                |
| `--profile runtime`                      | _default_ + `runtime-agent` (Linux host only)                       |
| `--profile cvedb`                        | _default_ + `vulndb-aggregator` (NVD / KEV / EPSS / OSV refresh)    |

Profiles compose:

```sh
docker compose --profile seed --profile cvedb up -d
```

---

## Service URLs

| Endpoint                  | URL                                  | Notes                              |
| ------------------------- | ------------------------------------ | ---------------------------------- |
| API healthz               | `http://localhost:18080/healthz`     | Liveness                           |
| API readyz                | `http://localhost:18080/readyz`      | Readiness (DB ping)                |
| API openapi               | `http://localhost:18080/openapi.json`| Generated OpenAPI 3.0              |
| Frontend SPA              | `http://localhost:3000/`             | nginx → built Vite SPA             |
| Postgres                  | `localhost:15433`                    | user/pw `constellation`            |

---

## Token bootstrap

`bootstrap-tokens` is a one-shot job that runs after `migrate`. It:

1. Connects to Postgres with `psql`.
2. Ensures the `demo` org exists.
3. Generates a random scanner token (`cst_<base64url>`) and a random runtime-agent
   token, inserts the sha256 hashes into `scanner_tokens` and `runtime_agent_tokens`.
4. Writes the raw tokens to a named volume `constellation-tokens` at:
   - `/run/constellation-tokens/scanner.token`
   - `/run/constellation-tokens/runtime-agent.token`
   - `/run/constellation-tokens/org.id`

`scanner`, `scanner-driver`, `runtime-agent`, and `discoverer` mount that volume
read-only and read the tokens at startup. **No dev secrets land in the repo or in
compose env values.**

The script is at [`deploy/docker/bootstrap-tokens.sh`](../deploy/docker/bootstrap-tokens.sh).
It is idempotent: re-running it leaves existing tokens in place unless they no longer
hash to a row in the DB.

---

## Scan a local Docker image (the killer demo)

`scanner-driver` bind-mounts the host's `/var/run/docker.sock`, so trivy/syft/grype can
read an image straight out of the local Docker daemon without re-pulling from a registry:

```sh
# 1. Pull an image with known CVEs into the host docker daemon.
docker pull nginx:1.14.2

# 2. Boot the stack.
docker compose --profile seed up -d

# 3. Log in and grab a JWT (admin@demo.test / Constellation!1).
TOKEN=$(curl -fsS http://localhost:18080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@demo.test","password":"Constellation!1"}' \
  | jq -r .access_token)

# 4. Enqueue a scan for the local image.
curl -fsS -X POST http://localhost:18080/api/v1/scan-jobs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"image_ref":"nginx:1.14.2"}'

# 5. Watch the driver pick it up. It runs every SCAN_INTERVAL (30s by default).
docker compose logs -f scanner-driver

# 6. Pull findings back.
curl -fsS http://localhost:18080/api/v1/findings \
  -H "Authorization: Bearer $TOKEN" | jq '.findings[] | {cve_id, severity, package}'
```

On the first scan trivy will download its vulnerability DB (~600 MB). Subsequent scans
reuse the cached DB inside the `constellation/scanner-driver:dev` image.

### Why a separate `scanner-driver` and `scanner`?

- `scanner` is the in-cluster worker. It receives a baked-in token and polls
  the API. We keep it in compose so the ops loop (`docker compose logs scanner`,
  `--scale scanner=N`) matches what Helm runs in production.
- `scanner-driver` is a compose-native variant that talks directly to Postgres (to mint
  its own short-TTL token per org) and to the docker daemon (for local-image scans).
  Use it when you want a single-VM demo without setting up a registry.

---

## Hot reload (Go + Vite)

```sh
docker compose -f docker-compose.yaml -f compose.dev.yaml up
```

This overlay swaps in `golang:1.26-bookworm` (image `constellation/go-dev:dev`) for the
Go services and runs `go run ./cmd/<role>` against a bind-mounted source tree. The Go
module + build caches are persisted in named volumes so warm rebuilds are 2–3 s.

For the frontend it replaces nginx with `npm run dev` (Vite) bound to `0.0.0.0:8080`.
HMR is exposed on port 24678; browser auto-refresh works end-to-end.

Migrations are bind-mounted RO so `goose up` on the host takes effect inside the stack
without rebuilding the images.

---

## Multi-cluster discovery

The default compose runs a single `discoverer`. To watch a real cluster:

```sh
KUBECONFIG_HOST_PATH=$HOME/.kube/config CLUSTER_NAME=dev-local \
  docker compose up -d discoverer
```

For multi-cluster, scale the service or use the Helm chart — see
`cmd/constellation-discoverer/main.go` for the supported env vars.

---

## Runtime agent (Linux host only)

```sh
docker compose --profile runtime up -d runtime-agent
```

The agent runs `privileged: true`, `pid: host`, `network_mode: host`, with capabilities
`NET_ADMIN`, `SYS_ADMIN`, `BPF`, `PERFMON`, `SYS_PTRACE`, and bind-mounts `/sys`,
`/sys/fs/bpf`, `/sys/kernel/btf`, `/proc`. It will not start on macOS / Windows hosts —
their Docker VM kernels do not expose BTF in the layout the loader expects.

---

## Vulnerability database refresh

```sh
docker compose --profile cvedb run --rm vulndb-aggregator
```

Pulls NVD + KEV + EPSS + OSV into the `cve` table in Postgres. The image is published
from the sibling [`constellation-vulndb`](https://github.com/alphabravocompany/constellation-vulndb)
repo. Pass an `NVD_API_KEY` env var to avoid the anonymous 50-req/30-s rate limit.

---

## Tear-down

```sh
docker compose down -v        # stops services + drops volumes (Postgres data lost)
docker compose down           # keep volumes (Postgres data preserved)
```

---

## Troubleshooting

- **`scanner-driver` keeps logging "no orgs have pending jobs"** — that's expected when
  the queue is empty; it polls every `SCAN_INTERVAL`. Enqueue a scan via the API to see
  it process.
- **`/var/run/docker.sock` permission denied on the host** — the driver runs as root,
  but on rootless docker the socket lives at `$XDG_RUNTIME_DIR/docker.sock`. Update the
  bind mount in `docker-compose.yaml`.
- **`runtime-agent` exits 2 with "BTF not found"** — Linux host kernel without
  `CONFIG_DEBUG_INFO_BTF=y`. Either run on a kernel that has it (Ubuntu 22.04+, Fedora
  37+) or skip the `--profile runtime`.
- **`discoverer` sleeps with "empty placeholder kubeconfig detected"** — that is the
  intentional no-op when no kubeconfig is bind-mounted. Set
  `KUBECONFIG_HOST_PATH=/path/to/kubeconfig` and re-up.
