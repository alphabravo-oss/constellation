# Development

## Start on a fresh development machine

The verified build profile is **Linux/amd64** with Git, GNU Make, a C compiler
(for Go race tests), curl, tar/xz, Docker Engine with Buildx/Compose, Go **1.27.4**
(from `go.mod`), Node **24.22.0** (from `.node-version`) and npm **11.19.1**
(the frontend manifest requires at least 11.19.0).
Install those prerequisites using your normal host provisioning. Helm **4.3.1**
is also needed for chart checks; Playwright installs its own browser dependencies.
Other host architectures need separate native/tool qualification.

```sh
git clone https://github.com/alphabravo-oss/constellation.git
cd constellation
export PATH="$HOME/.local/bin:$(go env GOPATH)/bin:$PATH"
make tools
bash scripts/install-ci-tools.sh air
go mod download
npm --prefix frontend ci --strict-peer-deps
make build tools-build
make check
npm --prefix frontend test -- --maxWorkers=2
make test-integration
```

The source, SQL migrations, password corpus, vendored dataplane, BPF source/header,
Go module checksums, npm lockfile, Dockerfiles, Helm chart and current
[working plan](../PLAN.md) are tracked in Git. No sibling VulnDB checkout,
Go workspace, old worktree, copied `node_modules`, prebuilt binary or private
session helper is required. `make` explicitly uses `GOWORK=off`. Initial bootstrap
needs access to GitHub, Go/npm registries and container/package repositories;
this procedure does not claim disconnected-install qualification.

`make build` produces the Go programs; native enforcement assets have their own
build recipes. `make image-runtime-agent` builds the BPF object and vendored C
dataplane as well as the Go agent. For BPF-only host development, install clang
with a BPF target and libbpf headers, then run
`make -C internal/runtime/ebpf/bpf`. The committed `vmlinux.h` is sufficient for the
normal build; bpftool is needed only when deliberately regenerating that header.
The ignored `.o` file is generated output. Building these assets does not qualify
privileged execution or enforcement on a new kernel/CNI profile.

The [fresh-checkout receipt](verification/fresh-checkout-2026-11-14.json) records
what was actually rebuilt from GitHub with empty container dependency/build
caches. After cloning, read [AGENTS.md](../AGENTS.md), [CLAUDE.md](../CLAUDE.md) and
[PLAN.md](../PLAN.md) to continue the current work. Historical branches and archived
plans are not instructions to restore retired implementations.

## Preserve state separately from source

A Git clone restores the development source and work queue. It does not restore
a running installation's PostgreSQL data/WAL, object-store archives, evidence,
private signing/encryption keys, registry/OIDC credentials, Kubernetes secrets,
or a developer's `.env.dev.local`. Keep those in protected backups and the
appropriate secret store. Restoring encrypted data requires its original keys;
a newly generated development key cannot decrypt the old values. See
[database recovery](cnpg-recovery.md) and the [deployment guide](deployment-helm.md).

Generated binaries, dependency caches and local logs are intentionally ignored.
The plan and committed receipts retain results, source references and limitations;
raw historical qualification logs under `/root/constellation-*` remain local
artifacts and need a separate durable archive if their original bytes must survive
loss of this host. They are not inputs to the build. No off-host state recovery is
claimed by the fresh-checkout build verification.

## One-command dev loop

```sh
make dev        # scripts/dev.sh up
make dev-logs   # tail everything (or: scripts/dev.sh logs api|operator|scanner|web|compose)
make dev-down
```

`scripts/dev.sh up`:

1. checks for `docker go air node npx` and prints install hints for anything missing;
2. loads `.env.dev` (tracked defaults) then `.env.dev.local` (gitignored; auto-created from
   `.env.dev` on first run — put your overrides there);
3. starts `deploy/dev/compose.yaml`: pgvector Postgres 16 on `:15432`, Prometheus `:9090`,
   Tempo `:3200` (OTLP gRPC `:4317`), Loki `:3100`, Grafana `:3000` with provisioned
   datasources (`deploy/dev/observability/`);
4. applies the embedded migrations (`constellation-api --migrate-only`) and seeds demo records (`cmd/constellation-seed`); the seeded user row has no local password;
5. starts `constellation-api` (`:18080`, admin `:18081`), `constellation-operator`
   (`:18082` metrics, `:18083` probes, watching the `constellation-dev` namespace of
   `$KUBECONFIG` so it never fights a deployed operator) and `constellation-scanner`
   (`:18084`) under Air (`.air.<binary>.toml`, rebuild on save, `_test.go` excluded);
6. starts Vite on `:5173` proxying `/api`, `/openapi.json` and `/ws` to the API.

Logs live under `tmp/dev/logs/` and are rotated with a timestamp suffix on every `up`.
The scanner needs `trivy`, `grype`, `syft` on `PATH` to run real scans; without them it
serves health/metrics and logs the missing tools.

Install Air with `bash scripts/install-ci-tools.sh air`; `make tools` installs
the versioned quality tools into `~/.local/bin`. Add that directory to `PATH`.

Before first boot with local sign-in, create `.env.dev.local` from `.env.dev`,
restrict its permissions (`chmod 600 .env.dev.local`), and privately configure
`LOCAL_AUTH_ORG`, `LOCAL_BOOTSTRAP_EMAIL`, `LOCAL_BOOTSTRAP_PASSWORD` and
`LOCAL_BOOTSTRAP_TOTP`. Use a unique administrator email rather than the seeded
`admin@demo.test` row; for demo data, set the organization to `demo`. The password
must satisfy the configured policy (at least 16 characters by default), and TOTP
requires an authenticator-compatible base32 secret encoding at least 20 random
bytes (SHA1, six digits, 30 seconds).
Bootstrap creates the first administrator; it does not reset existing accounts.
Alternatively configure OIDC. The [identity contract](deployment-helm.md#local-accounts-and-recovery-administrator)
describes local/recovery accounts and enrollment. Keep credentials out of Git.

When using a restored database, set `DEV_SEED=0` and supply its original encryption
key before starting the dev loop. The demo seeder truncates demo/evidence tables;
it is not a recovery step. `make dev` is local development orchestration; Helm
remains the supported deployment path.

## Quality gates

| Command | What |
|---|---|
| `make check` | lint (golangci-lint v2), vet, fmt (verify-only), shellcheck, frontend lint + tsc + production build/budget, Go unit tests |
| `make test` | gotestsum `-race -shuffle=on -count=1 ./...` — no Docker; DB tests skip when `CONSTELLATION_TEST_DATABASE_URL` is unset |
| `make test-integration` | `-tags=integration -p 8`; `internal/testutil/pgtest` starts one `pgvector/pgvector:pg16` testcontainer per test process and clones a migrated template DB per test (pgtestdb) |
| `make security` | gosec, govulncheck, gitleaks (full history) → SARIF under `artifacts/` |
| `make helm-lint helm-template-smoke` | chart lint + renders across value profiles (Helm 4) |
| `make e2e` | Playwright; `PLAYWRIGHT_BASE_URL=http://localhost:5173 VITE_API_URL=http://localhost:18080` against the dev loop |

Bring your own database for integration tests with
`CONSTELLATION_TEST_DATABASE_URL=postgres://... make test-integration`.

## Frontend TypeScript toolchain

The frontend uses TypeScript **7.0.2** for `tsc`, including `npm run type-check`
and the production build. ESLint's parser still requires the TypeScript 6
JavaScript API. Follow Microsoft's documented
[side-by-side configuration](https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/#running-side-by-side-with-typescript-6-0):

- `@typescript/native` aliases `typescript@7.0.2` and provides `tsc`.
- `typescript` aliases `@typescript/typescript6@6.0.2`, which provides `tsc6`
  and forwards the compiler API to `@typescript/old` (TypeScript 6.0.3 in the lockfile).

Keep these roles distinct when updating dependencies. Replacing the API alias
directly with TypeScript 7 breaks the current ESLint parser. Install with
`npm ci --strict-peer-deps` from `frontend/`; `npx --no-install tsc --version`
must report 7.0.2, while `node -p "require('typescript').version"` reports 6.0.3.
The normal lint rules and strict type-checking remain enabled. Re-evaluate the
API dependency when typescript-eslint supports the native compiler API.

## Images and release

`make image-<role>` builds one role image; `GO_VERSION` is read from `go.mod` and passed as
`--build-arg` (Dockerfiles have no default, `make check-go-version` enforces it). Release
promotion runs `bin/release-gate gate|promote` (Grype, no fixable critical/high) before a
tag is created; see `.github/workflows/release.yml`.

## Repository layout

See `CLAUDE.md` ("Where things live") and the ADRs under `docs/decisions/`.
