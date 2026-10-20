# Constellation — engineering discipline

This file is the project-root marker for the engineering rules every contributor (human or
agent) follows. It derives from the AlphaBravo Technology Selection Guide, chapter 08. RFC
2119 keywords (MUST / SHOULD / MAY) carry their RFC meaning.

## Seven principles

1. **Correctness over speed.** A change is done when its e2e proof passes, not when it
   compiles. Integration tests hit a real Postgres; Playwright hits the real bundle.
2. **Modular by default.** One package per business domain under `internal/<domain>/`
   with at most three layers: `handler.go` → `service.go` → `store.go`. DB queries MUST NOT
   appear in handler files. `pkg/` is only for deliberately public surfaces (`pkg/plugin`,
   `pkg/version`).
3. **Proto enums as the single source of truth.** Categorical fields are proto enums on the
   wire and `text` + `CHECK` in the database; conversion happens in one boundary package.
   (Phase 2 — see ADR 0002.)
4. **Air-gap first.** No out-of-cluster call on first boot unless opted in; every image is
   digest-pinned; no `:latest`.
5. **Real backends in tests.** No mocks at the database boundary. `make test` is the
   Docker-free unit suite; `make test-integration` provisions a disposable Postgres.
6. **Fix root causes, not symptoms.** Tag the rare workaround `// WORKAROUND: <issue>`.
7. **No backward-compatibility burden pre-production.** Rename, delete and rewrite freely;
   migrations are forward-only (ADR 0006); no shims.

## Dev loop

| Task | Command | Notes |
|---|---|---|
| Full local stack | `make dev` | Postgres + Prometheus/Tempo/Loki/Grafana (compose), api/operator/scanner under Air, Vite. Seeds `admin@demo.test` / `Constellation!1`. |
| Stop / status / logs | `make dev-down` / `make dev-status` / `make dev-logs` | `scripts/dev.sh logs api` for one process. |
| Build every binary | `make build` | `bin/<name>`; add binaries to `BINARIES` in the Makefile. |
| Unit tests | `make test` | gotestsum, `-race -shuffle=on`, JUnit under `artifacts/`; no Docker. |
| Integration tests | `make test-integration` | `-tags=integration`; testcontainers pgvector + pgtestdb clone per test (`internal/testutil/pgtest`), `-p 8`. |
| Quality gate | `make check` | lint + vet + fmt (verify-only) + shellcheck + frontend lint + unit tests. |
| Format | `make fmt-fix` | gofmt + goimports (local prefix `github.com/alphabravocompany/constellation`). |
| Security | `make security` | gosec, govulncheck, gitleaks → SARIF. |
| Migrations | `make migrate` | `constellation-api --migrate-only`: embedded goose set under an advisory lock; the API also runs it on boot. Forward-only. |
| Chart | `make helm-lint helm-template-smoke` | Helm 4 CLI. |
| Images | `make image-<role>` / `make images` | `GO_VERSION` always comes from `go.mod`. |
| FIPS | `make fips-build` | Go-native FIPS 140-3 module (ADR 0004). |
| E2E | `make e2e` | Playwright; `PLAYWRIGHT_BASE_URL` targets a running stack. |

Ports (from `.env.dev`): API `:18080`, API admin/metrics `:18081`, operator `:18082/:18083`,
scanner `:18084`, Vite `:5173`, Postgres `:15432`, Grafana `:3000`, Prometheus `:9090`,
Tempo `:3200` (OTLP `:4317`), Loki `:3100`.

## Where things live

- `cmd/<binary>/main.go` — composition roots only; `cmd/tools/` — CI/release helpers.
- `internal/server` — chi router and REST composition (shrinks as Phase 2 extracts domains).
- `internal/handler/*` — legacy REST handlers (lint held at STANDARD until extracted).
- `internal/telemetry` — the only OTel/Prometheus init; `Init(ctx, Config)`.
- `internal/operator` — controller-runtime operator; CRDs in `deploy/charts/constellation/crds`.
- `internal/server/database/migrations` — embedded goose SQL, forward-only; runner in `internal/server/database`.
- `deploy/charts/constellation` — the only deployment path (ADR 0007).
- `third_party/neuvector` — vendored C data-plane (ADR 0003).
- `docs/decisions` — ADRs (MADR); write one for any stack change.

## Style

Go: Uber + Google Go style guides; golangci-lint v2 STANDARD plus the guide's linters at the
golden thresholds (`.golangci.yml`). TypeScript: strict, React 19 function components,
TanStack Query for server state, react-hook-form + Zod for forms, lucide-react icons.
Bash: `set -euo pipefail`, < 200 lines, shellcheck-clean. Commits: Conventional Commits.
