# Development

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
4. applies the embedded migrations (`constellation-api --migrate-only`) and seeds `admin@demo.test` / `Constellation!1` (`cmd/constellation-seed`);
5. starts `constellation-api` (`:18080`, admin `:18081`), `constellation-operator`
   (`:18082` metrics, `:18083` probes, watching the `constellation-dev` namespace of
   `$KUBECONFIG` so it never fights a deployed operator) and `constellation-scanner`
   (`:18084`) under Air (`.air.<binary>.toml`, rebuild on save, `_test.go` excluded);
6. starts Vite on `:5173` proxying `/api`, `/openapi.json` and `/ws` to the API.

Logs live under `tmp/dev/logs/` and are rotated with a timestamp suffix on every `up`.
The scanner needs `trivy`, `grype`, `syft` on `PATH` to run real scans; without them it
serves health/metrics and logs the missing tools.

Install the Go tools once: `go install github.com/air-verse/air@latest` and
`make tools` installs the CI pins (golangci-lint, gosec, govulncheck, gitleaks, gotestsum, shellcheck).

## Quality gates

| Command | What |
|---|---|
| `make check` | lint (golangci-lint v2), vet, fmt (verify-only), shellcheck, frontend lint + tsc, unit tests |
| `make test` | gotestsum `-race -shuffle=on -count=1 ./...` — no Docker; DB tests skip when `CONSTELLATION_TEST_DATABASE_URL` is unset |
| `make test-integration` | `-tags=integration -p 8`; `internal/testutil/pgtest` starts one `pgvector/pgvector:pg16` testcontainer per test process and clones a migrated template DB per test (pgtestdb) |
| `make security` | gosec, govulncheck, gitleaks (full history) → SARIF under `artifacts/` |
| `make helm-lint helm-template-smoke` | chart lint + renders across value profiles (Helm 4) |
| `make e2e` | Playwright; `PLAYWRIGHT_BASE_URL=http://localhost:5173 VITE_API_URL=http://localhost:18080` against the dev loop |

Bring your own database for integration tests with
`CONSTELLATION_TEST_DATABASE_URL=postgres://... make test-integration`.

## Images and release

`make image-<role>` builds one role image; `GO_VERSION` is read from `go.mod` and passed as
`--build-arg` (Dockerfiles have no default, `make check-go-version` enforces it). Release
promotion runs `bin/release-gate gate|promote` (Grype, no fixable critical/high) before a
tag is created; see `.github/workflows/release.yml`.

## Repository layout

See `CLAUDE.md` ("Where things live") and the ADRs under `docs/decisions/`.
