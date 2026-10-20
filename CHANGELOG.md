# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Re-alignment with the AlphaBravo Technology Selection Guide, Phase 0 (mechanical).

### Added
- `LICENSE` (AGPL-3.0), `SECURITY.md`, `CHANGELOG.md`, root `CLAUDE.md`/`AGENTS.md`.
- ADRs 0002–0007 (`docs/decisions/`): guide stack adoption, vendored NeuVector data-plane,
  Go-native FIPS, Crossplane/CAPI N/A + distroless exemptions, forward-only migrations,
  Helm-only deployment.
- Dev loop: `.air.{api,operator,scanner}.toml`, `scripts/dev.sh`, `.env.dev`,
  `deploy/dev/compose.yaml` (pgvector Postgres + Prometheus 3.15 / Tempo 3.1 / Loki 3.7 /
  Grafana 13.2 with provisioned datasources).
- `internal/telemetry`: config-driven OTel init (OTLP gRPC), OTel Prometheus exporter,
  `service_build_info` gauge, `otelhttp` outbound transport, admin listener for `/metrics`.
- Admin/health listener (`/healthz`, `/readyz`, `/metrics`) on the discoverer,
  netpolicy-applier, compliance-scheduler and kube-bench worker; chart probes for each.
- Chart: `backup.objectStore` (in-cluster RustFS + Barman ObjectStore + bucket job),
  admin port + ServiceMonitor for the API, operator leader election on by default.
- `cmd/tools/{release-gate,sarif-tool,scanner-tools}` replace the Python release scripts.
- Frontend nginx: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy headers.

### Changed
- Go 1.27.3; pgx 5.11, chi 5.5, OpenTelemetry 1.47, client_golang 1.25,
  controller-runtime 0.25.2 / k8s 0.37.1, cilium 1.20.
- Frontend: React 19.3, Vite 8.3, TypeScript 7, Tailwind 4.3, TanStack Query 5.104,
  zod 4.6.7, react-hook-form 7.90, lucide-react 1.59, vitest 5, Playwright 1.64.
- Node 24.22.0; golangci-lint 2.15, gitleaks 8.30.1, gosec 2.29, gotestsum 1.13.
- Makefile rewritten to the guide's target set (`dev build test test-integration lint vet
  fmt generate migrate check security updates fips-build helm-lint e2e`); `GO_VERSION`
  is derived from `go.mod` and passed to every image build; `test` runs through
  gotestsum; `fmt` is verify-only.
- Dockerfiles: no hard-coded Go version, numeric `USER` everywhere, builder and runtime
  bases pinned by digest.
- API router: Recoverer → RequestID → telemetry → logger → CORS → CSRF → rate-limit →
  auth → authz; request timeout and body limit; cookie-before-bearer precedence;
  `/metrics` moved to the admin listener; access log carries the HTTP status.
- Operator moved from `deploy/operator` to `internal/operator`; `:latest` defaults removed.
- Migrations are forward-only; all goose `Down` sections removed.
- Scanner refreshes the Trivy Java DB alongside the main DB; platform targets are no
  longer re-scanned on every discoverer report when the evidence hash is unchanged.
- README deployment section is Helm-only; status line replaced with an honest
  pre-release statement.

### Removed
- NeuVector parity programme docs and gates, Python tooling and test harness, systemd and
  docker-compose deployment paths, embedded StatefulSet Postgres mode and
  `retainStatefulSetForRollback`, scaffold `ConstellationComplianceExemption` CRD,
  `Dockerfile.{cli,seed,scanner-driver,go-dev}`, `.goreleaser.yaml`, `go.work.example`,
  VS Code extension, calico/cilium Python validation workflows (to be re-done in Go).

## [0.2.0] - 2026-08-25

Last release before the re-alignment: Helm chart 0.2.0, per-role images under
`ghcr.io/alphabravo-oss/constellation/<role>`, CNPG Postgres mode, runtime agent with the
vendored NeuVector data-plane, admission webhook, compliance scheduler, federation.
