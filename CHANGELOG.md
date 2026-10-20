# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## 0.3.0 - 2026-10-20

Re-alignment with the AlphaBravo Technology Selection Guide (Phase 0 mechanical clean-up,
Phase 1 backend foundations) and the C1 "Triage Desk" UI on the shared AlphaBravo UI kit.

### Upgrade notes (breaking)
- **Migrations run inside the API** under a Postgres advisory lock (embedded goose).
  The migrate Job, `wait-for-migrations` init container, `migrate.*` values and the
  `migrate` image are gone. Give the first API boot `DB_CONNECT_TIMEOUT` headroom.
- **Column encryption is age-based (migration 185).** `CONSTELLATION_KEK` is gone. Set
  `crypto.ageKey` / `crypto.existingSecret`, or let the pre-install hook mint
  `<release>-age-key` (toolbox image) - and back that Secret up (`backup.secrets`).
  Ciphertext sealed under the old KEK is cleared or revoked: **re-enter registry
  credentials and git PATs, re-issue cluster init bundles / agent tokens**; the
  federation CA regenerates.
- **Error bodies** are always `{"error":{"code","message","request_id"[,"details"]}}`.
- **Scanner defaults to offline vulnerability DBs** (`scanner.vulnDB.offline: true`).
  Connected installs set `scanner.vulnDB.offline: false`; air-gapped installs use the
  `scanner-airgap` image or a loaded bundle.
- New **toolbox** image (age + kubectl + rclone, non-root): age-key hook, off-host archive
  sync, secrets backup.
- Air-gap bundles are verified against the vendor bundle-signing key compiled into
  `constellationctl` (`internal/bundle/trust/bundle-signing.pub`); bundles signed with
  the 0.3.0 development key are rejected.
- The published chart renders `<role>:v<appVersion>` and `postgres:16.14-v<appVersion>`;
  release.yml now builds `compliance-scheduler` and packages the chart at the exact tag
  (`scripts/check-chart-images.sh` proves every rendered image exists before publishing).

### Added (Phase 1)
- `internal/testutil/pgtest`: testcontainers + pgtestdb fixture; every DB test is tagged
  `integration` and parallel (`make test-integration` 11 min -> under 3 min).
- Composite pgx tracer (otelpgx + query metrics), `db_pool_*` gauges; zerolog via
  `internal/logging` with a `slog` bridge and per-request correlation ids.
- `internal/api/apiutil`: error contract, cursor pagination, route-policy table (528 routes).
- `internal/crypto`: age column encryption with `(key_id, algorithm, nonce)` and
  `constellationctl admin rotate-keys` / `generate-key`.
- Air-gap primitives: `internal/storage` (S3 + discovery), signed bundles
  (`constellationctl bundle build|verify|load|resolve`), `global.imageRegistry`,
  `--insecure-registries`, one `egress endpoints` log line per binary.
- Chart: runtime overlays made native - off-host Barman archive + rclone sync + recovery
  ObjectStore (`backup.offhost`), CNPG/object-store NetworkPolicies (`networkPolicies.cnpg`),
  admission kube-API egress, ServiceMonitors/PodMonitors (`metrics.serviceMonitor`),
  PrometheusRule (`metrics.prometheusRule`), declarative metrics role
  (`metrics.postgresRole`), secrets backup CronJob (`backup.secrets`), admission
  `exemptNamespaces`, k3s PSA admission config and kubelet profile (`deploy/k3s/`).
- First-class metrics: component heartbeat age, scanner engine-DB age/readiness (incl.
  trivy java-db), CVE feed age.
- API: `GET/PUT /api/v1/me/preferences`, last-known cluster exposure when inventory is
  stale, `X-Request-ID` exposed to CORS, asset display names on finding detail.
- ADR 0008 (explicit bearer token before session cookie).

### Changed (UI, C1 Triage Desk - ADR 0009)
- Shared AlphaBravo UI kit (`frontend/src/ui`, byte-identical to Astronomer): kit rail +
  cluster panel, 56 px header with scope chip, System workloads switch, palette, 3-mode
  theme synced to `/me/preferences`; teal is the only accent; self-hosted Inter and
  JetBrains Mono.
- Every page opens with a 56 px verdict strip instead of stat stacks; one Export menu and
  one Refresh per table; kit Select/Checkbox/Switch everywhere; 11 px type floor;
  sentence-case labels; names instead of UUIDs in breadcrumbs.
- Policies hub (Admission, Runtime, Network, Response), Agents hub (Components, Sensor
  health), two-layer Settings; NeuVector migration tooling moved under Settings.
- Skeleton loading, kit error states with the request id, in-shell 404; axe
  WCAG 2.1 AA clean on the audited pages in both themes.

### Fixed (Phase 1)
- Admission egress NetworkPolicy lacked kube-API egress (RBAC snapshot / namespace
  resolvers failed); the namespace informer wait is bounded.
- Migration 186 role grants no longer require CREATEROLE.
- syft/grype insecure-registry flags; containerd-safe bundle layouts; CNPG image tags carry
  the PG version.

### Phase 0



#### Added
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

#### Changed
- Go 1.27.3; pgx 5.11, chi 5.5, OpenTelemetry 1.47, client_golang 1.25,
  controller-runtime 0.25.2 / k8s 0.37.1, cilium 1.20.
- Frontend: React 19.3, Vite 8.3, TypeScript 6.0.3 (7.x blocked by typescript-eslint), Tailwind 4.3, TanStack Query 5.104,
  zod 4.6.7, react-hook-form 7.90, lucide-react 1.59, vitest 5, Playwright 1.64.
- Node 24.22.0; golangci-lint 2.15, gitleaks 8.30.1, gosec 2.29, gotestsum 1.13.
- Makefile rewritten to the guide's target set (`dev build test test-integration lint vet
  fmt generate migrate check security updates fips-build helm-lint e2e`); `GO_VERSION`
  is derived from `go.mod` and passed to every image build; `test` runs through
  gotestsum; `fmt` is verify-only.
- Dockerfiles: no hard-coded Go version, numeric `USER` everywhere, builder and runtime
  bases pinned by digest.
- API router: Recoverer → RequestID → telemetry → logger → CORS → CSRF → rate-limit →
  auth → authz; request timeout and body limit; an explicit bearer token keeps
  precedence over the session cookie (ADR 0008);
  `/metrics` moved to the admin listener; access log carries the HTTP status.
- Operator moved from `deploy/operator` to `internal/operator`; `:latest` defaults removed.
- Migrations are forward-only; all goose `Down` sections removed.
- Scanner refreshes the Trivy Java DB alongside the main DB; platform targets are no
  longer re-scanned on every discoverer report when the evidence hash is unchanged.
- README deployment section is Helm-only; status line replaced with an honest
  pre-release statement.

#### Removed
- NeuVector parity programme docs and gates, Python tooling and test harness, systemd and
  docker-compose deployment paths, embedded StatefulSet Postgres mode and
  `retainStatefulSetForRollback`, scaffold `ConstellationComplianceExemption` CRD,
  `Dockerfile.{cli,seed,scanner-driver,go-dev}`, `.goreleaser.yaml`, `go.work.example`,
  VS Code extension, calico/cilium Python validation workflows (to be re-done in Go).

## 0.2.0 - 2026-08-25

Last release before the re-alignment: Helm chart 0.2.0, per-role images under
`ghcr.io/alphabravo-oss/constellation/<role>`, CNPG Postgres mode, runtime agent with the
vendored NeuVector data-plane, admission webhook, compliance scheduler, federation.
