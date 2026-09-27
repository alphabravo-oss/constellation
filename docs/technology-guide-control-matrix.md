# Technology Selection Guide control inventory

Inventory date: 2026-09-27. Source: [published guide](https://technology-selection-guide.aws.ablabs.io/) and its [complete chapter text](https://technology-selection-guide.aws.ablabs.io/llms-full.txt), SHA-256 `13ec22a5d0dfa4789b91e2e3101bed4d9e19982db444c8c66ad4173159e6ada0`. This is an evidence inventory for the TSG-1 workstream in `NEUVECTOR-PARITY-PLAN.md`, **not** an approval record or a guide-conformance claim. The guide's May 2026 version tables are historical snapshots, not authority to downgrade supported dependencies. Recheck the source hash and upstream support at each quarterly review.

## Reading this matrix

Each stable ID is a *control family*, keyed to the guide chapter and prescriptive subsection. A family groups clauses that have one acceptance boundary; **every** MUST/MUST NOT and SHOULD/SHOULD NOT clause in the named boundary must pass before the family becomes `verified`. Optional MAY choices are recorded where a decision changes applicability. TL;DR repetitions, illustrative code, reference-implementation callouts, and pinned-version tables are not independent obligations. The control wording below is a paraphrase; the linked chapter remains normative. Conditional controls are `open` until applicability is decided or their condition is proven false. For a SHOULD departure, an ADR must document the trade-off; a MUST departure is a nonconformance even if a risk owner accepts it.

Status vocabulary follows TSG-1: `open` (missing, disputed, or undecided), `implemented/unverified` (source evidence exists but acceptance has not passed), `verified` (positive and negative tests plus applicable live proof are recorded), `approved-deviation` (explicit approval, **not** strict conformance), `not-applicable` (condition demonstrably false). No row here is an approved deviation. `D` in a row means **decision needed**, not approved. Evidence paths are pointers to inspect, not test results. `—` under command means an acceptance command must be defined; do not infer a pass from a nearby test. Owners are proposed accountable roles, not an assignment. `L` means live/deployed proof is still needed; `R` means repository/CI proof; `N` means a documented applicability/architecture decision. A row with `L` cannot close from local E2E alone.

Common command candidates: `make check`, `make test-integration`, `make security`, `make helm-lint helm-template-smoke`, `make test-browser`, `cd frontend && npm run build && npx playwright test`. They are **candidates**, not blanket acceptance of the controls below. `make check` currently includes source quality gates but not every security or browser gate. Where no dedicated gate exists, `—` identifies work to do. For each row, future evidence should record command, revision, date, result, failing-path case, and deployed environment where `L` applies.

## 00 — [Introduction](https://technology-selection-guide.aws.ablabs.io/00-introduction/)

| ID / subsection | Obligation and applicability | Status | Evidence; acceptance command / proof | Owner; decision |
|---|---|---|---|---|
| TSG-00-RFC / keyword definitions | Apply RFC 2119 strengths without silently promoting SHOULD or treating MAY as mandatory. | open | This inventory defines vocabulary; review TSG decisions quarterly / —; N | Architecture; adopt reviewer rule. |
| TSG-00-FORK / audiences | Guide-fork `site_url`, `repo_url`, license, reference callouts: conditional on publishing a fork. | not-applicable | This repository adopts, but does not publish, a guide fork / N | Architecture; reassess if a fork is created. |
| TSG-00-DOC / doc conventions | Single H1, keyworded prescriptions, path-agnostic text and self-contained chapters: guide-authoring requirements, not product runtime requirements. | not-applicable | No guide chapter is maintained here / N | Docs; reassess if a fork is created. |
| TSG-00-REV / review cadence | Date source snapshot and review versions/applicability at least quarterly; document unchanged reviews. | open | Plan and this snapshot exist; no recurring owner/gate / —; R | Architecture; schedule and CI evidence report. |

## 01 — [Architecture](https://technology-selection-guide.aws.ablabs.io/01-architecture/)

| ID / subsection | Obligation and applicability | Status | Evidence; acceptance command / proof | Owner; decision |
|---|---|---|---|---|
| TSG-01-LAYOUT / top-level layout | Private service code in `internal/`; `cmd/<binary>` only boots composition root; public `pkg/` deliberately versioned; do not treat generic Go layout as authority. | open | `cmd/`, `internal/`, `pkg/` exist; public-package audit / —; R | Backend; D: retained public `pkg/` API. |
| TSG-01-DOMAIN / package boundaries | One package per domain, handler/service/store separation, domain-local helpers, no root `utils` sink. | open | `internal/handler/` contains SQL and broad HTTP domain; query audit / —; R | Backend; refactor or review deviation. |
| TSG-01-DI / composition root | Construct dependencies topologically, inject constructors, no mutable runtime globals, parse env only at composition roots. | open | `cmd/`, `internal/db/db.go`; env/global audit / —; R | Backend; binary-by-binary evidence. |
| TSG-01-OPROOT / operator | Operator has separate root, manager/client/reconciler wiring. | implemented/unverified | `deploy/operator/` / `GOWORK=off go test ./deploy/operator/...`; R,L | Operator; prove deployed wiring. |
| TSG-01-OPLOCK / operator | Serialize same-resource reconciliation; leader election for replicas; stage registry SHOULD isolate steps. | open | `deploy/operator/controllers/`; race and HA reconciliation / —; R,L | Operator; prove lock/election. |
| TSG-01-ENUM / operator | Proto enum↔DB conversion only at typed boundary. | open | No proto/Connect pipeline identified / —; R | Backend/operator; D: REST contract strategy. |
| TSG-01-PLATFORM / operator | Evaluate Crossplane v2/CAPI applicability; migrate v1 before adoption; test Helm v4 lookup changes before cutover. | open | Helm chart and operator exist, no evidence of Crossplane/CAPI provisioning / `make helm-lint helm-template-smoke` plus architecture review; R | Operator; D: mark Crossplane/CAPI not applicable if justified. |

## 02 — [Data](https://technology-selection-guide.aws.ablabs.io/02-data/)

| ID / subsection | Obligation and applicability | Status | Evidence; acceptance command / proof | Owner; decision |
|---|---|---|---|---|
| TSG-02-PG / engine and driver | PostgreSQL ≥16, pgx/v5 pool injected from root, no pool globals; avoid `database/sql` for new code. | implemented/unverified | `go.mod`, `internal/db/db.go`, Helm Postgres chart; version/config audit / `make test-integration`; R,L | Data; verify deployed version. |
| TSG-02-TRACE / engine and driver | SHOULD compose OTel and call-site query tracing. | open | `internal/db/db.go` has no tracer / —; R,L | Observability; D if retaining current instrumentation. |
| TSG-02-SQLC / sqlc workflow | Annotated domain SQL, generated typed accessors checked in and generated in build; no hand-written domain SQL except reviewed bounded dynamic cases. | open | `db/migrations/`, handler SQL, no `sqlc.yaml` found / —; R | Data; D: sqlc migration or approved nonconformance. |
| TSG-02-GOOSE / goose migrations | Versioned reversible Up/Down migrations, embedded runner, advisory lock including release, before-serve failure exit. | open | `db/migrations/`, `Makefile` uses external `goose` / `make test-integration` plus replica-start failure test; R,L | Data; D: external migrator strategy. |
| TSG-02-KEYROW / encryption shape | Encrypted user columns carry key ID, algorithm, ciphertext and needed nonce; unique nonces; SHOULD use envelope/KMS custody. | open | `internal/auth/sessionkeys.go`, `docs/browser-sessions.md`; schema/crypto inventory / —; R,L | Security/data; D: key scheme. |
| TSG-02-JSONB / JSONB discipline | Document schemas, validate writes, migrate/reject stale reads, suitable GIN classes, promote fixed fields. | open | `db/migrations/`; JSONB column/query audit / —; R | Data; decide schemas per column. |
| TSG-02-DELETE / soft delete | User-data rows include `deleted_at`; delete marks rows and every read filters. | open | `db/migrations/`; table/query matrix / —; R,L | Data; D: retention/privacy semantics. |
| TSG-02-TENANT / tenant scoping | Tenant key on multi-tenant tables; scope **reads and writes**; cross-tenant access explicit/reviewed; SHOULD prevent cross-tenant FK relationships. | open | `db/migrations/002_tenancy.sql`, auth scope tests; full table/query/FK audit / `make test-integration`; R,L | Security/data; cross-tenant negative matrix. |
| TSG-02-NOTIFY / LISTEN/NOTIFY | MAY use for best-effort events; if used: reconcile canonical row, dedicated connection, domain channel names. | open | Need eventing usage audit / —; N | Data; decide applicability, then test reconnect/loss. |

## 03 — [Surface](https://technology-selection-guide.aws.ablabs.io/03-surface/)

| ID / subsection | Obligation and applicability | Status | Evidence; acceptance command / proof | Owner; decision |
|---|---|---|---|---|
| TSG-03-ROUTER / RPC/router | chi root with generated Connect handlers; REST only non-colliding auxiliary paths; global timeout/body limit. | open | `go.mod` has chi; product API remains REST/OpenAPI / `make check-endpoint-mapping`; R,L | API; D: REST versus Connect ADR. |
| TSG-03-CHAIN / interceptors | Recovery → request ID/trace → log → authn → authz → validation → handler. | open | `internal/server/`; middleware order and denial/panic tests / —; R,L | API/security; Connect conditional on RPC decision. |
| TSG-03-ERROR / error mapping | Typed domain errors; one scrubbed mapping helper; unmapped internal errors not exposed. | open | `internal/handler/`; error-shape audit / —; R,L | API; D: REST analogue if Connect retained out. |
| TSG-03-PAGE / pagination | Opaque capped cursor token and next token for lists; return effective size SHOULD; no client-decoded cursor. | open | REST lists vary; `docs/NEUVECTOR-ENDPOINT-MAPPING-2026-08.md` / —; R,L | API; D: REST-equivalent pagination contract. |
| TSG-03-AUTH / authentication | Short-lived HttpOnly/Secure browser cookies, separate refresh, bearer CLI, exp ≤15 min; one validated context principal; signer set central. | implemented/unverified | `docs/browser-sessions.md`, `internal/auth/browser_sessions.go`, `internal/auth/jwt.go` / `make test-browser` plus service-token/expiry negative tests; R,L | Security; verify deployed paths. |
| TSG-03-ENUM / proto enums | Categorical wire fields from proto; DB CHECK/reference and dedicated typed conversion; coordinated enum migration. | open | OpenAPI/REST and hand-maintained DTOs / —; R | API/data; D: contract migration. |
| TSG-03-WEB / frontend | React 19, strict TS, Vite; generated Connect-Web client; top-level provider composition. | open | `frontend/package.json`, `frontend/src/main.tsx`, `frontend/src/App.tsx`; no generated Connect-Web / `cd frontend && npm run build`; R | Frontend/API; generated contract decision. |
| TSG-03-ROUTES / canonical router | Central react-router Data Mode route objects, loader auth redirects, `useNavigation` pending state. | open | `frontend/src/main.tsx` uses `BrowserRouter` / browser routing E2E; R | Frontend; D: transition/ADR. |
| TSG-03-ALT / alternative router | TanStack Router MAY replace canonical router with ADR; never silently use both. | not-applicable | `frontend/package.json` uses react-router / N | Frontend; reassess only if router changes. |

## 04 — [Infrastructure and Tooling](https://technology-selection-guide.aws.ablabs.io/04-infra-tooling/)

| ID / subsection | Obligation and applicability | Status | Evidence; acceptance command / proof | Owner; decision |
|---|---|---|---|---|
| TSG-04-AIR / Air | Per-binary checked-in Air config with exact build/stamps, explicit watched/excluded paths, test exclusion, delay, stop-on-error and graceful signal settings. | open | No `.air.*.toml` found / —; R | DevEx; D: Air versus current dev loop. |
| TSG-04-VITE / Vite | HMR, explicit host/port, API proxy, build stamp from env at config load. | open | `frontend/vite.config.ts` proxies `/api`, no stamp/host contract / `cd frontend && npm run dev -- --help` plus browser About test; R | Frontend/DevEx. |
| TSG-04-MAKE / Make | Root phony dev/build/test/integration/lint/vet/fmt/generate/migrate/check; generated dependencies explicit, Git build variables overridable, consistent binary targets. | open | `Makefile` covers most but no `dev`/`proto` contract / `make -n check build`; R | DevEx; D: equivalent targets if retained. |
| TSG-04-IMAGE / containers | Multi-stage, digest-pinned builder, minimal nonroot runtime, no package manager, OCI source/version labels, health probe. | open | `deploy/docker/Dockerfile.api`, `Dockerfile.runtime-agent` use Debian/package managers and mutable bases / image inspection + `make release-images`; R,L | Release/security; D: privileged/native image exception. |
| TSG-04-GOVERSION / Dockerfile pins | Builder version derives from `go.mod`; CI fails drift. | open | Dockerfiles have literal `GO_VERSION` defaults / —; R | Release/DevEx. |
| TSG-04-DEVSH / dev entrypoint | One-command full stack with preflight, `.env.dev(.local)`, PID/teardown, traps, rotated logs, `nohup`, validated up/down/status/logs/migrate/migrate-down. | open | `compose.dev.yaml`, Make targets; no `scripts/dev.sh` / —; R | DevEx; D: equivalent lifecycle. |
| TSG-04-K3S / local cluster | SHOULD use upstream k3s; safe user kubeconfig, uncordon race; production not dependent on k3s/k3d. | open | `deploy/e2e/`, `docs/e2e-k3s-results.md`; local-host procedure / —; R,L | DevEx/operator; D: host policy. |
| TSG-04-LINT / golangci | v2 STANDARD, checked-in exceptions/thresholds, readonly modules, gofmt/goimports, scoped exclusions, sufficient timeout where applicable. | implemented/unverified | `.golangci.yml`, `docs/security-testing.md` / `make lint fmt`; R | DevEx; baseline findings and CI results needed. |
| TSG-04-CONFIG / reproducibility | Tool config checked in; editor commands delegate to Make; env not hidden defaults; dev/prod parity SHOULD be demonstrated. | open | `Makefile`, `.github/workflows/ci.yml`, `compose.dev.yaml` / fresh-clone smoke; R,L | DevEx. |

## 05 — [Observability](https://technology-selection-guide.aws.ablabs.io/05-observability/)

| ID / subsection | Obligation and applicability | Status | Evidence; acceptance command / proof | Owner; decision |
|---|---|---|---|---|
| TSG-05-LOG / structured logging | zerolog wrapper, JSON **stderr** in services, levels/formats, component and correlation context helpers, inbound ID adoption/generation, writer-safe constructor. | open | `internal/obslog/`, Go binaries use `slog`/stdout / —; R,L | Observability; D: slog/transport ADR. |
| TSG-05-OTEL / SDK init | One init/shutdown for trace+meter; identity resource, sample config, OTLP **gRPC**, noop trace without endpoint while metrics persist, partial-init cleanup. | open | `go.mod` uses OTLP/HTTP exporters; telemetry source audit / —; R,L | Observability; D: OTLP/HTTP versus gRPC. |
| TSG-05-METRICS / Prometheus | OTel Prom exporter at `/metrics`, accessible but restricted in production; naming/buckets/cardinality; every long-lived binary exposes endpoint. | open | Prometheus client dependency and handlers exist; binary/metric audit / —; R,L | Observability; D: client registry versus OTel exporter. |
| TSG-05-PGX / composite tracer | otelpgx and query tracer fan out across pgx methods before pool open. | open | `internal/db/db.go` has no tracer / —; R,L | Observability/data. |
| TSG-05-LOKI / shipping | Sidecar means JSON stderr only; direct push MAY be used without sidecar, then bounded batching/drop visibility. | open | `compose.dev.yaml`; deployment log path inventory / —; R,L | Observability; decide sidecar/direct path. |
| TSG-05-STACK / local stack | Compose Prometheus, Tempo, Loki, Grafana with checked-in scrape/datasource config and dev OTLP endpoint. | open | `compose.dev.yaml`; four-service boot and trace/log/metric smoke / —; R | Observability/DevEx. |

## 06 — [Security](https://technology-selection-guide.aws.ablabs.io/06-security/)

| ID / subsection | Obligation and applicability | Status | Evidence; acceptance command / proof | Owner; decision |
|---|---|---|---|---|
| TSG-06-AGE / column crypto | age X25519 wrapper owns encrypt/decrypt, file/env key custody, opaque ciphertext, no key in source/DB, typed wrapped errors; KMS constructor MAY extend it. | open | Existing credential sealing differs; `internal/auth/sessionkeys.go` / —; R,L | Security; D: age versus existing crypto. |
| TSG-06-REV / reversibility | Encryption rotation, session renewal and FIPS selection must remain reversible without a downtime migration. | open | `docs/browser-sessions.md`, `docs/fips.md`; upgrade/rollback exercise / —; R,L | Security/release; define reversibility limits. |
| TSG-06-KEY / row shape and rotation | Key/algorithm/ciphertext triples, current-ID writes, old-key reads, typed unknown-algorithm error, resumable transactional rotation, zero-reference retirement query, audited key generation host. | open | `db/migrations/`, `docs/browser-sessions.md`; rotation failure tests / —; R,L | Security/data; design+operations decision. |
| TSG-06-JWT / JWT | jwt/v5, algorithm allowlist, short access + rotating refresh/reuse revocation, Strict/Lax secure HttpOnly browser cookies, no token storage, bearer automation, `aud`/`iss`/`exp` and `sub`/org/roles/sid claims. | open | `go.mod`, `internal/auth/jwt.go`, `docs/browser-sessions.md`; note header precedence differs from guide / `make test-browser` + claim matrix; R,L | Security; D: bearer-header precedence and claim shape. |
| TSG-06-RBAC / authorization | Central post-auth route/role/org gate, typed identity, denial audit with principal/method/roles; no handler reparse/check drift. | open | `internal/handler/authctx/`, `internal/server/`; route-map/tenant negative tests / `make test-integration`; R,L | Security/API; REST-equivalent design decision. |
| TSG-06-SCAN / PR scanners | gosec+govulncheck each PR, SARIF, HIGH/CRITICAL blocking, same Go toolchain, reasoned suppression and triage SLA. | implemented/unverified | `.github/workflows/ci.yml`, `scripts/security-scan.sh`, `docs/security-testing.md` / `make security`; R | Security/CI; hosted gate/SLA still needed. |
| TSG-06-SECRETS / secret scan | Full branch history each PR, reviewed allowlists, block/rotate on finding. | implemented/unverified | `.github/workflows/ci.yml`, `scripts/security-scan.sh` / `make security`; R | Security/CI; prove hosted enforcement. |
| TSG-06-FIPS / FIPS | Separate opt-in build, runtime state, `-fips` images/admission policy; default non-FIPS. | open | `docs/fips.md`, `deploy/docker/Dockerfile.fips`, `Makefile`; guide's Microsoft/BoringCrypto recipe differs / FIPS build + live image smoke; R,L | Security/release; D: Go FIPS toolchain equivalence. |
| TSG-06-DEPS / currency | Update listing, automated security PRs, severity SLA and human major upgrades. | open | `go.mod`, `.github/workflows/`; updater/SLA audit / —; R | Security/DevEx. |
| TSG-06-THREAT / threat model | OWASP Top Ten gap analysis; SHOULD target ASVS L2 for multi-tenant service; severity and key lifecycle risk documented. | open | `docs/security-testing.md` is gate documentation, not threat model / —; R | Security; D: ASVS scope. |

## 07 — [Testing](https://technology-selection-guide.aws.ablabs.io/07-testing/)

| ID / subsection | Obligation and applicability | Status | Evidence; acceptance command / proof | Owner; decision |
|---|---|---|---|---|
| TSG-07-TABLE / table-driven | Multiple cases use named table/subtests, parallel unless serial state, `t.Cleanup`, `t.Helper`. | open | Go tests exist; test-style audit / `make test-race`; R | QA/backend. |
| TSG-07-DB / real DB isolation | One testcontainers PostgreSQL/process, production migration function, pgtestdb template clone/test, production minor match; no shared mutable fixture. | open | `scripts/test-go.sh` uses disposable **suite-level** DB, not pgtestdb / `make test-integration`; R | QA/data; D: harness migration. |
| TSG-07-NOMOCK / DB boundary | Query/repository integration against real PG, no mocked DB boundary; higher fakes local and nonexported. | open | `scripts/test-go.sh`, handler tests; query-layer audit / `make test-integration`; R | QA/data. |
| TSG-07-PW / Playwright | Checked-in config, explicit dirs/baseURL, order-independent tests, zero PR retries, setup project/storageState, retained trace/screenshot/video, artifact upload. | open | `frontend/playwright.config.ts` uses global setup, not setup-project/storageState; video conditional / `make test-browser`; R | QA/frontend; D: auth fixture strategy. |
| TSG-07-JUNIT / gotestsum | Unit+integration through gotestsum, JUnit uploaded, race and uncached runs. | implemented/unverified | `scripts/test-go.sh`, `.github/workflows/ci.yml` / `make test-race test-integration`; R | QA/CI; hosted report proof. |
| TSG-07-TAGS / test partitions | Integration build tags, Docker-free unit target, required main integration gate, same package permitted. | open | `scripts/test-go.sh`, `docs/security-testing.md`; many DB tests untagged / `make test-race test-integration`; R | QA/backend. |
| TSG-07-E2E / production path | E2E must use production binary/static assets; no mock substituted for transport proof. | implemented/unverified | `scripts/test-browser.sh`, `docs/browser-sessions.md`; production-container browser gate / `make test-browser`; R,L | QA; broader deployed matrix open. |

## 08 — [Discipline](https://technology-selection-guide.aws.ablabs.io/08-discipline/)

| ID / subsection | Obligation and applicability | Status | Evidence; acceptance command / proof | Owner; decision |
|---|---|---|---|---|
| TSG-08-KEYWORD / RFC 2119 | Internal binding guidance uses one RFC keyword, no unreviewed SHOULD→MUST promotion. | open | This inventory distinguishes strengths; documentation review gate absent / —; R | Architecture/docs. |
| TSG-08-CORRECT / correctness | Favor correctness; known rare-input defects need explicit comment/issue and written release decision. | open | Parity plan insists evidence; contributor-review practice absent / —; R | Engineering lead. |
| TSG-08-MODULE / modularity | Domain ownership, handler/service/query separation, limited exports, larger helpers separate. | open | `internal/handler/` is broad; architecture audit / —; R | Backend. |
| TSG-08-ENUM / enum source | Proto enum single source; one conversion boundary; frontend generated enums; coordinated changes. | open | REST DTOs, no proto generation / —; R | API/frontend; same REST decision as TSG-03-ENUM. |
| TSG-08-OFFLINE / offline first | Every runtime path works offline; external calls opt-in, local image hydration, bounded telemetry buffering. | open | `docs/offline-scanning.md`; closed-egress first boot/all-feature E2E / —; R,L | Platform/release. |
| TSG-08-REAL / real backends | PG/S3/OCI integration with real fixtures; mocks never replace transport proof; E2E production path. | open | `scripts/test-go.sh`, `scripts/test-browser.sh`; S3/OCI fixture coverage audit / —; R,L | QA/platform. |
| TSG-08-ROOT / root-cause fixes | Trace upstream defect; workaround issue/comment; diagnose flakes before skip/retry. | open | No enforceable review record for all fixes / —; R | Engineering lead/QA. |
| TSG-08-COMPAT / lifecycle | Pre-v1 renames update consumers; post-v1 deprecations/dual-write; avoid unsupported shims. | open | `docs/architecture.md` states pre-stable; version policy/consumer audit / —; R | Architecture/API. |
| TSG-08-STYLE / references | Uber/Google Go consensus, reviewable diff; Twelve-Factor SHOULD shape config/process/disposal; imported principles include tooling. | open | `README.md`, `Makefile`; contributor policy review / —; R | Engineering lead. |
| TSG-08-RUNNER / agent-runner exclusions | Guide-authoring ban on quoting runner-private files, not a product control. | not-applicable | This repository does not author guide chapters / N | Docs; reassess if guide forked. |

## 09 — [Air-gap](https://technology-selection-guide.aws.ablabs.io/09-airgap/)

| ID / subsection | Obligation and applicability | Status | Evidence; acceptance command / proof | Owner; decision |
|---|---|---|---|---|
| TSG-09-BOOT / disconnected design | Full closed-egress feature smoke, external calls default off, startup egress inventory; offline license if license gate exists. | open | `docs/offline-scanning.md` covers scanner DB only / —; R,L | Platform; license subclause not-applicable: OSS has no license gate. |
| TSG-09-OCI / local registry | Every runtime image, including sidecars/init/operator workloads, bundled and cluster-local; manifests rewritten; persistent registry SHOULD; amd64+arm64. | open | Helm charts and amd64-only `Makefile` release / —; R,L | Release/platform; D: arm64/native support. |
| TSG-09-SIGN / signed bundle | Signed BOM verified **before extraction**, trusted offline key, reject invalid/expired, require vendor signature, log key fingerprint. | open | `.goreleaser.yaml`, `scripts/verify-release.sh` sign artifacts, not full loader contract / —; R,L | Release/security. |
| TSG-09-S3 / object storage | S3 API, discovered endpoint, external presign endpoint, stale-connection tolerance, idempotent bucket creation: conditional if local object storage shipped. | open | Backup S3 usage in `cmd/constellation-backup/main.go`; no local S3 contract verified / —; R,L | Platform; decide deployment applicability. |
| TSG-09-DISC / discovery | SHOULD prefer K8s API over DNS; graceful retry/degraded state, bounded TTL/error invalidation, named port, override precedence. | open | `deploy/operator/` clients; service-discovery audit / —; R,L | Platform/operator. |
| TSG-09-RESOLVE / registry resolver | Local → explicit authenticated fallback → fail closed; fallback default off; log winning layer, never unsigned substitution. | open | Scanner/OCI pathways need inventory / —; R,L | Platform/security. |
| TSG-09-K8S / control plane | Verified in-cluster Kubernetes client by default, explicit kubeconfig override, idempotent CRDs. | implemented/unverified | `deploy/operator/`, Helm CRDs / `make helm-lint helm-template-smoke` plus upgrade test; R,L | Operator/platform. |
| TSG-09-XPLANE / provider compatibility | Crossplane Provider/Composition v2 gate if compositions bundled. | not-applicable | No Crossplane composition under `deploy/` found / repository file audit; N | Operator; reassess on introduction. |

## 10 — [TypeScript](https://technology-selection-guide.aws.ablabs.io/10-typescript/)

| ID / subsection | Obligation and applicability | Status | Evidence; acceptance command / proof | Owner; decision |
|---|---|---|---|---|
| TSG-10-STACK / chapter baseline | Default primary set is React, Vite, Tailwind, Radix/shadcn, TanStack Query, Connect-Web, Zod and react-hook-form; substitutions need ADR. | open | `frontend/package.json` lacks Connect-Web/Zod/react-hook-form / —; R | Frontend/API; D: exact-stack adoption versus nonconformance. |
| TSG-10-REACT / React | React 19+, function components, automatic JSX, naming, named lazy exports. | implemented/unverified | `frontend/package.json`, `frontend/src/`; style scan / `cd frontend && npm run build`; R | Frontend. |
| TSG-10-VITE / Vite | Reachable dev host, `/api` and `/ws` proxies, relative URLs, build stamps, `@` alias. | open | `frontend/vite.config.ts` lacks `/ws` and stamps, host default only / —; R | Frontend/DevEx. |
| TSG-10-STYLE / styling | Tailwind v4, typed config, Radix primitives, shadcn SHOULD, `cn` merge helper; no new CSS-in-JS/hand-rolled primitives. | open | `frontend/package.json`, UI components; config and primitive audit / `cd frontend && npm run build`; R | Frontend. |
| TSG-10-ROUTER / canonical routing | Data Mode route objects/lazy/loaders, central root auth, nearest error boundary, no effect redirects. | open | `frontend/src/main.tsx` uses BrowserRouter / browser auth/navigation E2E; R | Frontend; D: migration schedule. |
| TSG-10-ALT / alternate routing | TanStack Router only with ADR, not mixed with react-router. | not-applicable | No TanStack Router dependency / N | Frontend. |
| TSG-10-VERS / router versions | Monitor v8 after GA and plan upgrade; do not defer two quarters without ADR. | open | No quarterly router review record / —; R | Frontend; current upstream must be verified. |
| TSG-10-DATA / fetching | TanStack Query v5, generated Connect-Web 2 singleton, dedup refresh, stable serializable keys, mutation invalidation; no component-body fetch. | open | `frontend/package.json`, `frontend/src/App.tsx`, `docs/browser-sessions.md`; Axios REST remains / `cd frontend && npm run build && npx playwright test`; R | Frontend/API; D: Connect substitution. |
| TSG-10-FORMS / forms | Zod v4 + react-hook-form schema/type/submit/inline errors, shared schemas at explicit boundary. | open | Neither dependency in `frontend/package.json` / —; R | Frontend; D: form migration. |
| TSG-10-ICONS / icons | lucide named imports; 0.x→1.x upgrade review. | open | `frontend/package.json` pins `^0.451.0` / —; R | Frontend; assess actual supported version. |
| TSG-10-BUILD / build/test | One-command dev, static checked TS build, Vitest/Playwright; SSR only with ADR. | open | `frontend/package.json`, `frontend/playwright.config.ts` / `cd frontend && npm run build && npm run test`; R | Frontend/DevEx; dev orchestration incomplete. |
| TSG-10-NODE / Node tooling | Node 24 LTS or 26 Current pinned in engines/root/CI; 25 disallowed; tsx/tsup/pnpm SHOULD when relevant. | implemented/unverified | `.node-version`, `frontend/package.json`, CI pin / CI build; R | DevEx; Node-side bundling advice conditional. |
| TSG-10-NODESVC / Node services | General backend defaults Go; any Node service needs language ADR. | not-applicable | Go backend; no Node service identified / N | Architecture; revisit if one is added. |

## 11 — [Multi-language](https://technology-selection-guide.aws.ablabs.io/11-multi-language/)

| ID / subsection | Obligation and applicability | Status | Evidence; acceptance command / proof | Owner; decision |
|---|---|---|---|---|
| TSG-11-TREE / language selection | Go runtime/operator, TS browser, YAML cluster; small Bash, Python data/scripts; other languages need prior ADR with alternatives, boundary and four-quarter owner. | open | `cmd/`, `frontend/`, `deploy/`, native/eBPF `third_party/`; no language ADR register / —; R | Architecture; D: C/native exception. |
| TSG-11-PY / Python | 3.12+, locked uv/poetry/pip-compile, quarterly refresh, pip-audit, pytest, type checker, Ruff, shared telemetry, vendored wheels if deployed. | open | `.github/workflows/ci.yml` pins 3.12 and audits harness; script/tooling audit / `make test-tooling security`; R,L if shipped | DevEx/QA; distinguish CI-only from production Python. |
| TSG-11-BASH / Bash | ~200-line cap, strict shebang/flags, ShellCheck, quoted variables, dependency preflight, no stateful daemon, SHOULD smoke help/dry run. | open | `scripts/lint-shell.sh`, ShellCheck CI; length/preflight audit / `make lint-shell`; R | DevEx; D for long existing scripts. |
| TSG-11-YAML / YAML | YAML manifests, Helm v4 new charts/upgrade plan, build-time validation, immutable image digests, no duplicated env copies/long inline shell. | open | `deploy/charts/constellation/`, `make helm-lint helm-template-smoke`; mutable image tags remain / R,L | Platform; D: Helm v3→v4 schedule. |
| TSG-11-LOCK / dependencies | Lockfiles for each language, quarterly refresh, exact revisions, review upgrades. | open | `go.sum`, `frontend/package-lock.json`; Python/Helm lock inventory / —; R | DevEx/security. |
| TSG-11-SBOM / supply chain | Per-language SBOM + PR vuln scan + signed artifact; vetted upstream; no curl-pipe-shell in build/deploy. | open | `.github/workflows/ci.yml`, release workflow; native/Python/Helm matrix / `make security` plus release artifact inspection; R,L | Release/security. |
| TSG-11-PIN / runtimes | Root runtime pins agree with CI and Dockerfiles, including chart Kube range. | open | `go.mod`, `.node-version`, `frontend/package.json`, Dockerfile literal Go defaults / —; R | DevEx/release. |
| TSG-11-OBS / telemetry parity | All long-lived languages share logs/metrics/traces and propagate W3C traceparent; no silent sidecar. | open | `internal/obslog/`, native agent/sidecar review / —; R,L | Observability. |
| TSG-11-TEST / testing parity | Every language PR suite, real transport boundaries, blocking failures. | open | Go/frontend CI and ShellCheck; native/Python/Helm test matrix / `.github/workflows/ci.yml` plus hosted proof; R | QA/CI. |
| TSG-11-ADR / ADR discipline | First nontrivial language slice and later PRs cite approved scope; consolidate or delete grown/stale scripts. | open | No language ADR register; repository inventory / —; R | Architecture. |

## Decision register — none approved

| Decision ID | Controls affected | Decision required before claiming conformance | Required approval record |
|---|---|---|---|
| D-API | TSG-01-ENUM, 03-ROUTER/CHAIN/ERROR/PAGE/ENUM/WEB, 06-RBAC, 08-ENUM, 10-DATA | Migrate REST/OpenAPI/Axios to Connect/proto or acknowledge mandatory nonconformance; test transport, pagination and tenant guard either way. | ADR, architecture/security approvers, rationale, residual risk, compensating controls, review date. |
| D-DATA | TSG-02-SQLC/GOOSE/DELETE/KEYROW/JSONB | Migrate to sqlc/embedded Goose and audited schemas or explicitly accept remaining nonconformance; define data-retention exceptions. | ADR and data/security sign-off with migration/rollback plan. |
| D-AUTH | TSG-06-JWT | Guide says cookie wins when both cookie and Authorization present; Constellation deliberately makes explicit bearer header win. Decide with CSRF/confused-deputy threat analysis. | Security ADR, negative browser/CLI tests, approver/date. |
| D-OBS | TSG-05-LOG/OTEL/METRICS/PGX | Keep slog/stdout, OTLP/HTTP and client Prometheus or adopt guide stack; document losses and controls. | Observability/security ADR with deployed telemetry comparison. |
| D-IMAGE | TSG-04-IMAGE, 09-OCI, 11-SBOM | Native/privileged runtime images and amd64-only release depart from minimal dual-arch model. Determine qualified fleet and exception scope. | Release/security ADR, SBOM and arch matrix, owner/risk/review date. |
| D-TOOL | TSG-04-AIR/DEVSH/K3S, 07-DB/PW, 10-ROUTER/FORMS/ICONS, 11-YAML/BASH | Decide whether current dev/test/UI/Helm choices are migrated or consciously retained; SHOULD departures need documented trade-off. | Per-domain ADR(s), not a blanket waiver. |
| D-VERSION | TSG-01-PLATFORM, 04-GOVERSION, 10-VERS/ICONS, 11-YAML/PIN | Verify current upstream versions/support before interpreting May 2026 predictions, and reconcile root/build/chart pins. | Quarterly version review with source URLs, compatibility tests and dated owner. |

No deviation row can be promoted to `approved-deviation` from this register alone. An approval must state the **specific control IDs**, decision, alternatives, rationale, residual risk, compensating controls, accountable owner, approver, date, and next review date. An approved MUST departure remains nonconforming and is reported separately from verified controls.

## TSG-1 checklist disposition

| Plan bullet | Honest disposition after this document | Remaining acceptance |
|---|---|---|
| Chapter/section control IDs, MUST/SHOULD, MAY, N/A | **Inventory portion may close** if reviewers agree each grouped control covers its entire cited subsection. This document gives stable IDs, conditional MAY decisions and explicit N/A cases. | Review completeness against the pinned guide hash; split any family whose clauses need independent status. Future source changes add/revise IDs without renumbering existing ones. |
| Per-control status, evidence, tests, owner, command, live proof | **Keep open.** Status and candidate evidence/owner are present, but several commands are `—`, negative tests are not enumerated per row, no live run is attached, and owners are proposed rather than assigned. | Assign accountable owners; add command and positive/failure artifact links for every applicable row; capture deployed proof for `L` rows. |
| ADRs for retained departures | **Keep open.** Decision register is not approval. | Write and approve the specific ADRs above; capture risk/controls/review dates. |
| Resolve guide inconsistencies | **Keep open.** The conflict is explicitly identified: chapters 03/06 require no browser localStorage tokens, while chapter 10 allows a transition. **Stronger 06 rule is the target**, and Constellation uses secure cookies. Dated router/Helm/version advice is flagged for review, not resolved by assumption. | Security approval of bearer precedence, live auth proof, and current upstream router/Helm/version assessment. |
| Quarterly review and CI evidence report | **Keep open.** Snapshot and process are described but not scheduled or automated. | Named owner/cadence, source-diff gate, per-control evidence report in CI, and release-claim policy. |

Conservative recommendation: do **not** check the first plan bullet until the grouped-clause coverage is reviewed; the other four bullets definitively remain open. This new file is deliberately not a second task tracker: the parity plan continues to own checklist status.
