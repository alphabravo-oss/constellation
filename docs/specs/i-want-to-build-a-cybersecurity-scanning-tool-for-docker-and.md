# Constellation — Container & Kubernetes Security Platform

> Working name: **Constellation** (internal codename: golden-dome). Repository directory: `/Users/mj/mjcode/ab/golden-dome/`.
> Specification compiled 2026-05-11 from lisa-plan interview.

## Overview

**Constellation** is a comprehensive container and Kubernetes cybersecurity platform that combines the strengths of three reference systems present locally in the repository tree:

- **NeuVector** (`./neuvector/`) — runtime DPI / L7 firewall, auto-generated network policies, process baselining.
- **StackRox** (`./stackrox/`) — admission control, posture management (CSPM), risk-prioritized dashboard, ClairCore-based vuln scanning.
- **Astronomer-Go** (`./astronomer/`) — multi-cluster K8s control plane (Chi/Go 1.25 backend + Next.js 16 / React 19 / Radix UI / Tailwind / TanStack Query frontend) with hub-and-spoke WebSocket-tunnel agent architecture.

Constellation plugs into Astronomer as the implementation of its already-reserved `/api/v1/security/*` feature space (analogous to how NeuVector integrates with Rancher), AND ships as a fully standalone product.

## Problem Statement

The container security tooling landscape in 2025–2026 forces customers to stitch together fragmented products: Trivy/Grype for image scanning, Falco for runtime, Kyverno/OPA for admission, kube-bench for compliance, separate dashboards for each. NeuVector and StackRox each solved part of this years ago but: (a) StackRox's UI is dated, (b) NeuVector's deployment story is heavy, (c) neither integrates natively with modern multi-cluster control planes like Astronomer, (d) neither offers reachability-confirmed risk scoring across both build-time and runtime.

Constellation offers a **single, polished, Astronomer-native security platform** that covers every pillar — image scan, IaC scan, admission (with signature verification), runtime (with WAF + DLP enforcement), posture, cloud configuration (CSPM), compliance, network policy, and AI/ML workload security — with a unified risk model, an aggregator-style scanner architecture that lets us start from the best open-source engines, MITRE ATT&CK-mapped runtime events, GitOps drift detection, developer-experience integrations (VS Code, GitHub/GitLab Apps, PR comments), migration tools from competing products, trend analytics + industry benchmarking, and a separate CVE-DB pipeline that supports both online and airgapped deployments.

An **optional cross-product GenAI Assistant integration surface** is defined but the implementation is deferred to a unified Alpha Bravo AI workstream that spans Constellation, Astronomer, and future products — Constellation must remain fully functional with the AI layer disabled.

## Scope

### In Scope (full v1 platform — all pillars)

1. **Image / SBOM scanning** — registries, images, layers, packages (OS + language ecosystems), SBOMs (SPDX 2.3 + CycloneDX 1.6).
2. **Vulnerability management** — CVE DB ingestion + enrichment + airgapped delivery, composite risk scoring, finding lifecycle.
3. **Admission control** — Kyverno-first webhook with pluggable engines (OPA/Rego in v2, K8s CEL ValidatingAdmissionPolicy in v3) + curated policy catalog + **image signature verification** (cosign/sigstore; verify customer images, not just our releases) as a first-class admission rule.
4. **Kubernetes posture management (CSPM)** — kube-bench-driven CIS checks + custom posture rules.
5. **Cloud posture (cloud-CSPM)** — basic AWS/GCP/Azure config scanning at v1: IAM over-privilege detection, S3/GCS/Blob public-access checks, EKS/GKE/AKS control-plane misconfig. Deeper coverage (compute, networking, serverless) deferred to v2.
6. **Infrastructure-as-Code (IaC) scanning** — first-class pillar (not buried in image scan): Terraform, Helm charts, Kustomize, Dockerfile, K8s manifests, CloudFormation. Maps misconfigs to the same `Finding` schema.
7. **Supply chain security** — SBOM (SPDX + CycloneDX), SLSA provenance, in-toto attestations, cosign signature verification on admission, dependency provenance (image → build → repo lineage).
8. **OSS license risk** — license detection from Syft/Trivy surfaced as compliance-class findings (GPL/AGPL/copyleft policy violations) with a configurable license-policy catalog.
9. **Runtime threat detection** — eBPF agent (syscalls + process tree + network 5-tuples) + L7 DPI (HTTP, gRPC, DNS, SQL, Kafka payload inspection — NeuVector parity) + Falco rules ingestion.
10. **Runtime WAF + DLP enforcement (NeuVector parity)** — distinct from DPI observation: **WAF** rule engine for inline HTTP/gRPC payload blocking (SQLi, XSS, path traversal, custom regex); **DLP** rule engine for sensitive-data exfiltration blocking (CC/SSN/custom patterns) at L7. Both rule sets have learn/monitor/enforce modes per workload.
11. **Workload behavior baselining** — process baselining (NeuVector parity) + **API endpoint baselining** (learn expected request paths/methods per workload; alert on drift). Both feed into the auto-policy generation pipeline.
12. **Reachability analysis** — static call-graph at scan time (Go, Java, Python initially) + runtime confirmation via in-cluster agent.
13. **Network policy** — observed-flow learning mode → auto-generate Cilium NetworkPolicy, Calico GlobalNetworkPolicy, and native K8s NetworkPolicy.
14. **Resource & Traffic Map** — live force-directed UI of workloads + observed edges colored by security state (NeuVector parity).
15. **Container quarantine + forensics capture** (NeuVector parity).
16. **MITRE ATT&CK mapping** — every `RuntimeEvent` carries one or more ATT&CK technique IDs (T-numbers); UI lets users pivot from technique → affected workloads.
17. **GitOps / configuration drift detection** — Argo CD + Flux integrations; compare in-cluster state vs Git-declared state; alert on out-of-band changes to security-sensitive resources (RoleBindings, NetworkPolicies, admission webhooks).
18. **Risk-prioritized deployment dashboard + violation timeline** (StackRox parity).
19. **Image-level acceptance workflow** — beyond per-finding lifecycle: customers can accept-risk an *image* (with rationale + expiry + approver) so it stops alerting org-wide; tracked separately in the audit log.
20. **Compliance** — CIS K8s + CIS Docker + NIST 800-53/800-190 + NSA-CISA K8s Hardening + PCI-DSS 4.0 + HIPAA + SOC 2 + STIG/FedRAMP + **NIS2 (EU)** + **DORA (EU finance)** + **ISO 27001/27017/27018** + **CSA Cloud Controls Matrix (CCM)**, with a **custom-framework editor** so customers tune their own.
21. **Policy-as-code workflow** — `constellationctl policy-check`, `policy-validate`, `policy-export`, `policy-import` so policies live in Git, are reviewable in PRs, and can be diffed across environments (StackRox `roxctl` parity).
22. **CI/CD integration** — `constellationctl` CLI + GitHub Action + GitLab CI templates that fail builds on policy violations.
23. **Developer experience layer** — **VS Code extension** (inline finding markers, hover-to-explain, quick-fix suggestions), **GitHub App** + **GitLab App** posting PR comments with findings on changed files, `pre-commit` hook integration.
24. **Reporting/Export** — SARIF, JSON, CSV, branded PDF compliance reports + executive summaries, CycloneDX/OpenVEX statements, SLSA + in-toto provenance.
25. **Trend analytics + industry benchmarking** — per-org dashboards tracking mean-time-to-fix, finding velocity, fix rate by team/repo, with anonymous opt-in benchmarking against industry P25/P50/P75 (similar to Snyk Insights, Wiz Reports).
26. **ITSM/Chat integrations** — Jira, ServiceNow, Slack, PagerDuty, webhooks, with Alertmanager-style routing tree per org.
27. **Plugin / extensibility** — gRPC-pluggable scanners, enrichers, exporters (Go interfaces internally; out-of-process gRPC for 3rd parties).
28. **Migration tools** — `constellationctl import --from {stackrox|neuvector|aqua|prisma}` for policies, exceptions, and acceptance records. Removes the #1 evaluator objection.
29. **AI/ML workload security** — ML model file scanning (HuggingFace safetensors integrity, detection of unsafe-deserialization payloads in model artifacts, ONNX integrity verification), Model BOM (MBOM) emission, AI-workload tagging on inferred or labeled workloads, runtime policies for model inference endpoints.
30. **Privacy + data residency** — configurable PII redaction in findings/audit logs (configurable patterns + per-field redaction); per-tenant data-residency pinning for SaaS deployments (EU customer data stays in EU region).
31. **Optional GenAI Assistant via Abbot** — Constellation consumes **Abbot** (the shared Alpha Bravo GenAI gateway, spec at `docs/specs/abbot-architecture.md`) for all AI features. Architecture is hybrid: Constellation imports the `abbot-go` library (handles RBAC enforcement, local audit writes, pgvector RAG, tool catalog registration, per-product redaction policy) which talks to the Abbot service (handles the three downstream wire protocols — OpenAI Chat Completions / OpenAI Responses / Anthropic Messages — plus provider routing, cost accounting, rate limits, central operational log, prompt versioning). Constellation contributes: (a) pgvector embedding columns on `findings` / `assets` / `policies` / `cve_records` with a background embedding worker; (b) a Constellation tool catalog registered at startup with read-side tools (`list_findings`, `search_findings_semantic`, `get_compliance_report`) and write-side tools gated on explicit RBAC verbs (`triage_finding`, `suppress_finding`, `accept_risk`); (c) a `POST /api/v1/ai/query` endpoint that the library handles. Constellation must run with Abbot disabled or unreachable — every AI-powered affordance has a non-AI fallback. AI is off by default per org.
32. **Standalone + Astronomer-integrated modes** — runs both ways; in-cluster agents reuse Astronomer's WebSocket reverse tunnel when present.

### Registry / Runtime / Distro coverage at v1
- **Registries (9):** Docker Hub, ECR, GCR/Artifact Registry, ACR, Quay, Harbor, GHCR, GitLab, JFrog Artifactory.
- **Container runtimes:** containerd, CRI-O, Docker.
- **K8s distros:** vanilla K8s, EKS, GKE, AKS, OpenShift, Rancher RKE, K3s, MicroK8s, Talos.

### Out of Scope (deferred to v2 or beyond)
- Original CVE intelligence / CNA status / private disclosure program (aspirational; not v1).
- VM-based workloads + serverless containers (ECS, Fargate, Cloud Run) — agentless cloud scanning.
- Wiz-class large-enterprise scale (1K clusters / 1B findings) — requires sharded Postgres + ClickHouse + multi-region; v1 targets mid-market self-hosted + small SaaS.
- WASM-sandboxed plugin runtime (v1 uses gRPC out-of-process plugins; WASM later).
- Commercial vendor advisory ingestion (Microsoft, Cisco, Oracle).

## Reference Architecture

### Stack
- **Language:** All-Go monorepo (matches all three reference repos). C/C++ reserved for DPI hot path inside the runtime agent only.
- **Database:** PostgreSQL with extensions — pgvector (embeddings/semantic search), pg_trgm (trigram GIN indexes accelerating case-insensitive substring/ILIKE CVE-ID lookup — substring matching, not similarity-ranked fuzzy search), partitioning for `findings` and `events`. **sqlc** for type-safe queries (matches astronomer pattern).
- **Frontend:** Next.js 16 + React 19 + Radix UI + Tailwind + TanStack Query + Zustand + Monaco + xterm — adopt astronomer/frontend's stack exactly so embedded views look native.
- **Inter-service:** gRPC + protobuf for all internal RPC and plugin boundary.
- **Observability:** OpenTelemetry SDK (traces + metrics + logs) emitted via OTLP; customer points it at their own collector. Prometheus metrics exposed at `/metrics` for backward compat.

### Scanner Architecture (multi-engine aggregator + dedupe)
Open-source engines integrated under a unified findings schema and dedupe/glue layer:
- **ClairCore** (Quay/Red Hat, MIT) — primary vuln matching (used by StackRox v4).
- **Syft** (Anchore, Apache-2.0) — SBOM generation.
- **Trivy** (Aqua, Apache-2.0) — secondary vuln matcher + IaC / secrets / misconfig.
- **Grype** (Anchore, Apache-2.0) — alternative matcher used for reconciliation/confidence.
- **Falco** (CNCF) — syscall rules engine for runtime.
- **Tetragon** or own eBPF programs — kernel telemetry.
- **Custom** — L7 DPI engine, static call-graph reachability analyzer, network-policy generator.

### Runtime Agent Architecture (most-capable path)
One DaemonSet pod per node, composed of five subsystems:
1. **eBPF programs** — syscalls, process tree, network 5-tuples, file events.
2. **Userspace L7 DPI** — protocol parsers (HTTP/1+2, gRPC, DNS, MySQL/Postgres wire, Kafka, Redis).
3. **WAF engine** — rule-based inline blocking of HTTP/gRPC payloads (SQLi, XSS, path traversal, custom regex). Modes: learn / monitor / enforce per workload. Inline data path via NFQUEUE + userspace verdict (NeuVector pattern).
4. **DLP engine** — rule-based inline payload inspection for sensitive-data exfiltration (PCI/PII patterns + custom regex). Same NFQUEUE/userspace pattern as WAF; separate rule store.
5. **Falco rules engine** — ingest community ruleset, map to our schema.
6. **MITRE ATT&CK mapper** — pure-Go library called by the agent before emitting events; maps `(syscall|net|file|L7) → []TechniqueID` using a curated mapping table updated alongside Falco rule updates.

### Runtime Enforcement Modes
Every enforcement subsystem (WAF, DLP, network policy, process baseline) supports three modes per workload:
- **Learn** — observe; record baseline; emit no alerts.
- **Monitor** — observe + alert; never block. Default for fresh workloads after learn window.
- **Enforce** — observe + alert + block. Customer-promoted; requires audit log entry.

### Static Scanner Pillar (build-time)
- **Image scanner** — ClairCore + Syft + Trivy + Grype as described.
- **IaC scanner** — Trivy IaC + Checkov-style rules wrapped under a unified `IaCFinding → Finding` schema. Inputs: Terraform (HCL/state), Helm charts (template-render then scan), Kustomize (build then scan), Dockerfiles, K8s YAML manifests, CloudFormation.
- **ML model scanner** — model artifact inspection for unsafe-deserialization payloads (e.g., pickle-based attack vectors in PyTorch/HuggingFace artifacts), ONNX integrity, safetensors integrity. Outputs Model BOM (MBOM) using CycloneDX 1.6 ML-BOM extension. Reuses the same finding schema with `kind=ml-model`.
- **Image signature verifier** — given an image reference + a configured trust policy (sigstore Rekor + Fulcio identity claims OR static cosign keys), verifies signatures + attestations. Used by both build-time and admission paths.

### Cloud Posture (cloud-CSPM) Pillar
- **Connector architecture** — each cloud provider has a connector that lists resources via the provider SDK and emits `CloudConfigFinding`. Reuses the same `Finding` schema with `kind=cloud-config`.
- **v1 coverage** — IAM (over-privileged roles, unused permissions, role chains), storage (public buckets), K8s control plane (audit logging, encryption at rest, private endpoint, OIDC).
- **Auth** — customer-provided IAM role (AWS), service account (GCP), workload identity (Azure). Read-only.
- **Out of scope at v1** — agentless VM scanning, full CSPM-equivalent coverage; that's the v2 "cloud workload" workstream.

### GitOps Drift Detection
- Argo CD + Flux read connectors call their APIs (or watch their CRDs) for declared state.
- Differ compares declared vs in-cluster state for a curated set of security-sensitive resources: `RoleBinding`, `ClusterRoleBinding`, `NetworkPolicy`, `ValidatingWebhookConfiguration`, `MutatingWebhookConfiguration`, `Secret`, `PodSecurityPolicy`/`Pod Security Admission labels`.
- Out-of-band changes emit a `DriftFinding` (same schema, `kind=drift`).

### Developer Experience Layer
- **VS Code extension** — connects to a Constellation server; pulls findings for the current repo; renders inline diagnostics; "Explain this CVE" + "Suggest fix" actions (Suggest-fix backed by GenAI surface when enabled, falls back to a curated remediation lookup).
- **GitHub App** — installs into customer GitHub org; on PR open, runs IaC scan + image scan (if new image refs detected in manifests) against the diff, posts a review comment with findings on changed files.
- **GitLab App** — analog using GitLab Apps API + merge-request notes.
- **`pre-commit` hook** — wraps `constellationctl image-check` + `constellationctl iac-check`.

### Trend Analytics + Benchmarking
- ETL job: nightly aggregation from `findings` + `events` + lifecycle transitions → `metrics_daily` materialized view (per org × per cluster × per severity × per pillar).
- UI: 90-day MTTF, finding velocity, fix-rate-by-team views.
- **Anonymous benchmarking** — opt-in per-org. ETL emits k-anonymous aggregates (org-size bucket, vertical, region) to a Constellation-operated aggregation service; service returns industry P25/P50/P75 lines that render alongside the customer's metric. Off by default; airgap deployments cannot opt in.

### Migration Tools
- `constellationctl import --from {stackrox|neuvector|aqua|prisma}` — each adapter reads the source product's policy export format and translates to Kyverno + Constellation policy YAML, preserving suppression/acceptance records.
- Round-trip test fixtures: golden inputs + expected outputs checked into the repo.

### AI/ML Workload Security
- **Model scanning** — invoked via `constellationctl model-check <path|registry-ref>` and from a registry connector when models are stored in OCI artifacts.
- **AI-workload tagging** — heuristic detector (image labels, common base images like `pytorch/*`, `tensorflow/*`, `huggingface/*`, GPU resource requests, common model server processes like `vllm`, `triton-inference-server`) tags workloads with `ai-workload=true`. Customers can label explicitly via annotation.
- **MBOM** — emitted on scan, attached to `Asset`, exported via SBOM endpoints alongside SPDX/CycloneDX.

### Privacy + Data Residency
- **PII redaction** — configurable patterns per org (regex set with a curated default of CC numbers, US SSN, EU national IDs, email addresses, IP addresses), applied at write-time to `findings.detail_json` and `audit_events.payload`. Original payload encrypted at rest with a per-org KEK accessible only to break-glass operators.
- **Data residency** — SaaS deployments pin each org to a region; Postgres + S3 archival both region-scoped. Cross-region replication off by default for resident orgs.

### GenAI Assistant Integration via Abbot (optional, cross-product)
Constellation consumes **Abbot** — the shared Alpha Bravo GenAI gateway, specified separately in `docs/specs/abbot-architecture.md`. Abbot is a hybrid library + service: each product imports the `abbot-go` library (in-process) which talks to the Abbot service (cross-product, centralized). The library owns product-specific concerns (RBAC, local audit, pgvector RAG, tool catalogs, redaction); the service owns cross-cutting concerns (wire protocols, cost, rate limits, provider routing). Constellation must run with Abbot unreachable.

**Constellation's contribution to Abbot:**
- **Semantic indexes** — `findings`, `assets`, `policies`, `cve_records` have an `embedding vector(1536)` column (pgvector); a background worker computes embeddings via the Abbot-configured provider when AI is enabled. **Embeddings stay in Constellation's Postgres** (data residency); Abbot never holds product domain data.
- **Tool catalog** — Constellation publishes a JSON Schema tool catalog to Abbot at startup. Read-side tools: `list_findings`, `get_finding`, `search_findings_semantic`, `list_assets`, `get_compliance_report`. Write-side tools (gated behind explicit RBAC verbs): `triage_finding`, `suppress_finding`, `accept_risk`. Tool execution happens inside Constellation via `abbot-go`, never inside Abbot itself; RBAC is re-checked per tool call.
- **NL query endpoint** — `POST /api/v1/ai/query` accepts a natural-language prompt; the `abbot-go` library forwards through Abbot which performs RAG (via the library's pgvector helper) + tool-calling. Constellation enforces RBAC on every tool call (AI cannot exceed the calling user's privileges).
- **Local audit writes** — every AI-initiated read and write produces an entry in Constellation's hash-chained `audit_events` table. This is the compliance audit; Abbot's own operational log is separate and not the compliance record.
- **Wire protocols downstream of Abbot** — the three protocols (OpenAI Chat Completions, OpenAI Responses, Anthropic Messages) are implemented inside the Abbot service, not inside Constellation. See `docs/specs/abbot-architecture.md` for full details. Constellation only speaks the **Abbot envelope** via the `abbot-go` library; it never speaks provider protocols directly.
- **Per-org configurability** — flows through Abbot: protocol, base URL, auth token, model name, enabled features, prompt-redaction rules. Constellation reads + displays these settings via a thin proxy through `abbot-go`.
- **Off-by-default + airgap-safe** — Constellation must build, deploy, test, and operate fully with Abbot service unreachable. Airgap deployments require an Abbot instance deployed inside the customer's airgapped environment, pointed at a self-hosted endpoint speaking one of the three protocols.
- **No hard dependency** — every UI affordance powered by AI has a non-AI fallback (NL search → keyword search; AI-summary → raw CVE description; AI-policy-gen → policy catalog browse). When `abbot-go` cannot reach the Abbot service, it signals graceful degradation and the UI falls back.
- **Implementation scope at Constellation v1** — Constellation Phase 5 ships pgvector columns + embedding worker + tool catalog registration + `POST /api/v1/ai/query` endpoint + `abbot-go` integration. Provider protocol bridges, cost accounting, rate limits, prompt versioning, and cross-product orchestration are all in the Abbot service, owned by the Abbot workstream — not in Constellation.

### CVE Database (separate repo + pipeline)
- **Sources (all):** NVD 2.0, OSV.dev, GHSA, distro feeds (RHEL, Debian, Ubuntu, Alpine, Wolfi, Chainguard), KEV (CISA), EPSS.
- **Strategy:** aggregator + enrichment service of our own (no trivy-db wrapper for v1; trivy-db used only as **v0 bootstrap** in Phase 1).
- **Delivery:** **signed OCI artifact** (cosign-signed) updated 4×/day. Customer `oras pull` into airgap; service imports into Postgres.
- **Repo:** lives outside the main Constellation monorepo (`constellation-vulndb/`) so its pipeline can ship independently.

### Astronomer Integration
- **Standalone service + adapter.** Constellation has its own Postgres + APIs. Astronomer talks to it like ArgoCD — calls Constellation's API, mounts its UI under `/api/v1/security/*` and the existing left-nav placeholder.
- **In-cluster network path:** reuse Astronomer's existing outbound WebSocket reverse tunnel. Constellation's data is multiplexed onto it. Standalone mode opens its own gRPC+mTLS tunnel.
- **Identity:** Astronomer is the primary IdP when present; Constellation validates JWT via JWKS. Standalone mode ships **local users (Argon2id hashes) + OIDC/SAML SP** so customer can use Okta/Auth0/Azure AD/Keycloak — break-glass local accounts always available.
- **Tenancy:** mirror Astronomer's 3-tier **Org > Cluster > Project** hierarchy in both standalone and integrated modes.
- **RBAC:** mirror Astronomer's resource/verb model + add security-specific verbs (`read-findings`, `triage-findings`, `suppress-findings`, `accept-risk`, `manage-policies`, `manage-cve-db`, `manage-runtime-rules`).

### Deployment Model
- **K8s Operator + Helm chart.** Helm installs the operator and CRDs. `ConstellationCluster` CRD owns the lifecycle of the in-cluster components. GitOps-friendly, self-healing, supports blue/green upgrades.
- Constellation control plane also deployable via Helm or docker-compose for SaaS / on-prem.

### Findings Data Model (central concept)
- **Severity / risk:** composite **Constellation Risk Score (0–100)** combining CVSS base + KEV multiplier + EPSS probability + reachability boost + asset criticality. Override-able. The score is our differentiator; inputs are industry-standard.
- **Lifecycle states:** `Open → Triaged → In-Progress → (Resolved | Suppressed | Accepted)` — full SOC workflow with assignee, priority, expiry on Accepted, fix-verification on Resolved.
- **Provenance:** every finding records which engines (Clair/Trivy/Grype/Syft/etc.) reported it + confidence + raw payload for audit.

### Audit Log
Immutable, append-only Postgres table + S3 archival + **hash-chain tamper detection** (each row contains hash of previous). Periodically frozen to S3 with cosign-signed manifests. Matches FedRAMP/SOC 2 expectations.

### Notifications / Routing
Alertmanager-style routing tree per org: routes match on severity threshold + cluster + labels → channels (Slack/Jira/ServiceNow/PagerDuty/webhook). Inhibition / grouping / throttling. UI for simple cases; raw YAML for power users.

### Backup / DR
Postgres logical backup managed by Constellation operator → S3-compatible object store (MinIO works for on-prem). Blue/green upgrades orchestrated by operator.

### Frontend Information Architecture
**Risk-first** left-nav: Dashboard → Findings → Assets → Policies → Compliance → Runtime → Network (Traffic Map) → CVE DB → Settings.

## User Stories

> Phase-1 stories are sized for one focused coding session each. Later phases are coarser feature buckets — each will be expanded into per-pillar stories at the start of that phase.

### Phase 1 — Foundations (14 stories, runnable largely in parallel after P1-US-1 + P1-US-2)

#### P1-US-1: Shared protobuf contracts repo
**As a** parallel sub-team, **I want** a single shared `proto/` package with all cross-pillar message types and gRPC service definitions, **so that** every pillar can mock interfaces and develop independently.
**Acceptance Criteria:**
- [ ] `proto/constellation/v1/*.proto` defines: `Finding`, `Asset`, `Scan`, `Policy`, `PolicyDecision`, `RuntimeEvent`, `NetworkFlow`, `ComplianceCheck`, `AuditEvent`.
- [ ] `proto/constellation/v1/services/` defines gRPC services: `Scanner`, `Admission`, `Runtime`, `Compliance`, `Findings`, `Notifications`, `CVEDB`.
- [ ] `buf generate` produces Go bindings into `gen/go/`.
- [ ] `buf lint` and `buf breaking` configured.
- [ ] CI checks: `buf lint`, `buf breaking --against main` pass.

#### P1-US-2: Postgres schema + sqlc + migrations
**As a** Constellation engineer, **I want** the canonical Postgres schema codified in `db/migrations/` with sqlc queries in `db/queries/`, **so that** every service uses the same data model with compile-time-checked SQL.
**Acceptance Criteria:**
- [ ] Tables: `orgs`, `clusters`, `projects`, `users`, `api_tokens`, `assets`, `images`, `findings` (partitioned by month), `events` (partitioned by month), `policies`, `compliance_checks`, `audit_events` (append-only, hash-chained), `cve_records`, `sbom_documents`.
- [ ] `pgvector` + `pg_trgm` extensions enabled.
- [ ] `goose` migrations apply cleanly forward and back on Postgres 16.
- [ ] `sqlc generate` produces typed query funcs into `gen/db/`.
- [ ] Integration test: spin up Postgres in testcontainers, apply all migrations, run a representative query.

#### P1-US-3: Control-plane API skeleton (Chi + OpenAPI)
**As a** frontend developer, **I want** the API server running with versioned routing, OpenAPI spec, and CORS, **so that** I can wire UI calls before backend logic exists.
**Acceptance Criteria:**
- [ ] `cmd/constellation-api/main.go` boots Chi router on `:8080`.
- [ ] `GET /healthz` returns 200; `GET /readyz` returns 200 only when DB is reachable.
- [ ] Routes mounted under `/api/v1/`.
- [ ] OpenAPI 3.1 spec served at `/openapi.json`; generated from `oapi-codegen` annotations or hand-written.
- [ ] CORS, request-id middleware, slog JSON logger.

#### P1-US-4: Auth — local users (Argon2id) + OIDC SP
**As a** customer, **I want** to log in via OIDC (Okta/Auth0/Azure AD/Keycloak) or local credentials, **so that** Constellation works in both managed and airgapped environments.
**Acceptance Criteria:**
- [ ] `POST /api/v1/auth/login` (local) + `GET /api/v1/auth/oidc/start` + `/api/v1/auth/oidc/callback`.
- [ ] Local password hashes use Argon2id with sensible params (memory ≥ 64MB, iterations ≥ 3).
- [ ] JWT issued (HS256 with rotating key, configurable).
- [ ] `POST /api/v1/auth/logout` revokes session.
- [ ] Integration test covers OIDC callback against a dex test container.

#### P1-US-5: RBAC engine + Astronomer-mirror tiers
**As an** admin, **I want** to assign roles at Org / Cluster / Project scopes with security-specific verbs, **so that** I can grant least-privilege access.
**Acceptance Criteria:**
- [ ] `pkg/rbac` exports `func Authorize(ctx, subject, verb, resource) error`.
- [ ] Built-in roles: `Viewer`, `Triager`, `SecOps`, `Admin`, `SuperAdmin`.
- [ ] Verbs implemented: `read-findings`, `triage-findings`, `suppress-findings`, `accept-risk`, `manage-policies`, `manage-cve-db`, `manage-runtime-rules`.
- [ ] HTTP middleware reads JWT, resolves subject, calls Authorize.
- [ ] Unit tests for each role × verb × scope.

#### P1-US-6: Audit log w/ hash chain + S3 archival
**As a** compliance auditor, **I want** every privileged action (suppress finding, change policy, rotate token) recorded immutably with tamper-evidence, **so that** I can prove integrity in audits.
**Acceptance Criteria:**
- [ ] Every write through `pkg/audit.Log(ctx, action, target, before, after)` appends a row.
- [ ] Each row stores hash of previous row's hash + canonical row content (SHA-256).
- [ ] `cmd/audit-archiver` is a cron-style job freezing rolling windows to S3 with cosign-signed manifests.
- [ ] `constellationctl audit verify` walks the chain and reports any break.

#### P1-US-7: OpenTelemetry SDK + Prometheus metrics plumbing
**As an** SRE, **I want** every service to emit OTLP traces/metrics/logs and `/metrics` Prom endpoint, **so that** I can wire Constellation into Datadog/Grafana/Honeycomb.
**Acceptance Criteria:**
- [ ] `pkg/observability.Init(ctx, serviceName)` returns shutdown func and is called by every service main.
- [ ] OTLP exporter target configurable via env: `OTEL_EXPORTER_OTLP_ENDPOINT`.
- [ ] Default metrics: HTTP request duration histogram, gRPC server histogram, DB query histogram.
- [ ] `/metrics` Prometheus endpoint on every service.

#### P1-US-8: Frontend shell — Next.js 16 + Radix + Tailwind + sidebar nav
**As a** user, **I want** a Constellation app that visually matches Astronomer with the 9-item left-nav and themed pages, **so that** the integrated experience feels native.
**Acceptance Criteria:**
- [ ] `frontend/` Next.js 16 + React 19 + Tailwind config copied from astronomer/frontend.
- [ ] Left-nav links: Dashboard / Findings / Assets / Policies / Compliance / Runtime / Network / CVE DB / Settings (each renders an empty themed view).
- [ ] Dark + light themes via `next-themes`.
- [ ] `npm run build` and `tsc --noEmit` pass.
- [ ] `npm run dev` opens a working app at `localhost:3000`.

#### P1-US-9: Frontend auth pages + session
**As a** user, **I want** to log in via OIDC or local credentials and see my profile in the header, **so that** I can use the app.
**Acceptance Criteria:**
- [ ] `/login` page calls API auth endpoints; OIDC redirect works.
- [ ] `next-auth` v5 wired against Constellation API as a custom provider.
- [ ] Header shows user name + org switcher (if multiple orgs).
- [ ] Logout button works.
- [ ] Protected routes redirect to `/login` when no session.

#### P1-US-10: CVE DB v0 pipeline scaffold (trivy-db bootstrap, our schema)
**As an** engineer, **I want** a bootstrap pipeline that pulls trivy-db daily and imports it into our `cve_records` schema, **so that** image scanning has data to match against on day 1 while we build the full aggregator.
**Acceptance Criteria:**
- [ ] Separate repo `constellation-vulndb/`.
- [ ] `cmd/vulndb-bootstrap` pulls trivy-db OCI artifact, converts to our schema, writes to Postgres.
- [ ] Cron CI runs daily; output verified.
- [ ] Schema includes columns for future enrichment fields (`kev_listed`, `epss_score`, `reachability_hint`).
- [ ] Smoke test: import full DB, count > 200 000 CVE rows.

#### P1-US-11: CVE DB OCI publisher (cosign-signed bundle)
**As an** airgapped customer, **I want** to `oras pull` a signed CVE bundle from a registry, **so that** I can update Constellation without internet access.
**Acceptance Criteria:**
- [ ] `cmd/vulndb-publisher` exports a postgres snapshot to OCI artifact via `oras` Go library.
- [ ] Artifact cosign-signed with a Constellation-owned key.
- [ ] `cmd/vulndb-importer` (runs on customer side) pulls + verifies signature + imports to local Postgres.
- [ ] Test: full round-trip on local OCI registry (zot or distribution).

#### P1-US-12: K8s operator + ConstellationCluster CRD + Helm chart
**As an** ops user, **I want** to install Constellation with `helm install` and manage in-cluster components via a CRD, **so that** lifecycle is GitOps-friendly.
**Acceptance Criteria:**
- [ ] `deploy/operator/` contains operator built with `operator-sdk` or `kubebuilder` v4.
- [ ] `ConstellationCluster` CRD with initial spec (`scannerEnabled`, `admissionEnabled`, `runtimeEnabled` flags).
- [ ] `deploy/charts/constellation/` Helm chart installs operator + CRDs.
- [ ] `helm install` + `kubectl apply -f sample-cr.yaml` succeed on kind cluster.
- [ ] Operator e2e test on kind via Chainsaw or kuttl.

#### P1-US-13: Astronomer adapter v0 — JWKS validation + tunnel mount
**As an** Astronomer admin, **I want** Constellation to recognize Astronomer JWTs and ride the existing agent tunnel, **so that** the integrated experience requires zero extra plumbing.
**Acceptance Criteria:**
- [ ] `pkg/astronomer/adapter` validates JWT via Astronomer JWKS (configurable URL).
- [ ] On a request to `/api/v1/security/*` from Astronomer, the user's Astronomer identity becomes a Constellation subject (cross-reference table).
- [ ] `internal/tunnel-client` is a Go package that opens a sub-channel on the Astronomer agent's WebSocket multiplex.
- [ ] Integration test: deploy astronomer-go + constellation-api in docker-compose; OIDC handshake + tunnel sub-channel both work.

#### P1-US-14: `constellationctl` CLI scaffold
**As a** developer, **I want** a CLI for image-check, login, audit-verify, and scan-trigger commands, **so that** I can integrate Constellation into CI and operate it from shell.
**Acceptance Criteria:**
- [ ] `cmd/constellationctl/main.go` built with `cobra`.
- [ ] Commands: `login`, `image-check <ref>` (initial CLI response before scanner wiring), `audit verify`, `version`.
- [ ] `--server` flag, `~/.constellation/config.yaml` for persistent config.
- [ ] `goreleaser` config builds for macOS+Linux+Windows × amd64+arm64.

### Phase 2 — Scan (feature buckets; will be expanded into stories at start of P2)
- Image scanner service (ClairCore + Syft + Trivy + Grype, normalized into our findings schema, deduped, provenance-tagged).
- **IaC scanner pillar** — **Trivy IaC** wrapped as the v1 engine across Terraform, Helm, Kustomize, Dockerfile, K8s manifests, CloudFormation; Trivy's `Misconfiguration` JSON normalized into the `Finding` schema with `kind=iac`. Checkov is *not* bundled at v1 (deliberate — avoids embedding Python in the build / FIPS / airgap stories); a reference Checkov plugin against the gRPC plugin SDK ships at Phase 5 for customers who need its broader rule pack.
- **OSS license risk** — extract license data from Syft, emit as `kind=license` findings against a default + customer-configurable policy (deny AGPL/GPL by default for commercial workloads, configurable per project).
- **Image signature verifier service** — verifies cosign signatures + in-toto attestations against configured trust policies; used by both build-time scans and the Phase 3 admission webhook.
- Findings UI: list, detail, filter by risk/severity/CVE/asset, suppress/accept-risk workflow, comments thread.
- **Image-level acceptance workflow** — accept-risk an image-digest (rationale + expiry + approver); separately auditable from finding-level acceptance.
- Composite **Constellation Risk Score** computation pipeline (CVSS + KEV + EPSS + reachability + asset criticality).
- SBOM endpoints: emit SPDX 2.3 + CycloneDX 1.6 per image; **MBOM** (CycloneDX ML-BOM extension) per AI/ML model artifact.
- **Static reachability** for Go (govulncheck pattern), Java (call-graph extraction via WALA or CodeQL-style), Python (Jedi/Pyre).
- Registry connectors: Docker Hub, ECR, GCR/Artifact Registry, ACR, Quay, Harbor, GHCR, GitLab, JFrog.
- Exports: SARIF, JSON, CSV.
- CI/CD: `constellationctl image-check` produces SARIF + nonzero exit on policy violation; GitHub Action + GitLab CI templates.
- **`constellationctl iac-check` + `model-check`** — same SARIF + exit-code contract as `image-check`.
- **GitHub App + GitLab App** — install into customer org/group, run image+IaC scan against PR/MR diffs, post line-level review comments on changed files.
- **`pre-commit` hook config** for `constellationctl` checks.
- **VS Code extension** — inline diagnostics for `Findings` against the active workspace; auth via Constellation API token.
- CVE DB v1: replace trivy-db wrapper with own aggregator (NVD + OSV + GHSA + distros + KEV + EPSS).

### Phase 3 — Admit & Posture
- Kyverno-based admission webhook + pluggable engine interface (OPA/Rego, K8s CEL adapters deferred).
- **Image signature verification admission rule** (first-class in the policy catalog): block unsigned images, block images not signed by a configured identity, block images missing required attestations (SLSA build provenance + in-toto materials).
- Curated **policy catalog** UI: named policies with one-click toggles + custom Kyverno YAML escape hatch.
- **Policy-as-code workflow** — `constellationctl policy-check`, `policy-validate`, `policy-export`, `policy-import`; CI checks that diff policies before merge and dry-run them.
- kube-bench wrapper + CIS Kubernetes + CIS Docker mapping into our `compliance_checks` schema.
- Compliance mappings: NIST 800-53, NIST 800-190, NSA-CISA Kubernetes Hardening, PCI-DSS 4.0, HIPAA, SOC 2, STIG, FedRAMP, **NIS2 (EU)**, **DORA (EU finance)**, **ISO 27001 / 27017 / 27018**, **CSA Cloud Controls Matrix (CCM)**.
- **Custom-framework editor** (UI): users compose their own framework from primitive checks; exportable.
- **Cloud-CSPM (v1 scope)** — AWS / GCP / Azure connectors that scan IAM (over-privilege detection), public storage exposure, and managed-K8s control-plane configuration. Findings reuse the standard schema with `kind=cloud-config`.
- **GitOps / config drift detection** — Argo CD + Flux integrations comparing declared vs actual state on security-sensitive resources; emit `kind=drift` findings.
- Compliance dashboard + PDF report templates + executive summary PDFs.
- StackRox-style **risk-prioritized deployment dashboard** + violation timeline.

### Phase 4 — Runtime
- **eBPF agent** subsystem (syscalls + process tree + network 5-tuples + file events).
- **L7 DPI engine** subsystem (HTTP/1+2, gRPC, DNS, MySQL/Postgres wire, Kafka, Redis) — NeuVector parity.
- **WAF rule engine** — inline payload blocking for HTTP/gRPC (SQLi, XSS, path traversal, custom regex). Built-in rule pack + custom rules. Modes: learn / monitor / enforce per workload. NeuVector parity.
- **DLP rule engine** — inline payload inspection + blocking for sensitive-data exfiltration (PCI, US SSN, EU national IDs, custom regex). Same engine framework as WAF; separate rule store. NeuVector parity.
- **Falco rules ingestion** subsystem (community ruleset → our event schema).
- **MITRE ATT&CK mapping** — every `RuntimeEvent` carries `attack_techniques []string` (T-numbers). UI pivots: technique → events → workloads. Curated mapping table version-pinned with each agent release.
- **Resource & Traffic Map** UI (react-flow): live workload + observed-edge graph colored by security state; ATT&CK technique heatmap overlay.
- **Process baselining** (learn → monitor → enforce) + **API endpoint baselining** (HTTP path/method per workload) + **container quarantine** + **forensics capture** (process tree + pcap on alert).
- **Runtime reachability** confirmation: observed symbol execution marks findings as `reachable-confirmed`.
- **Auto network-policy generation**: 14-day learn window → output Cilium NetworkPolicy / Calico GlobalNetworkPolicy / native K8s NetworkPolicy for review + apply.
- **AI/ML workload runtime policies** — when a workload is tagged `ai-workload=true`, agent applies AI-specific defaults: log inference endpoint URIs called, alert on outbound calls to non-allowlisted model registries, baseline expected GPU/CPU/memory shapes.

### Phase 5 — Polish & Enterprise
- VEX (OpenVEX + CycloneDX VEX) outputs + SLSA + in-toto provenance attestations.
- Airgap CVE bundle GA — daily cosign-signed OCI artifact + offline importer hardening.
- ITSM integrations: Jira, ServiceNow, Slack, PagerDuty (native connectors).
- Alertmanager-style routing tree UI + raw YAML.
- Additional admission engines: OPA/Rego, Kubernetes CEL ValidatingAdmissionPolicy.
- Backup / DR via operator (Postgres logical → S3) + blue/green upgrades.
- FIPS 140-3 cryptographic compliance mode.
- Plugin SDK GA (gRPC scanner/enricher/exporter contracts published; sample plugins).
- **Reference Checkov IaC plugin** — production-quality out-of-process gRPC plugin demonstrating the SDK; gives customers who need Checkov's broader IaC rule pack a clean integration path without forcing Python into the core Constellation build. Public, documented, and round-trip tested.
- **Trend analytics + benchmarking** — `metrics_daily` materialized view, 90-day MTTF/velocity/fix-rate dashboards, anonymous opt-in industry benchmarking aggregator.
- **Migration tools GA** — `constellationctl import --from {stackrox|neuvector|aqua|prisma}` with full round-trip fixtures.
- **PII redaction + data residency** — pattern-based redaction at write time, per-org KEK, region-pinned SaaS tenants.
- **GenAI Assistant integration surface** — pgvector embedding columns + background embedding worker + JSON Schema tool-use contract + `POST /api/v1/ai/query` endpoint + per-org config (model provider, enabled features, prompt redaction). Implementation of the actual AI service lives in the shared Alpha Bravo AI workstream; Constellation ships this phase as **disabled-by-default + airgap-safe**.
- Standalone-mode polish (full UI parity outside Astronomer).
- Scale hardening for tiered SaaS + mid-market self-hosted targets.

## Functional Requirements

- **FR-1** Image scanning: pull from supported registries, generate SBOM (SPDX + CycloneDX), match against CVE DB, produce normalized findings.
- **FR-2** Admission control: Kyverno webhook + pluggable engines, policy catalog with one-click toggles, custom YAML escape hatch.
- **FR-3** Runtime detection: eBPF + L7 DPI + Falco daemon, emits `RuntimeEvent` and `NetworkFlow` over gRPC.
- **FR-4** Posture / compliance: CIS K8s/Docker + NIST + NSA-CISA + PCI-DSS + HIPAA + SOC 2 + STIG + FedRAMP, plus custom-framework editor.
- **FR-5** Findings lifecycle: `Open → Triaged → In-Progress → (Resolved | Suppressed | Accepted)` with assignee, priority, comments, expiry on Accepted.
- **FR-6** Risk score 0–100 computed from CVSS + KEV + EPSS + reachability + asset criticality; override-able per finding.
- **FR-7** Reachability: static analysis (Go/Java/Python initially) + runtime confirmation.
- **FR-8** Network-policy auto-generation: 14-day learn window → Cilium / Calico / native NetworkPolicy YAML output.
- **FR-9** CVE DB pipeline (separate repo): ingest NVD + OSV + GHSA + distros + KEV + EPSS; publish signed OCI artifact 4×/day; offline import.
- **FR-10** Auth: local Argon2id + OIDC/SAML SP; Astronomer JWKS validation when integrated.
- **FR-11** RBAC: Org/Cluster/Project scopes; built-in roles + security verbs.
- **FR-12** Audit: append-only, hash-chained, S3-archived with cosign signatures.
- **FR-13** Notifications: Alertmanager-style routing tree → Slack/Jira/ServiceNow/PagerDuty/webhook.
- **FR-14** Exports: SARIF, JSON, CSV, PDF compliance reports, CycloneDX/OpenVEX, SLSA provenance.
- **FR-15** Plugin system: gRPC-pluggable scanners/enrichers/exporters.
- **FR-16** Deployment: K8s operator + Helm chart + ConstellationCluster CRD; Astronomer adapter that reuses agent tunnel.
- **FR-17** Image signature verification: cosign/sigstore (Rekor + Fulcio identity claims OR static keys); enforceable as a first-class admission rule and as a build-time scan check.
- **FR-18** IaC scanning: Terraform / Helm / Kustomize / Dockerfile / K8s manifests / CloudFormation; same `Finding` schema with `kind=iac`.
- **FR-19** OSS license risk: license extraction from Syft, license-policy catalog with configurable allow/deny, findings emitted with `kind=license`.
- **FR-20** Cloud posture: AWS / GCP / Azure connectors at v1 covering IAM over-privilege, public storage, managed-K8s control-plane configuration; `kind=cloud-config`.
- **FR-21** Runtime WAF: rule-based inline blocking of L7 payloads with learn/monitor/enforce modes per workload.
- **FR-22** Runtime DLP: rule-based inline blocking of sensitive-data exfiltration with learn/monitor/enforce modes per workload.
- **FR-23** API endpoint baselining: learn expected HTTP paths/methods per workload; alert on drift.
- **FR-24** MITRE ATT&CK mapping: every `RuntimeEvent` carries one or more technique IDs (T-numbers); UI pivot supported.
- **FR-25** GitOps drift detection: Argo CD + Flux integrations comparing declared vs in-cluster state for security-sensitive resources.
- **FR-26** Image-level acceptance workflow: accept-risk an image-digest with rationale + expiry + approver; audited separately from per-finding lifecycle.
- **FR-27** Policy-as-code: `constellationctl policy-check / validate / export / import`; CI diff + dry-run.
- **FR-28** Developer experience: VS Code extension, GitHub App + GitLab App posting PR/MR comments with findings on changed files, `pre-commit` hook config.
- **FR-29** Trend analytics + opt-in anonymous benchmarking against industry P25/P50/P75.
- **FR-30** Migration tools: `constellationctl import --from {stackrox|neuvector|aqua|prisma}` translating policies + exceptions + acceptance records.
- **FR-31** AI/ML workload security: model artifact scanning (HuggingFace safetensors, ONNX, detection of unsafe-deserialization payloads in model artifacts), MBOM emission, AI-workload tagging, AI-workload runtime policies.
- **FR-32** PII redaction + data residency: configurable pattern-based PII redaction at write time; per-tenant region pinning in SaaS.
- **FR-33** Optional GenAI Assistant integration surface: semantic indexes (pgvector), structured tool-use schemas with RBAC enforcement, `POST /api/v1/ai/query`, per-org configurable model provider, disabled by default, no functional regression when disabled.

## Non-Functional Requirements

- **NFR-1 (scale, mid-market):** 100 clusters / 10 000 nodes / 100 000 images / 100 M findings on a single Postgres 16 instance with partitioning.
- **NFR-2 (scale, SaaS small tier):** 10 clusters / 500 nodes / 5 000 images / 5 M findings.
- **NFR-3 (latency):** admission webhook p99 < 200 ms; findings list page p95 < 800 ms for top 1 000 results; risk-score recompute < 5 s on a 1 M-finding org.
- **NFR-4 (CVE freshness):** signed bundle published within 6 h of NVD/OSV/GHSA upstream publication.
- **NFR-5 (availability):** management plane targets 99.9 %; in-cluster agents continue local enforcement during management-plane outage.
- **NFR-6 (security):** all internal traffic mTLS; secrets encrypted with envelope keys; FIPS mode available; cosign-signed releases; SBOM for our own build (turtles all the way down).
- **NFR-7 (compliance):** SOC 2 Type II posture, hash-chained audit log, immutable findings history; designed-for-FedRAMP-Moderate.
- **NFR-8 (observability):** OpenTelemetry traces / metrics / logs; customer-pointable OTLP endpoint; standard Prom `/metrics`.
- **NFR-9 (backup):** RPO ≤ 15 min, RTO ≤ 1 h with operator-managed logical backups to S3-compatible store.
- **NFR-10 (airgap):** every component (control plane, in-cluster, CVE DB) deployable with zero outbound internet.
- **NFR-11 (runtime enforcement latency):** WAF + DLP inline verdict p99 < 5 ms on HTTP/1.1 + HTTP/2 payloads ≤ 32 KiB; no proxy hop added when modes are learn/monitor.
- **NFR-12 (developer experience):** VS Code extension cold-start ≤ 2 s; PR comment posted within 60 s of webhook receipt for image+IaC scan of a diff touching ≤ 50 files.
- **NFR-13 (regulatory):** designed to support **NIS2**, **DORA**, **ISO 27001/27017/27018**, **CSA CCM** in addition to SOC 2 / FedRAMP Moderate.
- **NFR-14 (privacy):** PII redaction applied to all `findings.detail_json` + `audit_events.payload` write paths when enabled; per-org KEK enforced; SaaS data-residency: zero cross-region traffic for resident orgs.
- **NFR-15 (AI optional):** with the GenAI integration disabled, no AI-dependent code path is on the critical path of any user-facing or background operation. Build, test, and deploy pipelines work without any AI service reachable.
- **NFR-16 (AI protocol neutrality):** the AI integration surface speaks three peer wire protocols only: **OpenAI Chat Completions API**, **OpenAI Responses API**, and **Anthropic Messages API** (all compatible-endpoint, not provider-specific). Switching providers (anything speaking one of these three protocols — including Azure OpenAI, Bedrock, Vertex, Ollama, vLLM, LM Studio, OpenRouter, LiteLLM, self-hosted) is a config change (base URL + auth + model + protocol selector), never a code change in Constellation. Minimum protocol surface = chat completions/messages + tool use + streaming; advanced features (caching, structured outputs, Responses API built-in tools) are best-effort per protocol.
- **NFR-17 (AI RBAC):** all AI tool-calls execute under the calling user's RBAC subject; AI cannot exceed user privileges; every AI-initiated write tool-call produces an audit event with the originating prompt + redacted context.

## Implementation Phases

### Phase 1 — Foundations
**Tasks:** 14 user stories above (P1-US-1 through P1-US-14). After P1-US-1 (contracts) and P1-US-2 (schema), the remaining 12 stories can run in parallel worktrees via sub-agents.

**Verification:**
```
buf lint && buf breaking --against main
go test ./...
goose -dir db/migrations postgres "$DB_URL" status
helm lint deploy/charts/constellation
helm install --dry-run constellation deploy/charts/constellation
kubectl apply -f deploy/operator/sample-cr.yaml --dry-run=server
cd frontend && npm run lint && npm run type-check && npm run build && npm run test
```

### Phase 2 — Scan
**Tasks:** image scanner aggregator (ClairCore + Syft + Trivy + Grype), findings UI, risk-score pipeline, SBOM emit, static reachability for Go/Java/Python, 9 registry connectors, SARIF/JSON/CSV exports, CI/CD CLI, full CVE DB aggregator (replaces trivy-db bootstrap).

**Verification:**
```
go test ./internal/scanner/... ./pkg/risk/... ./pkg/sbom/...
constellationctl image-check ghcr.io/test/sample:vuln  # produces SARIF, nonzero exit
go test -tags=e2e ./e2e/scanner/...
cd frontend && npm run test -- src/views/findings
```

### Phase 3 — Admit & Posture
**Tasks:** Kyverno admission webhook, policy catalog UI, kube-bench wrapper, compliance mappings (CIS / NIST / NSA-CISA / PCI / HIPAA / SOC 2 / STIG / FedRAMP), custom-framework editor, compliance dashboard, PDF reports, deployment risk dashboard + violation timeline.

**Verification:**
```
go test ./internal/admission/... ./internal/compliance/...
go test -tags=e2e ./e2e/admission/...   # spins kind, applies policies, asserts allow/deny
constellationctl compliance run --framework cis-k8s-1.9
```

### Phase 4 — Runtime
**Tasks:** eBPF agent subsystem, L7 DPI engine, Falco rules ingestion, Resource & Traffic Map UI, process baselining + quarantine + forensics, runtime reachability confirmation, auto network-policy generation (Cilium/Calico/native).

**Verification:**
```
go test ./internal/runtime/...
sudo go test -tags=ebpf,integration ./internal/runtime/ebpf/...
go test -tags=e2e ./e2e/runtime/...    # kind + workload + assert events captured
```

### Phase 5 — Polish & Enterprise
**Tasks:** VEX + SLSA outputs, airgap CVE bundle GA, ITSM integrations, Alertmanager-style routing, OPA/Rego + CEL admission engines, operator-managed backup/DR + blue/green upgrades, FIPS mode, plugin SDK GA, standalone-mode UI polish, scale hardening for tiered SaaS + mid-market.

**Verification:**
```
go test ./...
constellationctl audit verify
constellationctl backup test
constellationctl plugin run examples/sample-scanner
goreleaser release --snapshot --clean
```

## Definition of Done (per phase)

This phase is complete when:
- [ ] All acceptance criteria for that phase's user stories pass.
- [ ] `go test ./...` green across affected packages.
- [ ] `golangci-lint run` clean.
- [ ] `buf lint && buf breaking` clean.
- [ ] Frontend: `npm run lint && npm run type-check && npm run build && npm run test` clean.
- [ ] e2e suite green on kind cluster (where applicable to phase).
- [ ] `helm install --dry-run` succeeds; sample CR applies.
- [ ] Manual smoke test in browser of any new top-level view (Phase 1–3).
- [ ] OTel traces visible end-to-end for new request paths.
- [ ] Audit log entry exists for any new privileged action.

## Ralph Loop Command

```bash
/ralph-loop "Implement Constellation per spec at docs/specs/i-want-to-build-a-cybersecurity-scanning-tool-for-docker-and.md

PARALLELISM: After Phase 1 stories US-1 and US-2 are merged, dispatch parallel sub-agents per remaining P1 user story in separate worktrees. For Phases 2–5, expand each phase's feature list into stories at phase start, then dispatch parallel sub-agents per story.

PHASES:
1. Foundations: 14 stories (contracts, schema, API, auth, RBAC, audit, OTel, frontend shell, frontend auth, CVE DB v0, OCI publisher, operator+helm, Astronomer adapter, CLI). Verify with: buf lint && go test ./... && goose status && helm lint && frontend build+test
2. Scan: image scanner aggregator + findings UI + risk score + SBOM + static reachability + 9 registries + exports + CI CLI + CVE DB aggregator. Verify with: go test ./internal/scanner/... + image-check produces SARIF + e2e scanner suite
3. Admit & Posture: Kyverno admission + policy catalog + kube-bench + compliance mappings + custom-framework editor + dashboards. Verify with: e2e admission suite + compliance run
4. Runtime: eBPF + L7 DPI + Falco + Traffic Map + process baseline + forensics + runtime reachability + auto network-policy. Verify with: ebpf integration tests + e2e runtime suite
5. Polish: VEX/SLSA + airgap GA + ITSM + routing + OPA/CEL engines + backup/DR + FIPS + plugin SDK + scale hardening. Verify with: full suite + backup test + plugin sample + goreleaser snapshot

VERIFICATION (run after each story):
- go test ./...
- golangci-lint run
- buf lint && buf breaking --against main
- (frontend changes) npm run lint && npm run type-check && npm run build && npm run test

ESCAPE HATCH: After 20 iterations on a single story without progress:
- Document blockers in the story's Implementation Notes section
- List approaches attempted
- Stop and ask for human guidance

Output <promise>COMPLETE</promise> when all phases pass verification." --max-iterations 60 --completion-promise "COMPLETE"
```

## Open Questions

- Specific Postgres partitioning cadence: monthly is a starting assumption; reassess at Phase 2 against measured `findings` insert rates.
- Whether to ship a managed SaaS in addition to self-hosted at v1, or leave SaaS to v2 (currently planned as a tier at v1; revisit before P5).
- Frontend monorepo layout: standalone `frontend/` package vs Nx-style monorepo when standalone & embedded views diverge.
- License model (AGPL like Astronomer, Apache-2.0, or dual-licensed Apache + commercial) — defer to legal review.
- Specific cosign key custody (hardware HSM vs Sigstore Fulcio keyless) — decide before P1-US-11.
- Static reachability engine for Java + Python: build on WALA / Jedi / Pyre vs custom — decide at start of P2.
- **WAF/DLP inline path:** NFQUEUE + userspace verdict (NeuVector pattern) vs eBPF/XDP redirect to userspace vs sidecar proxy. NFQUEUE chosen by default for portability; revisit at Phase 4 if p99 latency budget at risk.
- **Cloud-CSPM connector depth:** agentless read-only is committed for v1; deeper CSPM (compute config, networking, serverless, agentless workload scanning) is v2 — confirm exact v1 cut at P3 start.
- ~~IaC scan engine~~ — **decided 2026-05-11**: Trivy IaC at v1; reference Checkov plugin via gRPC plugin SDK at Phase 5.
- **AI service location:** where does the shared Alpha Bravo AI service live (own repo, sub-org, hosted region default) and what is its contract with Constellation? Decide before P5 starts.
- **AI provider default for SaaS:** which provider is the default for new SaaS orgs (likely Bedrock for FedRAMP roadmap compatibility) — decide before P5.
- **Benchmarking aggregator:** which org-attribute taxonomy (vertical, size band, region) is used for industry P-curves, and what's the k-anonymity floor (recommend k≥50)? Decide at P5 start.
- **GitHub App vs OAuth App** for the developer experience layer: GitHub App is recommended (fine-grained installation per repo) but requires App Store listing for self-serve.

## Implementation Notes

- The three reference repos in `./neuvector/`, `./stackrox/`, `./astronomer/` are intended for reading + inspiration only — Constellation is greenfield and does not vendor or fork code from them, though it depends on **ClairCore (Quay/Red Hat, MIT)**, **Syft / Grype (Anchore, Apache-2.0)**, **Trivy (Aqua, Apache-2.0)**, **Falco (CNCF, Apache-2.0)**, and **Kyverno (CNCF, Apache-2.0)** as upstream libraries.
- Astronomer's already-reserved `/api/v1/security/*` route shape should drive Constellation's URL design to minimize adapter friction.
- The frontend stack must mirror `astronomer/frontend/package.json` exactly (Next.js 16, React 19, Radix, Tailwind, TanStack Query, Zustand, Monaco, xterm) so that embedded Constellation views are visually indistinguishable from native Astronomer pages.
- The CVE DB pipeline lives in a separate repo (`constellation-vulndb/`) so it can ship independently of the platform monorepo, with its own release cadence and airgap delivery story.
- Sub-agent dispatch: Phase 1's US-1 (contracts) and US-2 (schema) are **prerequisites** for the other 12 stories; the remaining 12 stories should be dispatched in parallel worktrees once US-1 and US-2 merge.
- **WAF/DLP are distinct subsystems from L7 DPI.** DPI is observation; WAF/DLP are enforcement with their own rule store, learn/monitor/enforce mode lifecycle, and inline data path. They must be implemented as separate Go packages (`internal/runtime/waf/`, `internal/runtime/dlp/`) sharing the L7 parser library — not as flags on the DPI engine.
- **Image signature verification appears in two places**: build-time (scan finding for unsigned/unattested images) and admission (block at the cluster boundary). Same verifier service called by both paths.
- **AI integration is via Abbot, not directly to providers.** Constellation imports the `abbot-go` library; the library talks to the Abbot service; the Abbot service speaks the three downstream wire protocols (OpenAI Chat Completions, OpenAI Responses, Anthropic Messages). Constellation has zero provider SDK imports and zero provider protocol code. See `docs/specs/abbot-architecture.md`.
- **The sharp line between library and service.** Library (in Constellation): RBAC enforcement, local audit writes, pgvector RAG, tool catalog registration, per-product redaction policy. Service (Abbot): provider protocol bridges, cost accounting, rate limits, model routing, central operational log, prompt versioning. Anything compliance-load-bearing or product-specific lives in the library inside the product; anything that benefits from centralization lives in the service.
- **Audit lives in Constellation, not Abbot.** Every AI-initiated read and write goes into Constellation's hash-chained `audit_events` table. Abbot keeps a separate *operational* call log for ops queries, but that is **not** the compliance record. Auditors look at Constellation's audit log.
- **Embeddings stay in Constellation's Postgres.** pgvector lives in Constellation's DB because embeddings derive from Constellation's domain objects, and Constellation tenants have data-residency requirements. Abbot never holds product domain data.
- **Tool execution happens in Constellation.** When the AI emits a tool-call (`triage_finding`, `suppress_finding`, etc.), the `abbot-go` library re-checks RBAC against Constellation's RBAC engine and executes the tool via the same code path a human would. Abbot orchestrates the dance; it never executes tools itself.
- **PII redaction is write-side, not read-side.** Patterns apply at insertion time to `findings.detail_json` and `audit_events.payload`; original payload encrypted with a per-org KEK held in KMS. Read-side is just normal serve — keeps the hot read path fast and prevents accidental leakage via untested code paths.
- **MITRE ATT&CK mapping table is versioned alongside the agent.** A new ATT&CK technique (or revised mapping) ships with a new agent release, not a config update — this guarantees the technique set the agent claims to map is exactly the set in the mapping table.
- **The cloud-CSPM pillar at v1 is deliberately narrow** (IAM + storage + control-plane). It is *not* the full Wiz/Prisma CSPM. The v1 cut is sized to answer the "do you have basic cloud config coverage?" evaluator question without exploding scope.
- **IaC engine at v1 is Trivy IaC only — Checkov is deferred to a Phase 5 plugin** (not bundled). The Python runtime cost (container size, FIPS validation, airgap pip mirroring, operator complexity) does not justify itself until at least one prospect demands Checkov-specific rules. The aggregator pattern that works for vuln matching (ClairCore + Trivy + Grype on the same finding shape) does *not* transfer to IaC because Trivy IaC and Checkov have substantially different rule taxonomies — they find different misconfigs, not the same misconfigs with different confidence. Bundling both in-process would produce ~80% rule overlap noise without the dedupe benefit the vuln aggregator gets.

## Spec Revisions

### Rev 2 — 2026-05-11

Initial draft folded a competitive-review pass against NeuVector + StackRox parity and modern 2024-2026 entrants (Wiz, Snyk Container, Aqua, Prisma Cloud). The following gaps were folded into the spec:

**Parity gaps closed (NeuVector / StackRox):**
- **A1 + A2** Runtime **WAF** + **DLP** enforcement engines added as distinct subsystems from L7 DPI (NeuVector parity).
- **A3** Image **signature verification at admission** added as a first-class policy-catalog rule (StackRox parity; modern table stakes).
- **A4** **OSS license risk** as findings (license-policy catalog), surfacing existing Syft/Trivy license data.
- **A5** **Policy-as-code workflow** via `constellationctl policy-check/validate/export/import` (StackRox `roxctl` parity).
- **A6** **API endpoint baselining** added alongside process baselining.
- **A7** **Image-level acceptance workflow** beyond per-finding lifecycle.

**Modern table-stakes additions:**
- **B1** Basic **cloud-CSPM** (AWS / GCP / Azure: IAM, storage, control plane) at v1; deeper CSPM v2.
- **B2** **IaC scanning** elevated to first-class pillar (Terraform / Helm / Kustomize / Dockerfile / K8s manifests / CloudFormation).
- **B3** **Developer experience layer**: VS Code extension, GitHub App + GitLab App with PR/MR comments, `pre-commit` hook config.
- **B4** **Optional GenAI Assistant integration surface** — Constellation defines the surface (pgvector embeddings, structured tool-use schemas, `/api/v1/ai/query`, per-org provider config); actual AI implementation is deferred to a cross-product Alpha Bravo AI workstream shared with Astronomer + future products. Disabled by default; product fully functional without it.
- **B5** **AI/ML workload security**: model artifact scanning, MBOM emission, AI-workload tagging, AI-workload runtime policies.
- **B6** **MITRE ATT&CK mapping** on every `RuntimeEvent`.
- **B7** **GitOps / configuration drift detection** with Argo CD + Flux.
- **B8** **Trend analytics + opt-in anonymous industry benchmarking**.
- **B9** **Migration tools** from StackRox / NeuVector / Aqua / Prisma.

**Compliance / regulatory completeness:**
- **C1** NIS2 (EU)
- **C2** DORA (EU finance)
- **C3** ISO 27001 / 27017 / 27018
- **C4** CSA Cloud Controls Matrix (CCM)
- **C5** Configurable **PII redaction** + per-tenant **data residency** for SaaS

**New requirements:** FR-17 through FR-33; NFR-11 through NFR-17.

**Architecture deltas:** Runtime agent grew from 3 to 5 subsystems (added WAF, DLP, ATT&CK mapper). New top-level architecture subsections: Runtime Enforcement Modes, Static Scanner Pillar (build-time), Cloud Posture, GitOps Drift Detection, Developer Experience Layer, Trend Analytics + Benchmarking, Migration Tools, AI/ML Workload Security, Privacy + Data Residency, GenAI Assistant Integration Surface.

**Scope discipline (explicitly NOT added):**
- Original CVE intelligence / CNA program — remains out of scope (aspirational only).
- Wiz-class scale (1K clusters / 1B findings) — remains out of scope (mid-market focus at v1).
- WASM-sandboxed plugin runtime — gRPC out-of-process plugins for v1.
- Full Wiz/Prisma-equivalent CSPM — narrow cut at v1 (IAM + storage + control-plane only).
- VM + serverless workload scanning — remains v2.
- AI implementation itself — only the integration surface lives here; the AI service is a cross-product workstream.

**GenAI design principles (load-bearing for the deferral):**
1. **Optional + off by default** — Constellation must build, deploy, test, and operate fully without any AI service reachable.
2. **No critical-path dependency** — every AI-powered affordance has a non-AI fallback.
3. **Protocol-agnostic surface, not provider-agnostic** — wire-protocol bridges (OpenAI Chat Completions, OpenAI Responses, Anthropic Messages) live in the Abbot service; Constellation only speaks the Abbot envelope via `abbot-go`. Providers are Abbot config (base URL + auth + model + protocol selector), not Constellation code.
4. **RBAC-enforced** — AI tool-calls execute under the calling user's subject; AI cannot exceed user privileges; every AI-initiated write is audited with the originating prompt.
5. **Cross-product unified** — the AI service is shared with Astronomer and future products; Constellation contributes its semantic indexes + tool-use schemas to the shared surface, does not own the model orchestration.

### Rev 5 — 2026-05-11

**Cross-product GenAI service named and architected: Abbot.**

The previously deferred cross-product GenAI workstream now has a name (**Abbot** — AB + bot) and a committed architecture: **hybrid library + gateway service**. Full architecture spec at `docs/specs/abbot-architecture.md`.

**Sharp line between library and service:**
- `abbot-go` library (in each product) owns: RBAC enforcement, local audit writes, pgvector RAG against product DB, tool catalog registration, per-product redaction policy, graceful degradation when service is unreachable.
- Abbot service owns: wire protocol bridges (the three protocols), provider routing + failover, cost accounting, rate limits + quotas, egress PII redaction, central operational call log, prompt versioning + eval, cross-product orchestration (future).

**Why hybrid, not pure library or pure service:**
- Audit must live in the calling product's audit log (compliance-load-bearing); can't centralize.
- RBAC enforcement must live in the calling product (each product has a different RBAC model); can't centralize.
- Semantic indexes (pgvector) must live in the product's DB (data residency); can't centralize.
- Tool catalogs are product-specific; only the *schema* for declaring tools is shared.
- Provider protocol bridges, cost, rate limits, prompt eval, model routing all get strictly better when centralized.

**Repo location:** own GitHub repo (`github.com/alphabravo/abbot/`), peer to `constellation/` and `astronomer/`. Local dev as a sibling under `golden-dome/` initially.

**Constellation v1 contributions to Abbot:** pgvector embedding columns + background embedding worker, tool catalog (read + write tools with RBAC verb gating), `POST /api/v1/ai/query` endpoint, `abbot-go` integration. Provider protocols, cost accounting, etc. are owned by the Abbot workstream — not in Constellation.

**Hard rules carried over from Rev 2:** AI is optional + off by default; product must build/deploy/test/operate fully without Abbot reachable; every AI-powered UI affordance has a non-AI fallback; airgap deployments use a customer-deployed Abbot pointed at a self-hosted endpoint.

### Rev 4 — 2026-05-11

**IaC engine choice locked.** Open question "IaC scan engine: Trivy IaC vs Checkov vs build our own" closed:
- **v1 engine: Trivy IaC** wrapped under the unified `Finding` schema with `kind=iac`. Covers Terraform, Helm, Kustomize, Dockerfile, K8s manifests, CloudFormation.
- **Checkov: not bundled at v1.** Avoids embedding a Python runtime in Constellation's build / FIPS / airgap / operator paths. The cost of carrying Python until a prospect actually demands Checkov-specific rules is real and persistent.
- **Phase 5 deliverable added: reference Checkov plugin** built against the gRPC plugin SDK as an out-of-process scanner. Doubles as a public demonstration of the plugin contract for 3rd-party scanner vendors.
- **Why not aggregate both engines in-process**: the vuln aggregator pattern works because ClairCore/Trivy/Grype find the same `Vulnerability` shape and dedupe is meaningful. Trivy IaC and Checkov have substantially different rule taxonomies — different misconfigs, not different confidences on the same misconfigs.

### Rev 3 — 2026-05-11

**AI wire-protocol contract sharpened.** Replaced provider enumeration (OpenAI / Anthropic / Bedrock / Vertex / Ollama / Azure OpenAI / etc.) with a three-protocol contract:
1. **OpenAI Chat Completions API** (`/v1/chat/completions`) — broadest gateway coverage.
2. **OpenAI Responses API** (`/v1/responses`) — OpenAI's newer agent-oriented stateful protocol with built-in tool primitives.
3. **Anthropic Messages API** (`/v1/messages`) — Anthropic + Bedrock + Vertex for Claude models.

Per-org config selects protocol + base URL + auth + model name. Provider names appear nowhere in Constellation code — anything speaking one of the three protocols works. Minimum protocol surface = chat completions/messages + tool use + streaming; advanced features (caching, structured outputs, Responses API built-in tools) are best-effort per protocol.

Implementation depth at v1 is the abstraction + config schema + mock-endpoint tests only. Full protocol surface coverage and per-provider feature tuning live in the shared Alpha Bravo AI workstream.

### Rev 1 — 2026-05-11
Initial specification compiled from lisa-plan interview.
