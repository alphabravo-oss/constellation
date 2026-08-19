# Constellation

**Enterprise cloud-native security, built for Kubernetes, containers, and modern software delivery.**

> ⚠️ **ALPHA — DO NOT USE.** This project is in early **alpha** and under active
> development. It is **not** production-ready, APIs and data formats will change
> without notice, and there are **no stability, security, or support guarantees**.
> Published for transparency and early feedback only — do not deploy it anywhere
> you care about.

Constellation gives security teams, platform engineers, and operators one place to see what is running, understand what is vulnerable, control what is allowed, and prove what happened. It combines vulnerability intelligence, runtime visibility, admission control, compliance evidence, network security, and enterprise governance into a single Kubernetes-native security platform.

Constellation is designed for organizations that need more than a scanner. It is a control plane for cloud-native risk: continuously discovering assets, prioritizing exploitable exposure, enforcing policy, and turning raw security data into operational decisions.

## Why Constellation

Modern infrastructure moves too fast for disconnected tools. Images are built continuously, workloads are scheduled dynamically, clusters drift, vulnerabilities change daily, and security teams still need clear answers:

- What is running in every cluster?
- Which workloads, images, nodes, repositories, and packages are exposed?
- Which vulnerabilities actually matter?
- Which controls are enforced before deployment and during runtime?
- What evidence proves compliance, response, and governance?
- Which teams, clusters, and applications need action first?

Constellation answers those questions with a unified platform that is built around live Kubernetes evidence, curated vulnerability intelligence, workload context, and enterprise controls.

## Platform Pillars

### Unified Cloud-Native Inventory

Constellation continuously discovers and organizes the cloud-native estate:

- Clusters, nodes, namespaces, workloads, deployments, services, images, repositories, serverless packages, and runtime components
- Kubernetes platform facts, distribution metadata, add-ons, sensor health, and cluster readiness
- Workload-to-image, image-to-CVE, package-to-CVE, and workload-to-runtime evidence
- Cross-cluster views for teams that operate more than one environment
- Actionable cluster dashboards designed for security triage and platform operations

The result is a current, searchable security inventory that reflects what is actually deployed.

### Vulnerability Intelligence

Constellation turns vulnerability data into decisions:

- Container image vulnerability scanning
- Running workload vulnerability correlation
- Host and node package exposure
- Kubernetes platform package evidence
- Repository and CI package evidence scans
- Serverless package reporting
- CVE search, affected asset views, and exposure rollups
- Vulnerability exceptions, accept-risk workflows, and audit-backed triage
- Scan status, scanner health, cache visibility, and rescan workflows

Constellation is built to prioritize active exposure, not just produce long CVE lists.

### Constellation VulnDB Alignment

Constellation consumes versioned vulnerability bundles produced by the separate **Constellation VulnDB** system.

VulnDB is the intelligence factory. It can aggregate and normalize vulnerability data, generate signed and versioned bundles, and publish those bundles through the delivery path that fits the environment: S3, artifact storage, manual upload, internal release channels, or other controlled distribution workflows.

Constellation is the consumer. It imports those bundles, tracks the active database version, scans assets against the imported intelligence, and exposes findings through dashboards, APIs, policy workflows, and reports.

This separation keeps vulnerability production independent from runtime security operations and makes Constellation suitable for connected, restricted, and air-gapped environments.

### Runtime Security

Constellation is designed to move beyond static assessment into live workload protection:

- Runtime agent coverage for workload, host, and network evidence
- Process baselines and drift visibility
- Runtime event ingestion and investigation workflows
- DLP and WAF policy surfaces
- Response rules for security operations
- Quarantine and containment workflows
- Recent activity timelines for cluster and workload investigation

Runtime security is presented in operator-friendly views so teams can move from signal to action quickly.

### Network Security

Constellation helps teams understand and control Kubernetes communication:

- Network traffic map for workload-to-workload visibility
- Observed flow context for application and namespace behavior
- Network policy lifecycle views
- Policy preview, approval, apply, demote, and rollback workflows
- Native Kubernetes policy alignment with room for Cilium and Calico-oriented environments
- Audit-backed network policy operations

Security teams get visibility. Platform teams get controlled rollout paths.

### Admission And Supply Chain Control

Constellation provides guardrails before workloads enter the cluster:

- Admission policy profiles
- Policy simulation against Kubernetes manifests
- Admission audit evidence
- Image, package, SBOM, and provenance-aware enforcement surfaces
- Repository and CI attestation trust policies
- Keyless and key-based attestation verification modes
- Signature and provenance workflows designed for modern build pipelines

The goal is simple: prevent risky workloads from becoming production incidents.

### Compliance And Evidence

Constellation is built for continuous evidence collection and defensible reporting:

- Kubernetes compliance evidence
- Host, workload, cloud, and platform evidence surfaces
- Framework and control mapping
- Compliance summaries and control drill-downs
- Exemptions with reason, owner, expiry, and audit trail
- Scheduled compliance runs
- Report-ready evidence artifacts
- Audit verification for tamper-evident event history

Compliance becomes a byproduct of operating securely, not a separate scramble.

### Enterprise Governance

Constellation includes the controls expected in an enterprise security platform:

- Global administrator workflows
- Role-based access control
- Local authentication and OIDC-ready SSO integration
- API tokens and service principals
- Audit logging with hash-chain verification
- Integration delivery tracking
- Backup and restore surfaces
- System health, component health, and sensor readiness
- Multi-cluster operations
- Policy and exception workflows with accountability

It is designed for teams that need delegated operation without losing central control.

## Capabilities At A Glance

| Area | What Constellation Provides |
| --- | --- |
| Asset visibility | Clusters, nodes, workloads, images, repositories, packages, serverless assets, and platform components |
| Vulnerability management | CVE search, image scans, workload scans, host scans, platform scans, repository scans, affected asset views, exceptions, and rescans |
| Runtime security | Runtime events, process baselines, response rules, DLP, WAF, quarantine, and workload investigation |
| Network security | Traffic maps, flow context, policy lifecycle, approval, apply, demotion, and rollback workflows |
| Admission control | Deployment guardrails, policy profiles, manifest simulation, admission evidence, and enforcement workflows |
| Supply chain | SBOM and package evidence, repository attestations, CI provenance, keyless verification, and trust policies |
| Compliance | Evidence collection, framework mapping, schedules, exemptions, audit trails, and report artifacts |
| Governance | RBAC, GlobalAdmin operations, OIDC-ready auth, API tokens, audit verification, integrations, backups, and system health |
| Operations | Helm deployment, Kubernetes-native services, scanner workers, runtime agents, health probes, and enterprise observability |
| VulnDB | Independent bundle generation, versioned imports, S3/manual/artifact delivery, and air-gap-friendly update paths |

## Built For Enterprise Outcomes

### Faster Security Decisions

Constellation correlates vulnerability, runtime, network, and platform evidence so teams can focus on the exposures that matter first.

### Cleaner Platform Operations

Cluster dashboards, sensor health, scan status, and action items help platform teams see whether security coverage is working before incidents or audits expose gaps.

### Stronger Runtime Confidence

Workload baselines, runtime events, containment workflows, and policy controls help teams move from visibility to active defense.

### Better Governance

RBAC, audit verification, exemptions, accept-risk workflows, and evidence artifacts make security decisions accountable and reviewable.

### Air-Gap And Restricted Environment Readiness

The separation between Constellation and Constellation VulnDB allows vulnerability intelligence to be generated, approved, transported, and imported through controlled channels.

## Product Experience

Constellation is built as an operator console, not a data dump.

The UI is organized around cluster and organization workflows: triage findings, inspect node and workload exposure, review platform scan evidence, manage runtime and network controls, inspect compliance posture, configure integrations, and monitor system health from a single experience.

The platform is API-first for automation, but the primary user experience is designed for repeatable enterprise operations: scan, prioritize, decide, enforce, verify, and report.

## Deployment Model

Constellation is Kubernetes-native and deploys into the environments it protects.

- Helm-based installation for Kubernetes and k3s environments
- Frontend, API, scanner, admission, runtime, discoverer, operator, and supporting services
- Local demo support through Docker Compose
- In-cluster scanning and evidence collection
- Separate VulnDB bundle import path for connected or restricted deployments
- Designed for enterprise ingress, TLS, cert-manager, and standard Kubernetes operations

For production deployments, use the Helm chart in [`deploy/charts/constellation`](deploy/charts/constellation/).

## Evaluation And Demo

For a single-host evaluation:

```sh
make compose-images
docker compose --profile seed up -d
open http://localhost:3000
```

Default demo credentials:

```text
admin@demo.test
Constellation!1
```

For Kubernetes deployments, use the Helm chart and configure ingress, TLS, authentication, and VulnDB bundle imports according to the target environment.

## Documentation

- Architecture: [`docs/architecture.md`](docs/architecture.md)
- Development: [`docs/development.md`](docs/development.md)
- Docker Compose deployment: [`docs/deployment-compose.md`](docs/deployment-compose.md)
- Helm chart: [`deploy/charts/constellation`](deploy/charts/constellation/)
- VulnDB producer repository: `../constellation-vulndb`
- Enterprise parity and roadmap planning: [`docs/constellation-neuvector-vulndb-review-plan.md`](docs/constellation-neuvector-vulndb-review-plan.md)

## The Constellation Promise

Constellation brings the major cloud-native security surfaces together: vulnerability management, runtime defense, admission control, network policy, compliance evidence, supply-chain trust, auditability, and enterprise operations.

It is built to help organizations operate Kubernetes securely at scale without forcing teams to stitch together disconnected scanners, dashboards, scripts, and spreadsheets.
