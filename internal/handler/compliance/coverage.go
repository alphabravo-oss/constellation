package compliance

import (
	"net/http"

	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

type Coverage struct{}

func NewCoverage() *Coverage { return &Coverage{} }

type coverageItem struct {
	ID              string   `json:"id"`
	Domain          string   `json:"domain"`
	Feature         string   `json:"feature"`
	Reference       []string `json:"reference"`
	Decision        string   `json:"decision"`
	Status          string   `json:"status"`
	UXSurface       string   `json:"ux_surface"`
	Evidence        string   `json:"evidence"`
	NextMilestone   string   `json:"next_milestone"`
	EnterpriseNotes string   `json:"enterprise_notes"`
}

func (h *Coverage) List(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": featureCoverage})
}

var featureCoverage = []coverageItem{
	{
		ID: "network-graph", Domain: "Runtime", Feature: "Traffic map, flow drill-down, baselines, policy simulation",
		Reference: []string{"NeuVector: controller graph + learned policy modes", "StackRox: NetworkGraph, baselines, simulator"},
		Decision:  "implement", Status: "partial",
		UXSurface:       "/network",
		Evidence:        "Live /api/v1/network/map aggregation, ReactFlow topology, selectable flow/workload drill-down, policy preview.",
		NextMilestone:   "Add baseline violation approvals, CIDR grouping, generated YAML compare/apply workflow.",
		EnterpriseNotes: "Critical evaluator workflow; must support real-time and historical windows.",
	},
	{
		ID: "risk-dashboard", Domain: "Findings", Feature: "Risk-ranked deployment dashboard and violation timeline",
		Reference: []string{"StackRox: Risk view, deployments, violations"},
		Decision:  "implement", Status: "implemented",
		UXSurface:       "/deployments",
		Evidence:        "Risk-ranked deployments, per-deployment violation timeline, composite risk factors.",
		NextMilestone:   "Add saved filters and report export from filtered deployment sets.",
		EnterpriseNotes: "Primary SOC triage entry point.",
	},
	{
		ID: "image-vuln-sbom", Domain: "Vulnerability", Feature: "Image scanning, SBOMs, CVE enrichment, fixability",
		Reference: []string{"StackRox: Images, CVEs, ClairCore", "NeuVector: registry scanner"},
		Decision:  "implement", Status: "partial",
		UXSurface:       "/findings, /assets, /cve",
		Evidence:        "Syft/Trivy/Grype aggregator, SBOM endpoints, CVE DB bundle, finding lifecycle UI.",
		NextMilestone:   "Add image detail tabs for packages, layers, fixable CVEs, and SBOM diff.",
		EnterpriseNotes: "Needs registry connector management and scan coverage visibility in Settings.",
	},
	{
		ID: "admission-policy", Domain: "Policy", Feature: "Admission enforcement, policy catalog, signature verification",
		Reference: []string{"StackRox: Policy Management + Admission Control", "NeuVector: admission rules"},
		Decision:  "implement", Status: "implemented",
		UXSurface:       "/policies",
		Evidence:        "Kyverno-style builtin engine, OPA/Rego, CEL, image signature verification, monitor/enforce modes.",
		NextMilestone:   "Add policy test simulator against pasted manifests and live cluster resources.",
		EnterpriseNotes: "Policy changes must remain audited and Git-exportable.",
	},
	{
		ID: "runtime-waf-dlp", Domain: "Runtime", Feature: "L7 DPI, WAF, DLP, process/file monitoring",
		Reference: []string{"NeuVector: L7 firewall, WAF, DLP, process/file monitor", "StackRox: collector process/network telemetry"},
		Decision:  "implement", Status: "partial-runtime-management",
		UXSurface:       "/runtime",
		Evidence:        "Falco ingestion, MITRE mapping, baseline library; response-rule overrides are persisted/audited; runtime events now roll up affected workloads, verdicts, and ATT&CK evidence.",
		NextMilestone:   "Add Linux CI, rule-to-event correlation, and node-level verification for privileged eBPF/NFQUEUE agent enforcement components.",
		EnterpriseNotes: "Cannot be considered GA until tested on Linux nodes with eBPF/NFQUEUE capabilities.",
	},
	{
		ID: "compliance-posture", Domain: "Posture", Feature: "Compliance frameworks, posture checks, custom controls",
		Reference: []string{"StackRox: Compliance", "NeuVector: compliance/check APIs"},
		Decision:  "implement", Status: "implemented",
		UXSurface:       "/compliance",
		Evidence:        "CIS ingest, cross-framework mapping, custom framework editor API, report templates.",
		NextMilestone:   "Add scheduled report jobs and framework exception workflow.",
		EnterpriseNotes: "Enterprise buyers expect audit-ready exports and scoped reports.",
	},
	{
		ID: "clusters-sensors", Domain: "Operations", Feature: "Cluster onboarding, sensor health, upgrades, init bundles",
		Reference: []string{"StackRox: Clusters, init bundles, sensor upgrade", "Astronomer: managed clusters"},
		Decision:  "implement", Status: "partial",
		UXSurface:       "/settings",
		Evidence:        "Operator, Helm chart, Astronomer JWKS-backed security route mount, cluster list API.",
		NextMilestone:   "Add cluster onboarding UI with Helm commands, registration secrets, health panels, upgrade status, and any future Astronomer tunnel protocol wiring.",
		EnterpriseNotes: "This is required before multi-cluster enterprise pilots.",
	},
	{
		ID: "integrations-alerting", Domain: "Integrations", Feature: "Jira, ServiceNow, Slack, PagerDuty, webhooks, reports",
		Reference: []string{"StackRox: notifiers and report jobs", "NeuVector: response rules"},
		Decision:  "implement", Status: "partial",
		UXSurface:       "/settings",
		Evidence:        "Notify package has connectors and routing tree; UI for raw routing YAML still pending.",
		NextMilestone:   "Add integrations setup, test delivery buttons, routing tree editor, and report job UI.",
		EnterpriseNotes: "Must show delivery status and audit privileged notification changes.",
	},
	{
		ID: "migration", Domain: "Migration", Feature: "Import policies, suppressions, and exceptions from competitors",
		Reference: []string{"StackRox: roxctl exports", "NeuVector: policy/export APIs"},
		Decision:  "implement", Status: "partial-preview",
		UXSurface:       "/settings",
		Evidence:        "Import adapters for stackrox, neuvector, aqua, prisma with tests; Settings preview wizard now converts exports, shows create/update diff, generated YAML, and rollback bundle without applying.",
		NextMilestone:   "Add audited apply workflow with persisted rollback bundle and imported exception mapping.",
		EnterpriseNotes: "Important procurement unblocker; UI must be low-risk and transparent.",
	},
	{
		ID: "cloud-iac-supply-chain", Domain: "Build & Cloud", Feature: "Cloud CSPM, IaC, provenance, VEX, attestations",
		Reference: []string{"StackRox: config management and compliance", "Spec: cloud-CSPM/IaC/supply chain"},
		Decision:  "implement", Status: "partial",
		UXSurface:       "/findings, /assets",
		Evidence:        "AWS/GCP/Azure CSPM checks, Checkov plugin, VEX, SLSA and in-toto packages.",
		NextMilestone:   "Add source/repo asset detail pages and cloud connector setup UX.",
		EnterpriseNotes: "Needs clear separation between cloud resources, IaC resources, images, and workloads.",
	},
	{
		ID: "ai-assistant", Domain: "AI", Feature: "Abbot-backed AI assistant with non-AI fallbacks",
		Reference: []string{"Spec: Abbot integration"},
		Decision:  "implement-optional", Status: "backend-surface",
		UXSurface:       "/settings",
		Evidence:        "Abbot client, tool registry, RBAC/audit envelope, /api/v1/ai/query disabled when off.",
		NextMilestone:   "Add org-level enablement UI and fallback-aware affordances inside findings and compliance.",
		EnterpriseNotes: "Off by default; data residency and audit must be visible.",
	},
}
