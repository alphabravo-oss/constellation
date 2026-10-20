// Package complianceevidence builds first-class compliance evidence from the
// posture data Constellation already collects: kube-bench rows, host CIS
// snapshots, workload risk/policy state, and cloud posture findings.
package complianceevidence

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/compliance"
)

const (
	ScopeAll        = ""
	ScopeNode       = "node"
	ScopeWorkload   = "workload"
	ScopeKubernetes = "kubernetes"
	ScopeCloud      = "cloud"
)

// Query scopes a compliance evidence read.
type Query struct {
	OrgID     uuid.UUID
	ClusterID *uuid.UUID
	Scope     string
	Framework string
	Namespace string
	Limit     int
	Offset    int
	Sort      string
	Order     string
	ControlID string
	Status    string
	Search    string
	Target    string
	// Nil means no target filter; an explicit empty slice matches nothing.
	Targets []string
}

// Collector reads evidence from Postgres.
type Collector struct {
	Pool *pgxpool.Pool
}

// Result is the API/report-facing evidence envelope.
type Result struct {
	Items     []Item     `json:"items"`
	Summary   Summary    `json:"summary"`
	Total     int        `json:"total"`
	Limit     int        `json:"limit"`
	Offset    int        `json:"offset"`
	Sort      string     `json:"sort"`
	Order     string     `json:"order"`
	HasMore   bool       `json:"has_more"`
	ClusterID *uuid.UUID `json:"cluster_id,omitempty"`
	Scope     string     `json:"scope"`
	Framework string     `json:"framework"`
	Namespace string     `json:"namespace"`
	ControlID string     `json:"control_id"`
	Status    string     `json:"status"`
	Search    string     `json:"q"`
	Target    string     `json:"target"`
}

// Summary counts raw/effective status across a result set.
type Summary struct {
	Pass          int                     `json:"pass"`
	Fail          int                     `json:"fail"`
	Manual        int                     `json:"manual"`
	NotApplicable int                     `json:"not_applicable"`
	Exempted      int                     `json:"exempted"`
	Total         int                     `json:"total"`
	ByScope       map[string]ScopeSummary `json:"by_scope,omitempty"`
}

// ScopeSummary is the status rollup for one evidence scope.
type ScopeSummary struct {
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	Manual        int `json:"manual"`
	NotApplicable int `json:"not_applicable"`
	Exempted      int `json:"exempted"`
	Total         int `json:"total"`
}

// Item is one host/workload/Kubernetes/cloud control evidence row.
type Item struct {
	ID              string            `json:"id"`
	Scope           string            `json:"scope"`
	Source          string            `json:"source"`
	Framework       string            `json:"framework"`
	ControlID       string            `json:"control_id"`
	InternalID      string            `json:"internal_id,omitempty"`
	Title           string            `json:"title"`
	Severity        string            `json:"severity"`
	Status          string            `json:"status"`
	EffectiveStatus string            `json:"effective_status"`
	TargetKind      string            `json:"target_kind"`
	Target          string            `json:"target"`
	ClusterID       *uuid.UUID        `json:"cluster_id,omitempty"`
	Namespace       string            `json:"namespace,omitempty"`
	Evidence        string            `json:"evidence,omitempty"`
	Remediation     string            `json:"remediation,omitempty"`
	ObservedAt      time.Time         `json:"observed_at"`
	TagsV2          compliance.TagsV2 `json:"tags_v2,omitempty"`
	Exemption       *Exemption        `json:"exemption,omitempty"`
}

// Exemption is the active exemption overlay for a failed row.
type Exemption struct {
	ID        string    `json:"id"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ReportEvidence returns a compact text block for PDF/CSV/SARIF exports.
func (i Item) ReportEvidence() string {
	parts := []string{
		"scope=" + i.Scope,
		"target=" + i.Target,
		"source=" + i.Source,
		"status=" + i.Status,
	}
	if i.EffectiveStatus != "" && i.EffectiveStatus != i.Status {
		parts = append(parts, "effective_status="+i.EffectiveStatus)
	}
	if i.Namespace != "" {
		parts = append(parts, "namespace="+i.Namespace)
	}
	if i.Evidence != "" {
		parts = append(parts, "evidence="+i.Evidence)
	}
	if i.Remediation != "" {
		parts = append(parts, "remediation="+i.Remediation)
	}
	if i.Exemption != nil {
		parts = append(parts, "exemption="+i.Exemption.Reason)
	}
	return strings.Join(parts, "\n")
}

// Collect returns evidence for one scope or all scopes when Query.Scope is empty
// or "all".
func (c Collector) Collect(ctx context.Context, q Query) (Result, error) {
	return c.readInventory(ctx, q)
}

func internalIDForHostCIS(id string) string {
	switch id {
	case "1.1.1":
		return "host.fs.cramfs-disabled"
	case "1.1.2":
		return "host.fs.squashfs-disabled"
	case "3.2.1":
		return "host.net.source-route-disabled"
	case "3.2.2":
		return "host.net.redirects-disabled"
	case "3.3.1":
		return "host.net.tcp-syncookies-enabled"
	case "5.1.2":
		return "host.file.passwd-mode"
	case "5.1.3":
		return "host.file.shadow-mode"
	case "5.2.5":
		return "host.ssh.root-login-disabled"
	case "5.2.10":
		return "host.ssh.password-auth-disabled"
	case "6.1.2":
		return "host.file.sshd-config-mode"
	default:
		return ""
	}
}

func severityForHostCIS(id string) string {
	switch id {
	case "3.2.1", "5.1.3", "5.2.5":
		return "high"
	default:
		return "medium"
	}
}

func remediationForHostCIS(id string) string {
	switch id {
	case "1.1.1", "1.1.2":
		return "Disable the unused filesystem module with a modprobe.d install rule and remove it from loaded modules."
	case "3.2.1", "3.2.2", "3.3.1":
		return "Set the matching kernel sysctl to the benchmark value and persist it under /etc/sysctl.d."
	case "5.1.2", "5.1.3", "6.1.2":
		return "Tighten file ownership and permissions to the benchmark maximum mode."
	case "5.2.5", "5.2.10":
		return "Update sshd_config to disable the risky authentication mode and reload sshd."
	default:
		return "Review the host CIS detail and remediate according to the selected benchmark profile."
	}
}

func uuidArg(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return *id
}
