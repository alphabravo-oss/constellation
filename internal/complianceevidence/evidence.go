// Package complianceevidence builds first-class compliance evidence from the
// posture data Constellation already collects: kube-bench rows, host CIS
// snapshots, workload risk/policy state, and cloud posture findings.
package complianceevidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
}

// Collector reads evidence from Postgres.
type Collector struct {
	Pool *pgxpool.Pool
}

// Result is the API/report-facing evidence envelope.
type Result struct {
	Items   []Item  `json:"items"`
	Summary Summary `json:"summary"`
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
	if q.Limit <= 0 {
		q.Limit = 1000
	}
	q.Scope = strings.ToLower(strings.TrimSpace(q.Scope))
	q.Framework = strings.TrimSpace(q.Framework)
	q.Namespace = strings.TrimSpace(q.Namespace)

	var items []Item
	appendScope := func(scope string, fn func(context.Context, Query) ([]Item, error)) error {
		scoped := q
		scoped.Scope = scope
		out, err := fn(ctx, scoped)
		if err != nil {
			return err
		}
		items = append(items, out...)
		return nil
	}

	switch q.Scope {
	case ScopeAll, "all":
		if err := appendScope(ScopeKubernetes, c.collectKubernetes); err != nil {
			return Result{}, err
		}
		if err := appendScope(ScopeNode, c.collectNodes); err != nil {
			return Result{}, err
		}
		if err := appendScope(ScopeWorkload, c.collectWorkloads); err != nil {
			return Result{}, err
		}
		if err := appendScope(ScopeCloud, c.collectCloud); err != nil {
			return Result{}, err
		}
	case ScopeKubernetes:
		var err error
		items, err = c.collectKubernetes(ctx, q)
		if err != nil {
			return Result{}, err
		}
	case ScopeNode:
		var err error
		items, err = c.collectNodes(ctx, q)
		if err != nil {
			return Result{}, err
		}
	case ScopeWorkload:
		var err error
		items, err = c.collectWorkloads(ctx, q)
		if err != nil {
			return Result{}, err
		}
	case ScopeCloud:
		var err error
		items, err = c.collectCloud(ctx, q)
		if err != nil {
			return Result{}, err
		}
	default:
		return Result{}, fmt.Errorf("unsupported compliance evidence scope %q", q.Scope)
	}

	if len(items) > q.Limit {
		items = items[:q.Limit]
	}
	if err := c.applyExemptions(ctx, q, items); err != nil {
		return Result{}, err
	}
	return Result{Items: items, Summary: summarize(items)}, nil
}

func (c Collector) collectKubernetes(ctx context.Context, q Query) ([]Item, error) {
	rows, err := c.Pool.Query(ctx, `
SELECT framework, control_id, title, COALESCE(description,''), status, severity,
       COALESCE(evidence,''), evaluated_at, COALESCE(tags_v2, '{}'::jsonb),
       cluster_id
  FROM compliance_checks
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND ($3::text = '' OR framework = $3)
 ORDER BY evaluated_at DESC, framework, control_id
 LIMIT $4`, q.OrgID, uuidArg(q.ClusterID), q.Framework, q.Limit)
	if err != nil {
		return nil, fmt.Errorf("collect kubernetes compliance evidence: %w", err)
	}
	defer rows.Close()

	items := make([]Item, 0)
	for rows.Next() {
		var item Item
		var description string
		var tagsRaw []byte
		if err := rows.Scan(&item.Framework, &item.ControlID, &item.Title, &description,
			&item.Status, &item.Severity, &item.Evidence, &item.ObservedAt, &tagsRaw, &item.ClusterID); err != nil {
			return nil, err
		}
		item.Scope = ScopeKubernetes
		item.Source = "compliance_checks"
		item.TargetKind = "cluster"
		item.Target = "cluster"
		item.EffectiveStatus = item.Status
		if item.Evidence == "" {
			item.Evidence = description
		}
		_ = json.Unmarshal(tagsRaw, &item.TagsV2)
		item.ID = evidenceID(item.Scope, item.Source, item.Framework, item.ControlID, item.Target, item.ObservedAt.Format(time.RFC3339Nano))
		items = append(items, item)
	}
	return items, rows.Err()
}

func (c Collector) collectNodes(ctx context.Context, q Query) ([]Item, error) {
	rows, err := c.Pool.Query(ctx, `
SELECT cluster_id, node, COALESCE(profile,''), payload, observed_at
  FROM host_cis
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
 ORDER BY observed_at DESC, node
 LIMIT $3`, q.OrgID, uuidArg(q.ClusterID), q.Limit)
	if err != nil {
		return nil, fmt.Errorf("collect node compliance evidence: %w", err)
	}
	defer rows.Close()

	items := make([]Item, 0)
	for rows.Next() {
		var clusterID *uuid.UUID
		var node, profile string
		var payloadRaw []byte
		var observedAt time.Time
		if err := rows.Scan(&clusterID, &node, &profile, &payloadRaw, &observedAt); err != nil {
			return nil, err
		}
		var payload struct {
			Checks []struct {
				ID     string `json:"id"`
				Title  string `json:"title"`
				Result string `json:"result"`
				Detail string `json:"detail"`
			} `json:"checks"`
		}
		if err := json.Unmarshal(payloadRaw, &payload); err != nil {
			continue
		}
		for _, check := range payload.Checks {
			title := strings.TrimSpace(check.Title)
			if title == "" {
				title = check.ID
			}
			internalID := internalIDForHostCIS(check.ID)
			status := statusFromHostCIS(check.Result)
			evidence := strings.TrimSpace(check.Detail)
			if profile != "" {
				if evidence != "" {
					evidence += "; "
				}
				evidence += "profile=" + profile
			}
			items = append(items, mappedItems(mappedInput{
				Query:       q,
				Scope:       ScopeNode,
				Source:      "host_cis",
				InternalID:  internalID,
				DefaultFW:   compliance.FrameworkCISLinux,
				DefaultID:   check.ID,
				Title:       title,
				Status:      status,
				Severity:    severityForHostCIS(check.ID),
				TargetKind:  "node",
				Target:      node,
				ClusterID:   clusterID,
				Evidence:    evidence,
				Remediation: remediationForHostCIS(check.ID),
				ObservedAt:  observedAt,
			})...)
		}
	}
	return items, rows.Err()
}

func (c Collector) collectWorkloads(ctx context.Context, q Query) ([]Item, error) {
	rows, err := c.Pool.Query(ctx, `
SELECT d.cluster_id, d.namespace, d.name, d.kind, d.risk_score, d.finding_count,
       d.critical_count, d.high_count, d.last_seen_at,
       COALESCE(s.current_mode,''), COALESCE(s.approval_status,''),
       COALESCE(a.flavor,''), COALESCE(a.last_action,''), COALESCE(a.status,''),
       COALESCE(a.resource_ref,''), COALESCE(a.error,''), COALESCE(a.updated_at, s.updated_at, d.last_seen_at)
  FROM deployments d
  LEFT JOIN network_policy_lifecycle_states s
    ON s.org_id = d.org_id
   AND s.cluster_id IS NOT DISTINCT FROM d.cluster_id
   AND s.workload = (d.namespace || '/' || d.name)
  LEFT JOIN LATERAL (
        SELECT flavor, last_action, status, resource_ref, error, updated_at
          FROM network_policy_apply_status a
         WHERE a.org_id = d.org_id
           AND a.cluster_id IS NOT DISTINCT FROM d.cluster_id
           AND a.workload = (d.namespace || '/' || d.name)
         ORDER BY updated_at DESC
         LIMIT 1
       ) a ON TRUE
 WHERE d.org_id = $1
   AND ($2::uuid IS NULL OR d.cluster_id = $2)
   AND ($3::text = '' OR d.namespace = $3)
 ORDER BY d.risk_score DESC, d.last_seen_at DESC
 LIMIT $4`, q.OrgID, uuidArg(q.ClusterID), q.Namespace, q.Limit)
	if err != nil {
		return nil, fmt.Errorf("collect workload compliance evidence: %w", err)
	}
	defer rows.Close()

	items := make([]Item, 0)
	for rows.Next() {
		var clusterID *uuid.UUID
		var namespace, name, kind string
		var riskScore, findingCount, criticalCount, highCount int
		var observedAt time.Time
		var mode, approval, flavor, action, applyStatus, resourceRef, applyError string
		if err := rows.Scan(&clusterID, &namespace, &name, &kind, &riskScore, &findingCount,
			&criticalCount, &highCount, &observedAt, &mode, &approval, &flavor, &action,
			&applyStatus, &resourceRef, &applyError, &observedAt); err != nil {
			return nil, err
		}
		target := namespace + "/" + name

		vulnStatus := "pass"
		vulnSeverity := "info"
		if criticalCount > 0 || highCount > 0 {
			vulnStatus = "fail"
			if criticalCount > 0 {
				vulnSeverity = "critical"
			} else {
				vulnSeverity = "high"
			}
		} else if findingCount > 0 {
			vulnSeverity = "medium"
		}
		items = append(items, mappedItems(mappedInput{
			Query:       q,
			Scope:       ScopeWorkload,
			Source:      "deployments",
			InternalID:  "workload.high-critical-vulnerabilities",
			Title:       "Workload has no unresolved high or critical findings",
			Status:      vulnStatus,
			Severity:    vulnSeverity,
			TargetKind:  kind,
			Target:      target,
			Namespace:   namespace,
			ClusterID:   clusterID,
			Evidence:    fmt.Sprintf("risk_score=%d total_findings=%d critical=%d high=%d", riskScore, findingCount, criticalCount, highCount),
			Remediation: "Resolve or explicitly accept high and critical findings before treating the workload as compliant.",
			ObservedAt:  observedAt,
		})...)

		policyStatus := "fail"
		if mode == "protect" && approval == "applied" && applyStatus == "ok" {
			policyStatus = "pass"
		} else if mode == "protect" && approval == "applied" {
			policyStatus = "manual"
		}
		evidence := fmt.Sprintf("mode=%s approval_status=%s applier_status=%s", valueOr(mode, "unset"), valueOr(approval, "unset"), valueOr(applyStatus, "missing"))
		if flavor != "" {
			evidence += " flavor=" + flavor
		}
		if action != "" {
			evidence += " last_action=" + action
		}
		if resourceRef != "" {
			evidence += " resource=" + resourceRef
		}
		if applyError != "" {
			evidence += " error=" + applyError
		}
		items = append(items, mappedItems(mappedInput{
			Query:       q,
			Scope:       ScopeWorkload,
			Source:      "network_policy_lifecycle",
			InternalID:  "workload.network-policy-enforced",
			Title:       "Workload traffic is governed by an applied network policy",
			Status:      policyStatus,
			Severity:    "high",
			TargetKind:  kind,
			Target:      target,
			Namespace:   namespace,
			ClusterID:   clusterID,
			Evidence:    evidence,
			Remediation: "Approve and apply the learned network policy, then confirm the live applier reports status=ok.",
			ObservedAt:  observedAt,
		})...)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	imageItems, err := c.collectWorkloadImageArtifacts(ctx, q)
	if err != nil {
		return nil, err
	}
	items = append(items, imageItems...)
	return items, nil
}

func (c Collector) collectWorkloadImageArtifacts(ctx context.Context, q Query) ([]Item, error) {
	rows, err := c.Pool.Query(ctx, `
SELECT l.cluster_id,
       l.namespace,
       l.name,
       l.kind,
       l.image_ref,
       COALESCE(l.image_digest, ''),
       r.id,
       COALESCE(r.last_scanned_at, l.last_seen_at),
       COALESCE(sec.secret_count, -1)::int,
       COALESCE(sec.status, ''),
       COALESCE(fr.file_risk_count, -1)::int,
       COALESCE(fr.status, ''),
       COALESCE(fr.max_severity_rank, 0)::int,
       COALESCE(fr.risk_types, '')
  FROM image_workload_links l
  LEFT JOIN LATERAL (
        SELECT r.id, r.last_scanned_at
          FROM image_scan_results r
         WHERE r.org_id = l.org_id
           AND (
                (COALESCE(l.image_digest, '') <> '' AND r.image_digest = l.image_digest)
             OR (l.image_ref <> '' AND r.image_ref = l.image_ref)
             OR (l.image_ref_normalized <> '' AND r.image_ref_normalized = l.image_ref_normalized)
           )
         ORDER BY r.last_scanned_at DESC, r.updated_at DESC
         LIMIT 1
       ) r ON TRUE
  LEFT JOIN LATERAL (
        SELECT COALESCE(NULLIF(a.payload->>'secret_count', '')::int, a.package_count) AS secret_count,
               COALESCE(NULLIF(a.payload->>'status', ''), 'observed') AS status
          FROM image_scan_artifacts a
         WHERE a.org_id = l.org_id
           AND a.image_scan_result_id = r.id
           AND a.artifact_type = 'secret-scan'
           AND a.format = 'constellation-image-secrets-v1'
         ORDER BY a.created_at DESC
         LIMIT 1
       ) sec ON TRUE
  LEFT JOIN LATERAL (
        SELECT COALESCE(NULLIF(a.payload->>'file_risk_count', '')::int, a.package_count) AS file_risk_count,
               COALESCE(NULLIF(a.payload->>'status', ''), 'observed') AS status,
               COALESCE((
                   SELECT MAX(CASE lower(f.value->>'severity')
                                WHEN 'critical' THEN 5
                                WHEN 'high' THEN 4
                                WHEN 'medium' THEN 3
                                WHEN 'low' THEN 2
                                ELSE 1
                              END)::int
                     FROM jsonb_array_elements(COALESCE(a.payload->'findings', '[]'::jsonb)) AS f(value)
               ), 0)::int AS max_severity_rank,
               COALESCE((
                   SELECT string_agg(DISTINCT rt.value, ',')
                     FROM jsonb_array_elements(COALESCE(a.payload->'findings', '[]'::jsonb)) AS f(value)
                     CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(f.value->'risk_types', '[]'::jsonb)) AS rt(value)
               ), '') AS risk_types
          FROM image_scan_artifacts a
         WHERE a.org_id = l.org_id
           AND a.image_scan_result_id = r.id
           AND a.artifact_type = 'file-risk'
           AND a.format = 'constellation-image-file-risk-v1'
         ORDER BY a.created_at DESC
         LIMIT 1
       ) fr ON TRUE
 WHERE l.org_id = $1
   AND ($2::uuid IS NULL OR l.cluster_id = $2)
   AND ($3::text = '' OR l.namespace = $3)
 ORDER BY l.last_seen_at DESC, l.namespace, l.name, l.image_ref
 LIMIT $4`, q.OrgID, uuidArg(q.ClusterID), q.Namespace, q.Limit)
	if err != nil {
		return nil, fmt.Errorf("collect workload image artifact evidence: %w", err)
	}
	defer rows.Close()

	items := []Item{}
	for rows.Next() {
		var clusterID *uuid.UUID
		var resultID *uuid.UUID
		var namespace, name, kind, imageRef, imageDigest string
		var observedAt time.Time
		var secretCount, fileRiskCount, fileRiskSeverityRank int
		var secretStatus, fileRiskStatus, riskTypes string
		if err := rows.Scan(&clusterID, &namespace, &name, &kind, &imageRef, &imageDigest,
			&resultID, &observedAt, &secretCount, &secretStatus, &fileRiskCount, &fileRiskStatus,
			&fileRiskSeverityRank, &riskTypes); err != nil {
			return nil, err
		}
		secretStatus = strings.ToLower(strings.TrimSpace(secretStatus))
		fileRiskStatus = strings.ToLower(strings.TrimSpace(fileRiskStatus))

		target := workloadImageTarget(namespace, name, imageRef, imageDigest)
		imageEvidence := "image_ref=" + imageRef
		if imageDigest != "" {
			imageEvidence += " image_digest=" + imageDigest
		}
		if resultID != nil {
			imageEvidence += " image_scan_result_id=" + resultID.String()
		}

		secretStatusValue := "manual"
		secretSeverity := "medium"
		secretEvidence := imageEvidence
		switch {
		case resultID == nil:
			secretEvidence += " secret_scan=missing image_scan_result=missing"
		case secretCount < 0:
			secretEvidence += " secret_scan=missing"
		case secretStatus != "" && secretStatus != "observed":
			secretEvidence += fmt.Sprintf(" secret_scan_status=%s secret_count=%d", secretStatus, secretCount)
		case secretCount > 0:
			secretStatusValue = "fail"
			secretSeverity = "high"
			secretEvidence += fmt.Sprintf(" secret_scan_status=observed secret_count=%d", secretCount)
		default:
			secretStatusValue = "pass"
			secretSeverity = "info"
			secretEvidence += " secret_scan_status=observed secret_count=0"
		}
		items = append(items, mappedItems(mappedInput{
			Query:       q,
			Scope:       ScopeWorkload,
			Source:      "image_scan_artifacts",
			InternalID:  "container.image-secrets-absent",
			Title:       "Images contain no embedded secret findings",
			Status:      secretStatusValue,
			Severity:    secretSeverity,
			TargetKind:  kind + "/image",
			Target:      target,
			Namespace:   namespace,
			ClusterID:   clusterID,
			Evidence:    secretEvidence,
			Remediation: "Remove embedded secrets from the image, rotate exposed credentials, rebuild, and rescan the image.",
			ObservedAt:  observedAt,
		})...)

		fileRiskStatusValue := "manual"
		fileRiskSeverity := "medium"
		fileRiskEvidence := imageEvidence
		switch {
		case resultID == nil:
			fileRiskEvidence += " file_risk_scan=missing image_scan_result=missing"
		case fileRiskCount < 0:
			fileRiskEvidence += " file_risk_scan=missing"
		case fileRiskStatus != "" && fileRiskStatus != "observed":
			fileRiskEvidence += fmt.Sprintf(" file_risk_status=%s file_risk_count=%d", fileRiskStatus, fileRiskCount)
		case fileRiskCount > 0:
			fileRiskStatusValue = "fail"
			fileRiskSeverity = severityFromRank(fileRiskSeverityRank, "high")
			fileRiskEvidence += fmt.Sprintf(" file_risk_status=observed file_risk_count=%d", fileRiskCount)
			if riskTypes != "" {
				fileRiskEvidence += " risk_types=" + riskTypes
			}
		default:
			fileRiskStatusValue = "pass"
			fileRiskSeverity = "info"
			fileRiskEvidence += " file_risk_status=observed file_risk_count=0"
		}
		items = append(items, mappedItems(mappedInput{
			Query:       q,
			Scope:       ScopeWorkload,
			Source:      "image_scan_artifacts",
			InternalID:  "container.image-file-risks-absent",
			Title:       "Images contain no risky filesystem metadata",
			Status:      fileRiskStatusValue,
			Severity:    fileRiskSeverity,
			TargetKind:  kind + "/image",
			Target:      target,
			Namespace:   namespace,
			ClusterID:   clusterID,
			Evidence:    fileRiskEvidence,
			Remediation: "Remove setuid/setgid binaries, world-writable sensitive paths, device nodes, and other risky filesystem metadata from the image, then rebuild and rescan.",
			ObservedAt:  observedAt,
		})...)
	}
	return items, rows.Err()
}

func (c Collector) collectCloud(ctx context.Context, q Query) ([]Item, error) {
	var observed, assessed, openFindings int
	var lastAssessment *time.Time
	if err := c.Pool.QueryRow(ctx, `
SELECT COUNT(DISTINCT a.id) FILTER (WHERE a.kind = 'cloud-resource')::int,
       COUNT(DISTINCT a.id) FILTER (WHERE a.kind = 'cloud-resource' AND f.id IS NOT NULL)::int,
       COUNT(f.id) FILTER (WHERE f.kind = 'cloud-config' AND f.lifecycle = 'open')::int,
       MAX(f.last_seen_at) FILTER (WHERE f.kind = 'cloud-config')
  FROM assets a
  LEFT JOIN findings f ON f.org_id = a.org_id AND f.asset_id = a.id AND f.kind = 'cloud-config'
 WHERE a.org_id = $1
   AND ($2::uuid IS NULL OR a.cluster_id = $2)`, q.OrgID, uuidArg(q.ClusterID)).
		Scan(&observed, &assessed, &openFindings, &lastAssessment); err != nil {
		return nil, fmt.Errorf("collect cloud compliance summary: %w", err)
	}
	observedAt := time.Now().UTC()
	if lastAssessment != nil {
		observedAt = lastAssessment.UTC()
	}
	status := "pass"
	if observed == 0 {
		status = "not_applicable"
	} else if openFindings > 0 {
		status = "fail"
	}
	items := mappedItems(mappedInput{
		Query:       q,
		Scope:       ScopeCloud,
		Source:      "cloud_posture",
		InternalID:  "cloud.posture.open-findings",
		Title:       "Cloud resource posture findings are remediated",
		Status:      status,
		Severity:    "high",
		TargetKind:  "cloud",
		Target:      "cloud-resources",
		Evidence:    fmt.Sprintf("resources_observed=%d resources_assessed=%d open_findings=%d", observed, assessed, openFindings),
		Remediation: "Enable cloud connector assessment and remediate open cloud-config findings.",
		ObservedAt:  observedAt,
	})

	rows, err := c.Pool.Query(ctx, `
SELECT a.cluster_id, a.name, COALESCE(f.external_id,''), f.title, f.severity,
       COALESCE(f.description,''), f.last_seen_at
  FROM findings f
  JOIN assets a ON a.id = f.asset_id AND a.org_id = f.org_id
 WHERE f.org_id = $1
   AND f.kind = 'cloud-config'
   AND f.lifecycle = 'open'
   AND ($2::uuid IS NULL OR a.cluster_id = $2)
 ORDER BY f.risk_score DESC, f.last_seen_at DESC
 LIMIT $3`, q.OrgID, uuidArg(q.ClusterID), q.Limit)
	if err != nil {
		return nil, fmt.Errorf("collect cloud compliance findings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var clusterID *uuid.UUID
		var target, externalID, title, severity, description string
		var seenAt time.Time
		if err := rows.Scan(&clusterID, &target, &externalID, &title, &severity, &description, &seenAt); err != nil {
			return nil, err
		}
		evidence := title
		if externalID != "" {
			evidence = externalID + ": " + evidence
		}
		if description != "" {
			evidence += " - " + description
		}
		items = append(items, mappedItems(mappedInput{
			Query:       q,
			Scope:       ScopeCloud,
			Source:      "cloud_config_findings",
			InternalID:  "cloud.posture.open-findings",
			Title:       "Cloud resource posture findings are remediated",
			Status:      "fail",
			Severity:    severity,
			TargetKind:  "cloud-resource",
			Target:      target,
			ClusterID:   clusterID,
			Evidence:    evidence,
			Remediation: "Remediate the cloud-config finding or document a time-bound exemption.",
			ObservedAt:  seenAt,
		})...)
	}
	return items, rows.Err()
}

func (c Collector) applyExemptions(ctx context.Context, q Query, items []Item) error {
	for i := range items {
		items[i].EffectiveStatus = items[i].Status
	}
	rows, err := c.Pool.Query(ctx, `
SELECT framework, control_id, id::text, reason, expires_at
  FROM compliance_exemptions
 WHERE org_id = $1
   AND revoked_at IS NULL
   AND expires_at > NOW()
   AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)
 ORDER BY (cluster_id IS NULL), created_at DESC`, q.OrgID, uuidArg(q.ClusterID))
	if err != nil {
		if strings.Contains(err.Error(), "compliance_exemptions") {
			return nil
		}
		return fmt.Errorf("collect compliance exemptions: %w", err)
	}
	defer rows.Close()
	exemptions := map[string]Exemption{}
	for rows.Next() {
		var framework, controlID string
		var ex Exemption
		if err := rows.Scan(&framework, &controlID, &ex.ID, &ex.Reason, &ex.ExpiresAt); err != nil {
			return err
		}
		key := framework + "\x00" + controlID
		if _, ok := exemptions[key]; !ok {
			exemptions[key] = ex
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range items {
		if items[i].Status != "fail" {
			continue
		}
		ex, ok := exemptions[items[i].Framework+"\x00"+items[i].ControlID]
		if !ok {
			continue
		}
		items[i].EffectiveStatus = "exempted"
		items[i].Exemption = &ex
	}
	return nil
}

type mappedInput struct {
	Query       Query
	Scope       string
	Source      string
	InternalID  string
	DefaultFW   string
	DefaultID   string
	Title       string
	Status      string
	Severity    string
	TargetKind  string
	Target      string
	Namespace   string
	ClusterID   *uuid.UUID
	Evidence    string
	Remediation string
	ObservedAt  time.Time
}

func mappedItems(in mappedInput) []Item {
	status := normalizeStatus(in.Status)
	severity := strings.ToLower(strings.TrimSpace(in.Severity))
	if severity == "" {
		severity = "medium"
	}
	if in.ObservedAt.IsZero() {
		in.ObservedAt = time.Now().UTC()
	}
	mapping, mapped := compliance.MappingByInternalID(in.InternalID)
	if !mapped {
		return defaultMappedItem(in, status, severity)
	}
	if in.Title == "" {
		in.Title = mapping.Title
	}
	if in.Severity == "" {
		severity = mapping.Severity
	}
	tags := compliance.BuildTagsV2(in.InternalID)
	out := []Item{}
	for framework, controlID := range mapping.Controls {
		if in.Query.Framework != "" && framework != in.Query.Framework {
			continue
		}
		item := baseItem(in, framework, controlID, status, severity)
		item.TagsV2 = tags
		out = append(out, item)
	}
	return out
}

func defaultMappedItem(in mappedInput, status, severity string) []Item {
	framework := in.DefaultFW
	if framework == "" {
		framework = compliance.FrameworkCISK8s
	}
	controlID := in.DefaultID
	if controlID == "" {
		controlID = in.InternalID
	}
	if in.Query.Framework != "" && in.Query.Framework != framework {
		return nil
	}
	return []Item{baseItem(in, framework, controlID, status, severity)}
}

func baseItem(in mappedInput, framework, controlID, status, severity string) Item {
	item := Item{
		Scope:           in.Scope,
		Source:          in.Source,
		Framework:       framework,
		ControlID:       controlID,
		InternalID:      in.InternalID,
		Title:           in.Title,
		Severity:        severity,
		Status:          status,
		EffectiveStatus: status,
		TargetKind:      in.TargetKind,
		Target:          in.Target,
		Namespace:       in.Namespace,
		ClusterID:       in.ClusterID,
		Evidence:        in.Evidence,
		Remediation:     in.Remediation,
		ObservedAt:      in.ObservedAt.UTC(),
	}
	item.ID = evidenceID(item.Scope, item.Source, item.Framework, item.ControlID, item.Target, item.ObservedAt.Format(time.RFC3339Nano))
	return item
}

func summarize(items []Item) Summary {
	out := Summary{ByScope: map[string]ScopeSummary{}}
	for _, item := range items {
		out.Total++
		scope := out.ByScope[item.Scope]
		scope.Total++
		switch item.EffectiveStatus {
		case "pass":
			out.Pass++
			scope.Pass++
		case "fail":
			out.Fail++
			scope.Fail++
		case "exempted":
			out.Exempted++
			scope.Exempted++
		case "not_applicable":
			out.NotApplicable++
			scope.NotApplicable++
		default:
			out.Manual++
			scope.Manual++
		}
		out.ByScope[item.Scope] = scope
	}
	return out
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

func statusFromHostCIS(result string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "pass":
		return "pass"
	case "fail":
		return "fail"
	case "skip", "skipped":
		return "not_applicable"
	default:
		return "manual"
	}
}

func normalizeStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "pass", "fail", "manual", "not_applicable":
		return strings.ToLower(strings.TrimSpace(status))
	case "warn", "warning":
		return "manual"
	case "skip", "skipped", "info", "n/a", "na":
		return "not_applicable"
	default:
		return "manual"
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

func valueOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func workloadImageTarget(namespace, name, imageRef, imageDigest string) string {
	target := strings.TrimSpace(namespace + "/" + name)
	image := strings.TrimSpace(imageDigest)
	if image == "" {
		image = strings.TrimSpace(imageRef)
	}
	if image == "" {
		return target
	}
	return target + " " + image
}

func severityFromRank(rank int, fallback string) string {
	switch rank {
	case 5:
		return "critical"
	case 4:
		return "high"
	case 3:
		return "medium"
	case 2:
		return "low"
	case 1:
		return "info"
	default:
		return fallback
	}
}

func uuidArg(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return *id
}

func evidenceID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:12])
}

var _ = pgx.ErrNoRows
