package scanning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/scanner"
)

type ServerlessPackagesHandler struct {
	db *db.DB
}

func NewServerlessPackages(d *db.DB) *ServerlessPackagesHandler {
	return &ServerlessPackagesHandler{db: d}
}

type ServerlessPackagesPayload struct {
	FunctionRef        string                    `json:"function_ref"`
	FunctionName       string                    `json:"function_name,omitempty"`
	Provider           string                    `json:"provider,omitempty"`
	AccountID          string                    `json:"account_id,omitempty"`
	Region             string                    `json:"region,omitempty"`
	Runtime            string                    `json:"runtime,omitempty"`
	Version            string                    `json:"version,omitempty"`
	Architecture       string                    `json:"architecture,omitempty"`
	SourceType         string                    `json:"source_type,omitempty"`
	SourceRef          string                    `json:"source_ref,omitempty"`
	ObservedAt         time.Time                 `json:"observed_at,omitempty"`
	Packages           []scanner.Package         `json:"packages,omitempty"`
	Items              []handler.HostPackageItem `json:"items,omitempty"`
	PackageSource      string                    `json:"package_source,omitempty"`
	CodeSHA256         string                    `json:"code_sha256,omitempty"`
	Role               string                    `json:"role,omitempty"`
	Handler            string                    `json:"handler,omitempty"`
	PackageType        string                    `json:"package_type,omitempty"`
	Layers             []string                  `json:"layers,omitempty"`
	PermissionAnalysis json.RawMessage           `json:"permission_analysis,omitempty"`
}

func (h *ServerlessPackagesHandler) Report(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)

	var body ServerlessPackagesPayload
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	body.FunctionRef = strings.TrimSpace(body.FunctionRef)
	body.FunctionName = strings.TrimSpace(body.FunctionName)
	body.Provider = strings.TrimSpace(body.Provider)
	body.AccountID = strings.TrimSpace(body.AccountID)
	body.Region = strings.TrimSpace(body.Region)
	body.Runtime = strings.TrimSpace(body.Runtime)
	body.Version = strings.TrimSpace(body.Version)
	body.Architecture = strings.TrimSpace(body.Architecture)
	body.SourceType = normalizeServerlessSourceType(body.SourceType)
	body.SourceRef = strings.TrimSpace(body.SourceRef)
	body.PackageSource = strings.TrimSpace(body.PackageSource)
	body.CodeSHA256 = strings.TrimSpace(body.CodeSHA256)
	body.Role = strings.TrimSpace(body.Role)
	body.Handler = strings.TrimSpace(body.Handler)
	body.PackageType = strings.TrimSpace(body.PackageType)
	body.Layers = trimmedUniqueServerlessStrings(body.Layers)
	permissionAnalysisMetadata, permissionAnalysis, err := normalizeServerlessPermissionAnalysis(body.PermissionAnalysis)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid permission_analysis: "+err.Error())
		return
	}
	if body.FunctionRef == "" {
		jsonError(w, http.StatusBadRequest, "function_ref is required")
		return
	}
	if !handler.ValidScanSourceType(body.SourceType) {
		jsonError(w, http.StatusBadRequest, "unsupported source_type")
		return
	}
	if body.ObservedAt.IsZero() {
		body.ObservedAt = time.Now().UTC()
	}
	packages := scannerPackagesFromServerlessPackages(body)
	if len(packages) == 0 {
		jsonError(w, http.StatusBadRequest, "no packages in serverless evidence")
		return
	}
	if body.SourceRef == "" {
		body.SourceRef = defaultServerlessSourceRef(body)
	}

	evidencePayload := handler.ScanEvidencePackagePayload{
		Packages:     packages,
		Source:       body.PackageSource,
		Runtime:      body.Runtime,
		FunctionRef:  body.FunctionRef,
		Provider:     body.Provider,
		AccountID:    body.AccountID,
		Region:       body.Region,
		Version:      body.Version,
		Architecture: body.Architecture,
	}
	inventoryHash, err := handler.PackageEvidenceHash(evidencePayload)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "evidence hash: "+err.Error())
		return
	}
	metadataMap := map[string]any{
		"function_ref":  body.FunctionRef,
		"function_name": body.FunctionName,
		"provider":      body.Provider,
		"account_id":    body.AccountID,
		"region":        body.Region,
		"runtime":       body.Runtime,
		"version":       body.Version,
		"architecture":  body.Architecture,
		"package_count": len(packages),
		"code_sha256":   body.CodeSHA256,
		"role":          body.Role,
		"handler":       body.Handler,
		"package_type":  body.PackageType,
		"layers":        body.Layers,
	}
	if permissionAnalysisMetadata != nil {
		metadataMap["permission_analysis"] = permissionAnalysisMetadata
	}
	metadata, _ := json.Marshal(metadataMap)

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "begin: "+err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	target, err := handler.UpsertScanTarget(r.Context(), nil, tx, subj.OrgID, handler.ScanTargetUpsert{
		TargetType:    "serverless",
		TargetRef:     body.FunctionRef,
		SourceType:    body.SourceType,
		SourceRef:     body.SourceRef,
		InventoryHash: inventoryHash,
		Metadata:      metadata,
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "scan target: "+err.Error())
		return
	}
	if err := upsertServerlessPermissionFindings(r.Context(), tx, subj.OrgID, target, body, permissionAnalysis); err != nil {
		jsonError(w, http.StatusInternalServerError, "permission findings: "+err.Error())
		return
	}
	evidenceID, err := handler.UpsertPackageScanEvidence(r.Context(), tx, subj.OrgID, target, inventoryHash, evidencePayload, body.ObservedAt)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "scan evidence: "+err.Error())
		return
	}

	var exists bool
	if err := tx.QueryRow(r.Context(), `
SELECT EXISTS(
    SELECT 1
      FROM scan_jobs
     WHERE org_id = $1
       AND target_id = $2
       AND status IN ('pending', 'running', 'paused')
)`, subj.OrgID, target.ID).Scan(&exists); err != nil {
		jsonError(w, http.StatusInternalServerError, "scan job check: "+err.Error())
		return
	}
	var jobID *uuid.UUID
	if !exists {
		id := uuid.New()
		if _, err := tx.Exec(r.Context(), `
INSERT INTO scan_jobs (id, org_id, target_id, status, requested_by)
VALUES ($1, $2, $3, 'pending', $4)`, id, subj.OrgID, target.ID, subj.UserID); err != nil {
			jsonError(w, http.StatusInternalServerError, "enqueue scan job: "+err.Error())
			return
		}
		jobID = &id
	}

	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"scan_target_id":     target.ID,
		"scan_evidence_id":   evidenceID,
		"inventory_hash":     inventoryHash,
		"package_count":      len(packages),
		"scan_job_enqueued":  jobID != nil,
		"scan_job_id":        jobID,
		"scanner_source":     "scan_evidence",
		"scanner_target_ref": target.Ref,
	})
}

func scannerPackagesFromServerlessPackages(body ServerlessPackagesPayload) []scanner.Package {
	defaultEcosystem := ecosystemFromServerlessRuntime(body.Runtime)
	out := make([]scanner.Package, 0, len(body.Packages)+len(body.Items))
	for _, pkg := range body.Packages {
		name := strings.TrimSpace(pkg.Name)
		version := strings.TrimSpace(pkg.Version)
		if name == "" || version == "" {
			continue
		}
		ecosystem := strings.TrimSpace(pkg.Ecosystem)
		if ecosystem == "" {
			ecosystem = defaultEcosystem
		}
		pkg.Ecosystem = ecosystem
		pkg.Name = name
		pkg.Version = version
		pkg.Purl = strings.TrimSpace(pkg.Purl)
		pkg.NamespaceKind = handler.FirstNonEmpty(strings.TrimSpace(pkg.NamespaceKind), "language")
		pkg.NamespaceName = handler.FirstNonEmpty(strings.TrimSpace(pkg.NamespaceName), ecosystem)
		pkg.NamespaceVersion = handler.FirstNonEmpty(strings.TrimSpace(pkg.NamespaceVersion), strings.TrimSpace(body.Runtime))
		pkg.Arch = handler.FirstNonEmpty(strings.TrimSpace(pkg.Arch), strings.TrimSpace(body.Architecture))
		out = append(out, pkg)
	}
	itemSource := strings.TrimSpace(body.PackageSource)
	if itemSource == "" {
		itemSource = defaultEcosystem
	}
	for _, item := range body.Items {
		name := strings.TrimSpace(item.Name)
		version := strings.TrimSpace(item.Version)
		if name == "" || version == "" {
			continue
		}
		source := strings.TrimSpace(item.Source)
		if source == "" {
			source = itemSource
		}
		out = append(out, scanner.Package{
			Ecosystem:        source,
			Name:             name,
			Version:          version,
			Arch:             handler.FirstNonEmpty(strings.TrimSpace(item.Arch), strings.TrimSpace(body.Architecture)),
			NamespaceKind:    "language",
			NamespaceName:    source,
			NamespaceVersion: strings.TrimSpace(body.Runtime),
		})
	}
	return out
}

func normalizeServerlessSourceType(sourceType string) string {
	sourceType = strings.ToLower(strings.TrimSpace(sourceType))
	if sourceType == "" {
		return "manual"
	}
	return sourceType
}

func defaultServerlessSourceRef(body ServerlessPackagesPayload) string {
	parts := []string{}
	for _, part := range []string{body.Provider, body.AccountID, body.Region, body.FunctionRef} {
		part = strings.TrimSpace(part)
		if part != "" {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return body.FunctionRef
	}
	return strings.Join(parts, "/")
}

func ecosystemFromServerlessRuntime(runtime string) string {
	runtime = strings.ToLower(strings.TrimSpace(runtime))
	switch {
	case strings.HasPrefix(runtime, "python"):
		return "pypi"
	case strings.HasPrefix(runtime, "nodejs"):
		return "npm"
	case strings.HasPrefix(runtime, "java"):
		return "maven"
	case strings.HasPrefix(runtime, "dotnet"):
		return "nuget"
	case strings.HasPrefix(runtime, "ruby"):
		return "gem"
	case strings.HasPrefix(runtime, "go"):
		return "go"
	default:
		return ""
	}
}

func trimmedUniqueServerlessStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

type serverlessPermissionAnalysis struct {
	Status           string                                `json:"status"`
	Level            string                                `json:"level"`
	RoleARN          string                                `json:"role_arn,omitempty"`
	RoleName         string                                `json:"role_name,omitempty"`
	Error            string                                `json:"error,omitempty"`
	AttachedPolicies []serverlessPermissionPolicyRef       `json:"attached_policies,omitempty"`
	InlinePolicies   []string                              `json:"inline_policies,omitempty"`
	Findings         []serverlessPermissionFindingAnalysis `json:"findings,omitempty"`
	SensitiveActions []string                              `json:"sensitive_actions,omitempty"`
	ActionCount      int                                   `json:"action_count,omitempty"`
}

type serverlessPermissionPolicyRef struct {
	Name string `json:"name,omitempty"`
	ARN  string `json:"arn,omitempty"`
}

type serverlessPermissionFindingAnalysis struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	PolicyType  string   `json:"policy_type,omitempty"`
	PolicyName  string   `json:"policy_name,omitempty"`
	PolicyARN   string   `json:"policy_arn,omitempty"`
	Actions     []string `json:"actions,omitempty"`
	Resources   []string `json:"resources,omitempty"`
}

func normalizeServerlessPermissionAnalysis(raw json.RawMessage) (map[string]any, *serverlessPermissionAnalysis, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil, nil, nil
	}
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return nil, nil, err
	}
	if metadata == nil {
		return nil, nil, fmt.Errorf("must be a JSON object")
	}
	var analysis serverlessPermissionAnalysis
	if err := json.Unmarshal(raw, &analysis); err != nil {
		return nil, nil, err
	}
	analysis.normalize()
	return metadata, &analysis, nil
}

func (a *serverlessPermissionAnalysis) normalize() {
	if a == nil {
		return
	}
	a.Status = strings.ToLower(strings.TrimSpace(a.Status))
	a.Level = normalizeServerlessPermissionSeverity(a.Level)
	a.RoleARN = strings.TrimSpace(a.RoleARN)
	a.RoleName = strings.TrimSpace(a.RoleName)
	a.Error = strings.TrimSpace(a.Error)
	for i := range a.AttachedPolicies {
		a.AttachedPolicies[i].Name = strings.TrimSpace(a.AttachedPolicies[i].Name)
		a.AttachedPolicies[i].ARN = strings.TrimSpace(a.AttachedPolicies[i].ARN)
	}
	a.InlinePolicies = trimmedUniqueServerlessStrings(a.InlinePolicies)
	a.SensitiveActions = trimmedUniqueServerlessStrings(a.SensitiveActions)
	for i := range a.Findings {
		a.Findings[i].ID = strings.TrimSpace(a.Findings[i].ID)
		a.Findings[i].Severity = normalizeServerlessPermissionSeverity(a.Findings[i].Severity)
		a.Findings[i].Title = strings.TrimSpace(a.Findings[i].Title)
		a.Findings[i].Description = strings.TrimSpace(a.Findings[i].Description)
		a.Findings[i].PolicyType = strings.TrimSpace(a.Findings[i].PolicyType)
		a.Findings[i].PolicyName = strings.TrimSpace(a.Findings[i].PolicyName)
		a.Findings[i].PolicyARN = strings.TrimSpace(a.Findings[i].PolicyARN)
		a.Findings[i].Actions = trimmedUniqueServerlessStrings(a.Findings[i].Actions)
		a.Findings[i].Resources = trimmedUniqueServerlessStrings(a.Findings[i].Resources)
	}
}

func upsertServerlessPermissionFindings(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, target handler.ScanTarget, body ServerlessPackagesPayload, analysis *serverlessPermissionAnalysis) error {
	if analysis == nil {
		return nil
	}
	roleARN := handler.FirstNonEmpty(analysis.RoleARN, body.Role)
	if roleARN == "" && len(analysis.Findings) == 0 && strings.EqualFold(analysis.Status, "complete") {
		return resolveStaleServerlessPermissionFindings(ctx, tx, orgID, target.ID, nil)
	}
	assetID, err := upsertServerlessPermissionAsset(ctx, tx, orgID, body, analysis, roleARN)
	if err != nil {
		return err
	}
	currentKeys := []string{}
	for _, finding := range analysis.Findings {
		if finding.ID == "" {
			continue
		}
		key := serverlessPermissionStableKey(body, analysis, finding)
		if err := upsertServerlessPermissionFinding(ctx, tx, orgID, assetID, target, body, analysis, finding, key); err != nil {
			return err
		}
		currentKeys = append(currentKeys, key)
	}
	if len(currentKeys) == 0 && analysis.Status != "complete" && analysis.Error != "" {
		finding := serverlessPermissionFindingAnalysis{
			ID:          "serverless-permission-analysis-unavailable",
			Severity:    "info",
			Title:       "Serverless execution-role permission analysis is unavailable",
			Description: analysis.Error,
		}
		key := serverlessPermissionStableKey(body, analysis, finding)
		if err := upsertServerlessPermissionFinding(ctx, tx, orgID, assetID, target, body, analysis, finding, key); err != nil {
			return err
		}
		currentKeys = append(currentKeys, key)
	}
	if analysis.Status == "complete" {
		if err := resolveStaleServerlessPermissionFindings(ctx, tx, orgID, target.ID, currentKeys); err != nil {
			return err
		}
	}
	return nil
}

func upsertServerlessPermissionAsset(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, body ServerlessPackagesPayload, analysis *serverlessPermissionAnalysis, roleARN string) (uuid.UUID, error) {
	name := handler.FirstNonEmpty(roleARN, body.FunctionRef)
	if name == "" {
		return uuid.Nil, fmt.Errorf("permission asset identity required")
	}
	labels := map[string]any{
		"provider":      body.Provider,
		"account_id":    body.AccountID,
		"region":        body.Region,
		"function_ref":  body.FunctionRef,
		"function_name": body.FunctionName,
		"role_arn":      roleARN,
		"role_name":     analysis.RoleName,
		"resource_type": "serverless-execution-role",
	}
	if roleARN == "" {
		labels["resource_type"] = "serverless-function"
	}
	labelsJSON, _ := json.Marshal(labels)
	criticality := normalizeServerlessPermissionSeverity(handler.FirstNonEmpty(analysis.Level, "medium"))
	var id uuid.UUID
	err := tx.QueryRow(ctx, `
INSERT INTO assets (org_id, kind, name, digest, labels, criticality, last_seen_at)
VALUES ($1, 'cloud-resource', $2, '', $3::jsonb, $4, NOW())
ON CONFLICT (org_id, kind, name, digest) DO UPDATE SET
    labels = assets.labels || EXCLUDED.labels,
    criticality = EXCLUDED.criticality,
    last_seen_at = NOW()
RETURNING id`, orgID, name, string(labelsJSON), criticality).Scan(&id)
	return id, err
}

func upsertServerlessPermissionFinding(
	ctx context.Context,
	tx pgx.Tx,
	orgID uuid.UUID,
	assetID uuid.UUID,
	target handler.ScanTarget,
	body ServerlessPackagesPayload,
	analysis *serverlessPermissionAnalysis,
	finding serverlessPermissionFindingAnalysis,
	stableKey string,
) error {
	severity := normalizeServerlessPermissionSeverity(finding.Severity)
	title := finding.Title
	if title == "" {
		title = "Serverless execution-role permission issue"
	}
	description := finding.Description
	if description == "" {
		description = "The serverless execution role permission analysis detected a risky IAM permission pattern."
	}
	detail := map[string]any{
		"category":        "serverless-permission",
		"stable_key":      stableKey,
		"analysis_status": analysis.Status,
		"analysis_level":  analysis.Level,
		"provider":        body.Provider,
		"account_id":      body.AccountID,
		"region":          body.Region,
		"function_ref":    body.FunctionRef,
		"function_name":   body.FunctionName,
		"role_arn":        handler.FirstNonEmpty(analysis.RoleARN, body.Role),
		"role_name":       analysis.RoleName,
		"policy_type":     finding.PolicyType,
		"policy_name":     finding.PolicyName,
		"policy_arn":      finding.PolicyARN,
		"actions":         finding.Actions,
		"resources":       finding.Resources,
		"source_ref":      body.SourceRef,
	}
	detailJSON, _ := json.Marshal(detail)
	enginesJSON, _ := json.Marshal([]map[string]string{{
		"name":    "constellation-serverless-permissions",
		"version": "builtin",
	}})

	var existing uuid.UUID
	err := tx.QueryRow(ctx, `
SELECT id
  FROM findings
 WHERE org_id = $1
   AND kind = 'cloud-config'
   AND scan_target_id = $2
   AND detail_json->>'stable_key' = $3
 ORDER BY last_seen_at DESC
 LIMIT 1`, orgID, target.ID, stableKey).Scan(&existing)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	if err == nil {
		_, err = tx.Exec(ctx, `
UPDATE findings
   SET asset_id = $2,
       cluster_id = $3,
       external_id = NULLIF($4, ''),
       title = $5,
       description = $6,
       severity = $7,
       risk_score = $8,
       engines = $9::jsonb,
       detail_json = $10::jsonb,
       scan_target_id = $11,
       target_type = NULLIF($12, ''),
       target_ref = NULLIF($13, ''),
       target_cluster_id = $14,
       source_type = NULLIF($15, ''),
       last_seen_at = NOW(),
       lifecycle = CASE WHEN lifecycle = 'resolved' THEN 'open' ELSE lifecycle END
 WHERE id = $1 AND org_id = $16`,
			existing, assetID, target.ClusterID, finding.ID, title, description, severity,
			handler.SeverityToScore(severity, 0, false), string(enginesJSON), string(detailJSON),
			target.ID, target.Type, target.Ref, target.ClusterID, target.SourceType, orgID)
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO findings (org_id, cluster_id, asset_id, kind, external_id, title, description,
                      severity, risk_score, lifecycle, engines, detail_json,
                      scan_target_id, target_type, target_ref, target_cluster_id, source_type,
                      first_seen_at, last_seen_at)
VALUES ($1, $2, $3, 'cloud-config', NULLIF($4,''), $5, $6,
        $7, $8, 'open', $9::jsonb, $10::jsonb,
        $11, NULLIF($12,''), NULLIF($13,''), $14, NULLIF($15,''),
        NOW(), NOW())`,
		orgID, target.ClusterID, assetID, finding.ID, title, description, severity,
		handler.SeverityToScore(severity, 0, false), string(enginesJSON), string(detailJSON),
		target.ID, target.Type, target.Ref, target.ClusterID, target.SourceType)
	return err
}

func resolveStaleServerlessPermissionFindings(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, targetID uuid.UUID, currentKeys []string) error {
	sort.Strings(currentKeys)
	_, err := tx.Exec(ctx, `
UPDATE findings
   SET lifecycle = 'resolved',
       last_seen_at = NOW()
 WHERE org_id = $1
   AND scan_target_id = $2
   AND kind = 'cloud-config'
   AND detail_json->>'category' = 'serverless-permission'
   AND lifecycle <> 'resolved'
   AND NOT (detail_json->>'stable_key' = ANY($3::text[]))`, orgID, targetID, currentKeys)
	return err
}

func serverlessPermissionStableKey(body ServerlessPackagesPayload, analysis *serverlessPermissionAnalysis, finding serverlessPermissionFindingAnalysis) string {
	seed := map[string]any{
		"provider":     body.Provider,
		"function_ref": body.FunctionRef,
		"role_arn":     handler.FirstNonEmpty(analysis.RoleARN, body.Role),
		"role_name":    analysis.RoleName,
		"id":           finding.ID,
		"policy_type":  finding.PolicyType,
		"policy_name":  finding.PolicyName,
		"policy_arn":   finding.PolicyARN,
		"actions":      finding.Actions,
		"resources":    finding.Resources,
	}
	raw, _ := json.Marshal(seed)
	sum := sha256.Sum256(raw)
	return "serverless-permission:" + hex.EncodeToString(sum[:])
}

func normalizeServerlessPermissionSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "low"
	}
}
