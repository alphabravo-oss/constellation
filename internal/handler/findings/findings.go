package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"github.com/jackc/pgx/v5"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/platformrole"
	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/notify"
	"github.com/alphabravocompany/constellation/pkg/risk"
)

// Findings serves the /api/v1/findings tree.
type Findings struct {
	db         *db.DB
	auditLog   *audit.Logger
	dispatcher *notify.Dispatcher
}

// NewFindings constructs the Findings handler. dispatcher may be nil — when nil, the
// lifecycle endpoints still work but no outbound notification fires.
func NewFindings(database *db.DB, auditLog *audit.Logger, dispatcher *notify.Dispatcher) *Findings {
	return &Findings{db: database, auditLog: auditLog, dispatcher: dispatcher}
}

type findingDTO struct {
	RowID               string                         `json:"row_id"`
	Revision            string                         `json:"revision"`
	SourceClusterID     *uuid.UUID                     `json:"source_cluster_id"`
	TargetClusterID     *uuid.UUID                     `json:"target_cluster_id"`
	PlatformRole        string                         `json:"platform_role"`
	ID                  uuid.UUID                      `json:"id"`
	Kind                string                         `json:"kind"`
	ExternalID          *string                        `json:"external_id,omitempty"`
	Title               string                         `json:"title"`
	Severity            string                         `json:"severity"`
	RiskScore           int                            `json:"risk_score"`
	Lifecycle           string                         `json:"lifecycle"`
	AssetID             uuid.UUID                      `json:"asset_id"`
	ClusterID           *uuid.UUID                     `json:"cluster_id,omitempty"`
	AttackIDs           []string                       `json:"attack_techniques"`
	AcceptedUntil       *time.Time                     `json:"accepted_until,omitempty"`
	FirstSeen           time.Time                      `json:"first_seen_at"`
	LastSeen            time.Time                      `json:"last_seen_at"`
	RiskInputs          json.RawMessage                `json:"risk_inputs,omitempty"`
	CanonicalEngine     string                         `json:"canonical_engine,omitempty"`
	Engines             []scanner.EngineProvenance     `json:"engines,omitempty"`
	Reconciliation      []scanner.ReconciliationSignal `json:"reconciliation,omitempty"`
	ReconciliationCount int                            `json:"reconciliation_count,omitempty"`
	PackageName         string                         `json:"package_name,omitempty"`
	PackageVersion      string                         `json:"package_version,omitempty"`
	PackageEcosystem    string                         `json:"package_ecosystem,omitempty"`
	PackagePURL         string                         `json:"package_purl,omitempty"`
	FixedVersion        string                         `json:"fixed_version,omitempty"`
	AffectedRange       *scanner.AffectedRange         `json:"affected_range,omitempty"`
	VulnDBBundle        *scanner.BundleMetadata        `json:"vulndb_bundle,omitempty"`
	CVSS                float64                        `json:"cvss,omitempty"`
	CVSSBase            float64                        `json:"cvss_base,omitempty"`
	CVSSVector          string                         `json:"cvss_vector,omitempty"`
	KEV                 bool                           `json:"kev,omitempty"`
	EPSS                float64                        `json:"epss,omitempty"`
}

func (f *Findings) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		apiutil.WriteStatus(r.Context(), w, http.StatusUnauthorized, "no subject")
		return
	}
	values := r.URL.Query()
	limit, _ := strconv.Atoi(values.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset := findingOffset(values)
	where, args, err := findingFilter(subj.OrgID, values, true, true)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	order, err := findingOrder(values)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	args = append(args, limit, offset)
	rows, err := f.db.Pool().Query(r.Context(), `
SELECT id, kind, external_id, title, severity, risk_score, lifecycle, asset_id, cluster_id,
       attack_techniques, accepted_until, first_seen_at, last_seen_at, risk_inputs,
       COALESCE(canonical_engine, ''), engines, detail_json, `+platformrole.FindingPlatformRoleSQL("findings")+`, revision::text, target_cluster_id
  FROM findings WHERE `+where+` ORDER BY `+order+`
 LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	out := make([]findingDTO, 0, limit)
	for rows.Next() {
		var d findingDTO
		var inputs, enginesRaw, detailRaw []byte
		var techniques []string
		if err := rows.Scan(&d.ID, &d.Kind, &d.ExternalID, &d.Title, &d.Severity, &d.RiskScore,
			&d.Lifecycle, &d.AssetID, &d.ClusterID, &techniques, &d.AcceptedUntil, &d.FirstSeen, &d.LastSeen, &inputs,
			&d.CanonicalEngine, &enginesRaw, &detailRaw, &d.PlatformRole, &d.Revision, &d.TargetClusterID); err != nil {
			apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
			return
		}
		d.RowID = findingRowID(d.ID, d.FirstSeen)
		d.SourceClusterID = d.ClusterID
		d.AttackIDs = techniques
		if len(inputs) > 0 {
			d.RiskInputs = inputs
		}
		hydrateFindingProvenance(&d, enginesRaw, detailRaw)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "could not read findings")
		return
	}
	// Lifecycle tabs retain all statuses, but match the current kind, search,
	// cluster and fixability filters. The selected status gives the page total.
	countWhere, countArgs, _ := findingFilter(subj.OrgID, values, false, true)
	countRows, err := f.db.Pool().Query(r.Context(), `SELECT lifecycle, count(*) FROM findings WHERE `+countWhere+` GROUP BY lifecycle`, countArgs...)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
		return
	}
	defer countRows.Close()
	lifecycleCounts := map[string]int{"open": 0, "accepted": 0, "suppressed": 0, "triaged": 0, "resolved": 0, "in_progress": 0}
	for countRows.Next() {
		var lifecycle string
		var count int
		if err := countRows.Scan(&lifecycle, &count); err != nil {
			apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
			return
		}
		lifecycleCounts[lifecycle] = count
	}
	if err := countRows.Err(); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "could not count findings")
		return
	}
	total := 0
	for lifecycle, count := range lifecycleCounts {
		if values.Get("lifecycle") == "" || values.Get("lifecycle") == lifecycle {
			total += count
		}
	}
	var systemTotal *int
	if values.Get("workload_scope") != "" {
		// Count the same filtered system findings even when they are hidden. Do
		// not change the selected page's predicate or lifecycle totals.
		systemValues := r.URL.Query()
		systemValues.Set("workload_scope", "constellation")
		systemWhere, systemArgs, _ := findingFilter(subj.OrgID, systemValues, true, true)
		var count int
		if err := f.db.Pool().QueryRow(r.Context(), `SELECT count(*) FROM findings WHERE `+systemWhere, systemArgs...).Scan(&count); err != nil {
			apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "could not count system findings")
			return
		}
		systemTotal = &count
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"findings": out, "limit": limit, "offset": offset, "total": total, "has_more": offset+len(out) < total,
		"lifecycle_counts": lifecycleCounts,
		"system_total":     systemTotal,
	})
}

func (f *Findings) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		writeInstanceError(w, &instanceError{401, "subject_required", "subject required"})
		return
	}
	selector, err := parseInstanceSelector(r)
	if err != nil {
		writeInstanceError(w, err)
		return
	}
	tx, err := f.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		writeInstanceError(w, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(r.Context()))
	instance, err := resolveInstance(r.Context(), tx, subj.OrgID, selector, false)
	if err != nil {
		writeInstanceError(w, err)
		return
	}
	id := instance.ID
	var d findingDTO
	var inputs, factors, enginesRaw, detailRaw []byte
	var techniques []string
	err = tx.QueryRow(r.Context(), `
SELECT id, kind, external_id, title, severity, risk_score, lifecycle, asset_id, cluster_id,
       attack_techniques, accepted_until, first_seen_at, last_seen_at, risk_inputs,
       COALESCE(risk_factors,'[]'::jsonb), COALESCE(canonical_engine, ''), engines, detail_json, `+platformrole.FindingPlatformRoleSQL("findings")+`, revision::text, target_cluster_id
  FROM findings WHERE id = $1 AND org_id = $2 AND first_seen_at=$3`, id, subj.OrgID, instance.FirstSeen).
		Scan(&d.ID, &d.Kind, &d.ExternalID, &d.Title, &d.Severity, &d.RiskScore,
			&d.Lifecycle, &d.AssetID, &d.ClusterID, &techniques, &d.AcceptedUntil, &d.FirstSeen, &d.LastSeen, &inputs, &factors,
			&d.CanonicalEngine, &enginesRaw, &detailRaw, &d.PlatformRole, &d.Revision, &d.TargetClusterID)
	if errors.Is(err, pgx.ErrNoRows) {
		apiutil.WriteStatus(r.Context(), w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "finding evidence unavailable")
		return
	}
	d.RowID = findingRowID(d.ID, d.FirstSeen)
	d.SourceClusterID = d.ClusterID
	d.AttackIDs = techniques
	if len(inputs) > 0 {
		d.RiskInputs = inputs
	}
	hydrateFindingProvenance(&d, enginesRaw, detailRaw)

	// Risk decomposition: prefer the cached column; if absent, compute from inputs.
	decomp := loadOrComputeDecomposition(factors, inputs, d.RiskScore)
	out := map[string]any{
		"id":     d.ID,
		"row_id": d.RowID, "revision": d.Revision, "source_cluster_id": d.SourceClusterID, "target_cluster_id": d.TargetClusterID,
		"kind":              d.Kind,
		"external_id":       d.ExternalID,
		"title":             d.Title,
		"severity":          d.Severity,
		"risk_score":        d.RiskScore,
		"lifecycle":         d.Lifecycle,
		"asset_id":          d.AssetID,
		"cluster_id":        d.ClusterID,
		"platform_role":     d.PlatformRole,
		"attack_techniques": d.AttackIDs,
		"accepted_until":    d.AcceptedUntil,
		"first_seen_at":     d.FirstSeen,
		"last_seen_at":      d.LastSeen,
		"risk_inputs":       d.RiskInputs,
		"risk":              decomp,
	}
	if d.CanonicalEngine != "" {
		out["canonical_engine"] = d.CanonicalEngine
	}
	if len(d.Engines) > 0 {
		out["engines"] = d.Engines
	}
	if len(d.Reconciliation) > 0 {
		out["reconciliation"] = d.Reconciliation
		out["reconciliation_count"] = d.ReconciliationCount
	}
	if d.PackageName != "" {
		out["package_name"] = d.PackageName
	}
	if d.PackageVersion != "" {
		out["package_version"] = d.PackageVersion
	}
	if d.PackageEcosystem != "" {
		out["package_ecosystem"] = d.PackageEcosystem
	}
	if d.PackagePURL != "" {
		out["package_purl"] = d.PackagePURL
	}
	if d.FixedVersion != "" {
		out["fixed_version"] = d.FixedVersion
	}
	if d.AffectedRange != nil {
		out["affected_range"] = d.AffectedRange
	}
	if d.VulnDBBundle != nil {
		out["vulndb_bundle"] = d.VulnDBBundle
	}
	if d.CVSSBase > 0 {
		out["cvss"] = d.CVSSBase
		out["cvss_base"] = d.CVSSBase
	}
	if d.CVSSVector != "" {
		out["cvss_vector"] = d.CVSSVector
	}
	if d.KEV {
		out["kev"] = d.KEV
	}
	if d.EPSS > 0 {
		out["epss"] = d.EPSS
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type tolerantJSONFloat float64

func (n *tolerantJSONFloat) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" || s == "null" || s == `""` {
		return nil
	}
	if strings.HasPrefix(s, `"`) {
		var text string
		if err := json.Unmarshal(b, &text); err != nil {
			return nil
		}
		s = strings.TrimSpace(text)
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	*n = tolerantJSONFloat(v)
	return nil
}

type tolerantJSONBool bool

func (b *tolerantJSONBool) UnmarshalJSON(raw []byte) error {
	value := string(raw)
	if strings.HasPrefix(value, `"`) {
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
	}
	switch strings.ToLower(value) {
	case "true", "t", "1", "yes":
		*b = true
	default:
		*b = false
	}
	return nil
}

func hydrateFindingProvenance(d *findingDTO, enginesRaw, detailRaw []byte) {
	if len(enginesRaw) > 0 && string(enginesRaw) != "null" {
		_ = json.Unmarshal(enginesRaw, &d.Engines)
	}
	var detail struct {
		CanonicalEngine    string                         `json:"canonical_engine"`
		Reconciliation     []scanner.ReconciliationSignal `json:"reconciliation"`
		PackageName        string                         `json:"package_name"`
		PackageVersion     string                         `json:"package_version"`
		FixedVersionLegacy string                         `json:"fixed_version"`
		Package            scanner.Package                `json:"package"`
		FixedVersion       string                         `json:"fixed"`
		AffectedRange      *scanner.AffectedRange         `json:"affected_range"`
		VulnDBBundle       *scanner.BundleMetadata        `json:"vulndb_bundle"`
		CVSSBase           tolerantJSONFloat              `json:"cvss_base"`
		CVSSVector         string                         `json:"cvss_vector"`
		KEV                tolerantJSONBool               `json:"kev"`
		EPSS               float64                        `json:"epss"`
	}
	if len(detailRaw) > 0 && string(detailRaw) != "null" {
		_ = json.Unmarshal(detailRaw, &detail)
	}
	if d.CanonicalEngine == "" {
		d.CanonicalEngine = detail.CanonicalEngine
	}
	d.Reconciliation = detail.Reconciliation
	d.ReconciliationCount = len(detail.Reconciliation)
	d.PackageName = detail.Package.Name
	d.PackageVersion = detail.Package.Version
	d.PackageEcosystem = detail.Package.Ecosystem
	d.PackagePURL = detail.Package.Purl
	d.FixedVersion = detail.FixedVersion
	if d.PackageName == "" {
		d.PackageName = detail.PackageName
	}
	if d.PackageVersion == "" {
		d.PackageVersion = detail.PackageVersion
	}
	if d.FixedVersion == "" {
		d.FixedVersion = detail.FixedVersionLegacy
	}
	d.AffectedRange = detail.AffectedRange
	if d.AffectedRange != nil {
		if d.PackageName == "" {
			d.PackageName = d.AffectedRange.PackageName
		}
		if d.PackagePURL == "" {
			d.PackagePURL = d.AffectedRange.PackagePURL
		}
		if d.PackageEcosystem == "" {
			d.PackageEcosystem = d.AffectedRange.VersionScheme
		}
		if d.FixedVersion == "" {
			d.FixedVersion = d.AffectedRange.FixedVersion
		}
	}
	d.VulnDBBundle = detail.VulnDBBundle
	d.CVSSBase = float64(detail.CVSSBase)
	d.CVSS = d.CVSSBase
	d.CVSSVector = detail.CVSSVector
	d.KEV = bool(detail.KEV)
	d.EPSS = detail.EPSS
}

func loadOrComputeDecomposition(stored, inputsRaw []byte, score int) risk.Decomposition {
	if len(stored) > 0 && string(stored) != "[]" {
		var sf []risk.Subfactor
		if err := json.Unmarshal(stored, &sf); err == nil && len(sf) > 0 {
			return risk.Decomposition{Composite: score, Subfactors: sf}
		}
	}
	var ri struct {
		CVSSBase             float64 `json:"cvss_base"`
		KEVListed            bool    `json:"kev_listed"`
		EPSSProbability      float64 `json:"epss_probability"`
		ReachableStatic      bool    `json:"reachable_static"`
		ReachableRuntime     bool    `json:"reachable_runtime"`
		AssetCriticality     string  `json:"asset_criticality"`
		PolicyViolationCount int     `json:"policy_violation_count"`
		NetworkExposed       bool    `json:"network_exposed"`
		IngressFromInternet  bool    `json:"ingress_from_internet"`
	}
	if len(inputsRaw) > 0 {
		_ = json.Unmarshal(inputsRaw, &ri)
	}
	return risk.Decompose(risk.SubfactorInputs{
		Inputs: risk.Inputs{
			CVSSBase: ri.CVSSBase, KEVListed: ri.KEVListed, EPSSProbability: ri.EPSSProbability,
			ReachableStatic: ri.ReachableStatic, ReachableRuntime: ri.ReachableRuntime,
			AssetCriticality: ri.AssetCriticality,
		},
		PolicyViolationCount: ri.PolicyViolationCount,
		NetworkExposed:       ri.NetworkExposed,
		IngressFromInternet:  ri.IngressFromInternet,
	})
}

type triageBody struct {
	ReviewedRevision string `json:"reviewed_revision"`
	AssigneeID       string `json:"assignee_id"`
	Priority         string `json:"priority"`
}

func (f *Findings) Triage(w http.ResponseWriter, r *http.Request) {
	var body triageBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "bad request")
		return
	}
	tx, found, subj, err := f.beginMutation(r, body.ReviewedRevision)
	if err != nil {
		writeInstanceError(w, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(r.Context()))
	var assignee *uuid.UUID
	if body.AssigneeID != "" {
		u, err := uuid.Parse(body.AssigneeID)
		if err == nil {
			assignee = &u
		}
	}
	if _, err := tx.Exec(r.Context(),
		`UPDATE findings SET lifecycle = 'triaged', assignee_id = $2, priority = $3, last_seen_at = NOW()
         WHERE id = $1 AND org_id = $4 AND first_seen_at=$5`, found.ID, assignee, body.Priority, subj.OrgID, found.FirstSeen); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
		return
	}
	f.finishMutation(w, r, tx, found, subj, "finding.triage", body)
}

type suppressBody struct {
	ReviewedRevision string `json:"reviewed_revision"`
	Reason           string `json:"reason"`
}

func (f *Findings) Suppress(w http.ResponseWriter, r *http.Request) {
	var body suppressBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeInstanceError(w, &instanceError{400, "invalid_body", "invalid body"})
		return
	}
	tx, found, subj, err := f.beginMutation(r, body.ReviewedRevision)
	if err != nil {
		writeInstanceError(w, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(r.Context()))
	if _, err := tx.Exec(r.Context(),
		`UPDATE findings SET lifecycle = 'suppressed', last_seen_at = NOW()
         WHERE id = $1 AND org_id = $2 AND first_seen_at=$3`, found.ID, subj.OrgID, found.FirstSeen); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
		return
	}
	f.finishMutation(w, r, tx, found, subj, "finding.suppress", body)
}

type acceptBody struct {
	ReviewedRevision string    `json:"reviewed_revision"`
	Reason           string    `json:"reason"`
	ApproverID       string    `json:"approver_id"`
	AcceptedUntil    time.Time `json:"accepted_until"`
}

func (f *Findings) AcceptRisk(w http.ResponseWriter, r *http.Request) {
	var body acceptBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AcceptedUntil.IsZero() {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "accepted_until required")
		return
	}
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		writeInstanceError(w, &instanceError{401, "subject_required", "subject required"})
		return
	}

	// Mirror the image-acceptance guardrails (image_acceptances.go) and the declared
	// "max-30-day-expiration" blocking guardrail: an acceptance must expire in the future and
	// within 30 days. Previously any non-zero date was accepted, so a finding could be accepted
	// for ~75 years or with a date already in the past.
	now := time.Now().UTC()
	if body.AcceptedUntil.Before(now) {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "accepted_until must be in the future")
		return
	}
	if body.AcceptedUntil.After(now.Add(30 * 24 * time.Hour)) {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "accepted_until cannot exceed 30 days")
		return
	}

	// Persist approver_id + reason so the accept-risk decision is attributable
	// (separation-of-duties). The findings table has no dedicated columns, so the metadata is
	// merged into detail_json under "acceptance".
	body.Reason = strings.TrimSpace(body.Reason)
	if len(body.Reason) < 12 {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "reason must be at least 12 characters")
		return
	}
	var approver *uuid.UUID
	if body.ApproverID != "" {
		a, perr := uuid.Parse(body.ApproverID)
		if perr != nil {
			apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "approver_id must be a UUID")
			return
		}
		// Separation of duties: the requester (authenticated caller) may not be their own approver.
		if a == subj.UserID {
			apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "approver_id must differ from the requester")
			return
		}
		approver = &a
	}

	acceptanceMeta := map[string]any{
		"acceptance": map[string]any{
			"reason":         body.Reason,
			"requested_by":   subj.UserID.String(),
			"accepted_until": body.AcceptedUntil.UTC().Format(time.RFC3339),
			"accepted_at":    now.Format(time.RFC3339),
		},
	}
	if approver != nil {
		acceptanceMeta["acceptance"].(map[string]any)["approver_id"] = approver.String()
	}
	metaJSON, err := json.Marshal(acceptanceMeta)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
		return
	}

	tx, found, subj, err := f.beginMutation(r, body.ReviewedRevision)
	if err != nil {
		writeInstanceError(w, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(r.Context()))
	if _, err := tx.Exec(r.Context(),
		`UPDATE findings
		    SET lifecycle = 'accepted', accepted_until = $2,
		        detail_json = COALESCE(detail_json, '{}'::jsonb) || $4::jsonb,
		        last_seen_at = NOW()
         WHERE id = $1 AND org_id = $3 AND first_seen_at=$5`, found.ID, body.AcceptedUntil, subj.OrgID, metaJSON, found.FirstSeen); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
		return
	}
	f.finishMutation(w, r, tx, found, subj, "finding.accept_risk", body)
}

// BulkInsertNotifyEvent is a small hook the scanner-side bulk-insert path can call
// after persisting a batch of new findings — it emits a single `finding.bulk` event
// per insert batch instead of one per finding to avoid alert storms. Exposed as a
// method so the scan-job completion path can invoke it without re-discovering the
// dispatcher.
func (f *Findings) BulkInsertNotifyEvent(ctx context.Context, orgID uuid.UUID, count, criticals int) {
	if f.dispatcher == nil || count == 0 {
		return
	}
	sev := "medium"
	if criticals > 0 {
		sev = "critical"
	}
	_, _ = f.dispatcher.Dispatch(ctx, notify.Event{
		Kind: "finding.bulk", OrgID: orgID, Severity: sev,
		Title: fmt.Sprintf("%d new findings (%d critical)", count, criticals),
		Labels: map[string]string{
			"severity": sev,
			"count":    strconv.Itoa(count),
		},
		Payload: map[string]int{"count": count, "criticals": criticals},
		URL:     "/findings",
	})
}
