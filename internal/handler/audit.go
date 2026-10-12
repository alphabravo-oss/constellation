package handler

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	auditlog "github.com/alphabravocompany/constellation/pkg/audit"
)

type Audit struct {
	db *db.DB
}

func NewAudit(database *db.DB) *Audit { return &Audit{db: database} }

type auditDTO struct {
	EventID    string                    `json:"event_id"`
	ID         int64                     `json:"id"`
	OrgID      *uuid.UUID                `json:"org_id,omitempty"`
	ActorID    *uuid.UUID                `json:"actor_id,omitempty"`
	Action     string                    `json:"action"`
	TargetKind string                    `json:"target_kind,omitempty"`
	TargetID   string                    `json:"target_id,omitempty"`
	PrevHash   string                    `json:"prev_hash"`
	ChainHash  string                    `json:"chain_hash"`
	At         time.Time                 `json:"at"`
	Controls   []auditlog.ControlMapping `json:"controls,omitempty"`
}

func (a *Audit) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	cohort, cohortSet, err := auditEventCohort(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	action := r.URL.Query().Get("action")
	var eventID *int64
	if raw := r.URL.Query().Get("event_id"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			jsonError(w, http.StatusBadRequest, "invalid event_id")
			return
		}
		eventID = &parsed
	}
	var supportBundleJobID *uuid.UUID
	if raw := r.URL.Query().Get("support_bundle_job_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid support_bundle_job_id")
			return
		}
		supportBundleJobID = &parsed
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	// audit_events is 10s of millions of rows, so an exact COUNT(*) per page would be a
	// slow full scan. Instead fetch one extra row to learn whether a next page exists —
	// cursor-style has_more paging, cheap at any table size.
	fetch := limit + 1
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if clusterArg != nil {
		var owned bool
		if err := a.db.Pool().QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM clusters WHERE id = $1 AND org_id = $2)`, clusterArg, subj.OrgID).Scan(&owned); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !owned {
			jsonError(w, http.StatusNotFound, "cluster not found")
			return
		}
	}
	// E2: ?framework=<id>&control=<id> filters by compliance mapping. We
	// translate (framework, control) → action-prefix list at request time
	// (the mapping table is small and static, so this is cheap) and pass
	// the result as a parallel array to the SQL. When both `action` and
	// (framework, control) are present, action wins — operators using the
	// drill-down link from a compliance report click through to "all the
	// action=X rows that demonstrate this control".
	fw := strings.TrimSpace(r.URL.Query().Get("framework"))
	ctrl := strings.TrimSpace(r.URL.Query().Get("control"))
	var controlPrefixes []string
	if fw != "" && ctrl != "" && action == "" {
		controlPrefixes = auditlog.ActionsFor(auditlog.Framework(fw), ctrl)
		if len(controlPrefixes) == 0 {
			// Unknown control or framework — return empty result rather
			// than the entire audit log. An auditor pasting a malformed
			// control ID should not exfiltrate everything.
			writeJSON(w, http.StatusOK, map[string]any{
				"events": []auditDTO{}, "limit": limit, "offset": offset,
				"control_mapping": map[string]string{
					"framework": fw, "control_id": ctrl,
					"note": "no audit actions mapped to this control",
				},
			})
			return
		}
	}
	query, args := auditListQuery(subj.OrgID, clusterArg, action, controlPrefixes, eventID, supportBundleJobID, fetch, offset)
	if cohortSet {
		query = `SELECT a.id, a.org_id, a.actor_id, a.action, COALESCE(a.target_kind,''), COALESCE(a.target_id,''), a.prev_hash, a.chain_hash, a.at FROM audit_events a WHERE a.org_id=$1 AND a.id=ANY($2::bigint[]) ORDER BY a.at DESC,a.id DESC LIMIT $3 OFFSET $4`
		args = []any{subj.OrgID, cohort, fetch, offset}
	}
	rows, err := a.db.Pool().Query(r.Context(), query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	// Opt-in: ?with_controls=1 decorates each row with its compliance
	// mappings. Defaults to off because the typical activity-feed UI
	// doesn't render them and the table costs ~200 bytes/row to ship.
	withControls := strings.EqualFold(r.URL.Query().Get("with_controls"), "1") ||
		strings.EqualFold(r.URL.Query().Get("with_controls"), "true")
	out, err := readAuditListRows(rows, limit, withControls)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Trim the probe row and report whether another page exists.
	hasMore := false
	if len(out) > limit {
		hasMore = true
		out = out[:limit]
	}
	resp := map[string]any{"events": out, "limit": limit, "offset": offset, "has_more": hasMore}
	if fw != "" && ctrl != "" {
		resp["control_mapping"] = map[string]any{
			"framework":      fw,
			"control_id":     ctrl,
			"matched_prefix": controlPrefixes,
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// auditListQuery preserves the target-based cluster scope without walking the
// entire append-only log looking for sparse matches. Each distinct target probes
// idx_audit_org_target_id, then the outer query merges those events by ID. The
// first offset+fetch events per target contain every possible global page row.
// No target-kind restrictions are added: historical scoping matches target IDs
// across all five target tables, inherited policies, and the cluster itself.
func auditListQuery(orgID uuid.UUID, clusterID any, action string, controlPrefixes []string, eventID *int64, supportBundleJobID *uuid.UUID, fetch, offset int) (string, []any) {
	args := []any{orgID, fetch, offset}
	bind := func(value any) string {
		args = append(args, value)
		return "$" + strconv.Itoa(len(args))
	}
	var clusterParam, targetFetchParam string
	if clusterID != nil {
		clusterParam = bind(clusterID)
		// Keep an accepted maximum offset from overflowing the per-target bound.
		targetFetch := int64(offset)
		if targetFetch > math.MaxInt64-int64(fetch) {
			targetFetch = math.MaxInt64
		} else {
			targetFetch += int64(fetch)
		}
		targetFetchParam = bind(targetFetch)
	}
	filters := []string{"a.org_id = $1"}
	if action != "" {
		filters = append(filters, "a.action = "+bind(action))
	}
	if controlPrefixes != nil {
		filters = append(filters, "EXISTS (SELECT 1 FROM unnest("+bind(controlPrefixes)+"::text[]) AS p WHERE a.action LIKE p || '%')")
	}
	if eventID != nil {
		filters = append(filters, "a.id = "+bind(*eventID))
	}
	if supportBundleJobID != nil {
		filters = append(filters, "a.target_kind = 'support_bundle_job' AND a.target_id = "+bind(supportBundleJobID.String())+"::text")
	}
	const columns = `a.id, a.org_id, a.actor_id, a.action,
       COALESCE(a.target_kind,'') AS target_kind, COALESCE(a.target_id,'') AS target_id,
       a.prev_hash, a.chain_hash, a.at`
	if clusterID == nil {
		return "SELECT " + columns + " FROM audit_events a WHERE " + strings.Join(filters, " AND ") + " ORDER BY a.id DESC LIMIT $2 OFFSET $3", args
	}
	// UNION deduplicates IDs, including findings retained in multiple partitions
	// and IDs shared by different target tables. A duplicate must not repeat an
	// audit event or change has_more/page boundaries.
	return `WITH cluster_targets AS MATERIALIZED (
 SELECT id::text AS target_id FROM findings WHERE org_id = $1 AND cluster_id = ` + clusterParam + `
 UNION SELECT id::text FROM assets WHERE org_id = $1 AND cluster_id = ` + clusterParam + `
 UNION SELECT id::text FROM deployments WHERE org_id = $1 AND cluster_id = ` + clusterParam + `
 UNION SELECT id::text FROM compliance_checks WHERE org_id = $1 AND cluster_id = ` + clusterParam + `
 UNION SELECT id::text FROM policies WHERE org_id = $1 AND (cluster_id IS NULL OR cluster_id = ` + clusterParam + `)
 UNION SELECT ` + clusterParam + `::text
)
SELECT page.* FROM cluster_targets t
CROSS JOIN LATERAL (
 SELECT ` + columns + ` FROM audit_events a
 WHERE a.target_id = t.target_id AND ` + strings.Join(filters, " AND ") + `
 ORDER BY a.id DESC LIMIT ` + targetFetchParam + `
) page
ORDER BY page.id DESC LIMIT $2 OFFSET $3`, args
}

type auditListRows interface {
	Next() bool
	Scan(...any) error
	Err() error
}

func readAuditListRows(rows auditListRows, limit int, withControls bool) ([]auditDTO, error) {
	out := make([]auditDTO, 0, limit)
	for rows.Next() {
		var d auditDTO
		if err := rows.Scan(&d.ID, &d.OrgID, &d.ActorID, &d.Action, &d.TargetKind, &d.TargetID,
			&d.PrevHash, &d.ChainHash, &d.At); err != nil {
			return nil, err
		}
		d.EventID = strconv.FormatInt(d.ID, 10)
		if withControls {
			d.Controls = auditlog.ControlIDsFor(d.Action)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ControlMappings exposes the static compliance mapping table. UIs use this
// to render a "which controls do we provide evidence for?" tree, and
// auditors use it as a starting point for ATO worksheets.
//
// GET /api/v1/compliance/control-mappings
//
//	?framework=<id>     (optional) — filter to one framework
func (a *Audit) ControlMappings(w http.ResponseWriter, r *http.Request) {
	fw := strings.TrimSpace(r.URL.Query().Get("framework"))
	all := auditlog.AllControls()
	if fw != "" {
		filtered := all[:0]
		for _, m := range all {
			if string(m.Framework) == fw {
				filtered = append(filtered, m)
			}
		}
		all = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"frameworks": auditlog.AllFrameworks(),
		"controls":   all,
		"note": "Mappings are evidence-of-control, not a compliance attestation. " +
			"See docs/compliance-mappings.md.",
	})
}

func (a *Audit) Verify(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit database unavailable"})
		return
	}
	var eventCount int
	var lastHash string
	if err := a.db.Pool().QueryRow(r.Context(), `
SELECT COUNT(*)::int, COALESCE((SELECT chain_hash FROM audit_events ORDER BY id DESC LIMIT 1), '')
  FROM audit_events`).Scan(&eventCount, &lastHash); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if chainBreak, err := auditlog.VerifyChain(r.Context(), a.db.Pool()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	} else if chainBreak != nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"status":    "broken",
			"events":    eventCount,
			"last_hash": lastHash,
			"break": map[string]any{
				"id": chainBreak.ID, "reason": chainBreak.Reason,
				"expected": chainBreak.Expected, "found": chainBreak.Found,
			},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "verified",
		"events":       eventCount,
		"last_hash":    lastHash,
		"genesis_hash": auditlog.GenesisHash,
		"verified_at":  time.Now().UTC().Format(time.RFC3339),
	})
}
