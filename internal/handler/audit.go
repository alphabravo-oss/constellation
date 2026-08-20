package handler

import (
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
	subj, _ := SubjectFrom(r.Context())
	action := r.URL.Query().Get("action")
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
	// audit_events is hash-chained and intentionally has no cluster_id column
	// (writes would have to update the chain). Cluster-mode scoping instead
	// pivots on target_id: an audit row scopes to a cluster iff its target_id
	// matches a row in one of the cluster-bearing tables for that cluster.
	// This is a best-effort filter — events with no DB target (login, logout,
	// generic actions) are excluded from cluster mode, which is the intended
	// behavior: they belong to the org-level activity feed, not a cluster's.
	// The action filter combines an exact-match clause (?action=foo) with
	// a prefix-list clause (?framework=X&control=Y). At most one is set;
	// when neither is, both clauses degrade to TRUE.
	rows, err := a.db.Pool().Query(r.Context(), `
SELECT id, org_id, actor_id, action, COALESCE(target_kind,''), COALESCE(target_id,''),
       prev_hash, chain_hash, at
  FROM audit_events
 WHERE org_id = $1
   AND ($2::text = '' OR action = $2)
   AND ($6::text[] IS NULL OR EXISTS (
        SELECT 1 FROM unnest($6::text[]) AS p WHERE action LIKE p || '%'
       ))
   AND ($3::uuid IS NULL OR target_id IN (
        SELECT id::text FROM findings           WHERE org_id = $1 AND cluster_id = $3
        UNION ALL
        SELECT id::text FROM assets             WHERE org_id = $1 AND cluster_id = $3
        UNION ALL
        SELECT id::text FROM deployments        WHERE org_id = $1 AND cluster_id = $3
        UNION ALL
        SELECT id::text FROM compliance_checks  WHERE org_id = $1 AND cluster_id = $3
        UNION ALL
        SELECT id::text FROM policies           WHERE org_id = $1 AND (cluster_id IS NULL OR cluster_id = $3)
        UNION ALL
        SELECT $3::text
       ))
 ORDER BY id DESC
 LIMIT $4 OFFSET $5`, subj.OrgID, action, clusterArg, fetch, offset, controlPrefixes)
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
	out := make([]auditDTO, 0, limit)
	for rows.Next() {
		var d auditDTO
		if err := rows.Scan(&d.ID, &d.OrgID, &d.ActorID, &d.Action, &d.TargetKind, &d.TargetID,
			&d.PrevHash, &d.ChainHash, &d.At); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if withControls {
			d.Controls = auditlog.ControlIDsFor(d.Action)
		}
		out = append(out, d)
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
