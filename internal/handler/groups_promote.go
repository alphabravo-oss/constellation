package handler

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/group"
)

// Mode promotion — advance policy maturity across groups (NeuVector's Discover→Monitor→Protect
// workflow). Operators learn in Discover, watch in Monitor, then Protect. This bulk-promotes
// every eligible group one step up a chosen dimension (network policy_mode or process/file
// profile_mode), matching NV's "switch mode" action. POST /api/v1/groups:promote

// nextMode returns the mode one step up the maturity ladder, or "" if already at the top.
func nextMode(m group.Mode) group.Mode {
	switch m {
	case group.ModeDiscover:
		return group.ModeMonitor
	case group.ModeMonitor:
		return group.ModeProtect
	default:
		return ""
	}
}

func (h *Groups) Promote(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var body struct {
		Dimension string `json:"dimension"` // policy | profile
		From      string `json:"from"`      // discover | monitor
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	from := group.Mode(body.From)
	to := nextMode(from)
	if to == "" || (from != group.ModeDiscover && from != group.ModeMonitor) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from must be discover or monitor"})
		return
	}
	if body.Dimension != "policy" && body.Dimension != "profile" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "dimension must be policy or profile"})
		return
	}

	// Only advance user-authored (ground/learned-promoted) groups; leave raw learned groups
	// in discover so re-learning isn't clobbered. cfg_type <> 'learned' is the guard.
	var promoted int
	if body.Dimension == "policy" {
		// Network mode: no member propagation (network rules are learned separately).
		tag, err := h.db.Pool().Exec(r.Context(), `
UPDATE groups
   SET policy_mode = $4, updated_at = NOW()
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)
   AND policy_mode = $3
   AND cfg_type <> 'learned'`, subj.OrgID, clusterArg, string(from), string(to))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		promoted = int(tag.RowsAffected())
	} else {
		// Profile mode: promote each affected group AND push the new baseline mode down to
		// its member workloads (matching the per-group Update propagation).
		rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, cluster_id, members
  FROM groups
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)
   AND profile_mode = $3
   AND cfg_type <> 'learned'`, subj.OrgID, clusterArg, string(from))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		type affected struct {
			id        uuid.UUID
			clusterID *uuid.UUID
			members   []string
		}
		var groups []affected
		for rows.Next() {
			var a affected
			var membersRaw []byte
			if err := rows.Scan(&a.id, &a.clusterID, &membersRaw); err != nil {
				rows.Close()
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			_ = json.Unmarshal(membersRaw, &a.members)
			groups = append(groups, a)
		}
		rows.Close()
		for _, a := range groups {
			if _, err := h.db.Pool().Exec(r.Context(),
				`UPDATE groups SET profile_mode = $2, updated_at = NOW() WHERE id = $1 AND org_id = $3`,
				a.id, string(to), subj.OrgID); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			if a.clusterID != nil {
				_ = h.propagateGroupProfileMode(r.Context(), subj.OrgID, *a.clusterID, a.members, to)
			}
			promoted++
		}
	}

	oid, uid := subj.OrgID, subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "group.promote", TargetKind: "group", TargetID: "",
		After: map[string]any{"dimension": body.Dimension, "from": string(from), "to": string(to), "promoted": promoted}})
	writeJSON(w, http.StatusOK, map[string]any{"dimension": body.Dimension, "from": string(from), "to": string(to), "promoted": promoted})
}
