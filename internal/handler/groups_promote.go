package handler

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/group"
)

// Mode promotion — adjust policy maturity across groups (NeuVector's Discover→Monitor→Protect
// workflow). Operators learn in Discover, watch in Monitor, then Protect; incident response
// also needs safe demotion back to Monitor/Discover. POST /api/v1/groups:promote keeps the
// original one-step promote body working while accepting an explicit "to" for bulk mode changes.

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
		To        string `json:"to"`        // optional; defaults to the next maturity mode
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	from := group.Mode(body.From)
	if !validGroupMode(from) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from must be discover, monitor, or protect"})
		return
	}
	to := group.Mode(body.To)
	if to == "" {
		to = nextMode(from)
		if to == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from must be discover or monitor when to is omitted"})
			return
		}
	}
	if !validGroupMode(to) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "to must be discover, monitor, or protect"})
		return
	}
	if from == to {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from and to must differ"})
		return
	}
	if body.Dimension != "policy" && body.Dimension != "profile" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "dimension must be policy or profile"})
		return
	}

	// Only adjust user-authored (ground/learned-promoted) groups; leave raw learned groups
	// under the learner's control so re-learning isn't clobbered. cfg_type <> 'learned' is the guard.
	var changed int
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
		changed = int(tag.RowsAffected())
	} else {
		// Profile mode: change each affected group AND push the new baseline mode down to
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
			a.members = normalizeGroupMembers(a.members)
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
			changed++
		}
	}

	oid, uid := subj.OrgID, subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "group.mode.bulk", TargetKind: "group", TargetID: "",
		After: map[string]any{"dimension": body.Dimension, "from": string(from), "to": string(to), "changed": changed}})
	writeJSON(w, http.StatusOK, map[string]any{"dimension": body.Dimension, "from": string(from), "to": string(to), "changed": changed, "promoted": changed})
}

func validGroupMode(m group.Mode) bool {
	return m == group.ModeDiscover || m == group.ModeMonitor || m == group.ModeProtect
}
