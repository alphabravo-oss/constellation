package network

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// networkRuleDTO mirrors NeuVector's RESTPolicyRule so the Network Rules page is a
// drop-in match for NV users: one ordered allow/deny rule per (from -> to) with its
// applications, ports, learned flag, match counter, and last-match time. Constellation
// derives "learned" rules from observed flow rollups exactly as NV learns them from
// observed conversations.
type networkRuleDTO struct {
	ID           uint32   `json:"id"`
	Comment      string   `json:"comment"`
	From         string   `json:"from"`
	To           string   `json:"to"`
	Ports        string   `json:"ports"`
	Action       string   `json:"action"`
	Applications []string `json:"applications"`
	Learned      bool     `json:"learned"`
	Disable      bool     `json:"disable"`
	CfgType      string   `json:"cfg_type"`
	Priority     uint32   `json:"priority"`
	MatchCounter int64    `json:"match_counter"`
	LastMatchTS  int64    `json:"last_match_timestamp"`
}

// NetworkRules returns the cluster's observed network policy as an ordered NV-style
// rule list (learned from flow rollups). GET /api/v1/clusters/{id}/network-rules
func (h *Network) NetworkRules(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "subject required"})
		return
	}
	clusterID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cluster id"})
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT src_workload, dst_workload, verdict,
       COALESCE(array_agg(DISTINCT COALESCE(NULLIF(l7_protocol,''), protocol))
                FILTER (WHERE COALESCE(NULLIF(l7_protocol,''), protocol) <> ''), '{}') AS apps,
       COALESCE(string_agg(DISTINCT dst_port::text, ',') FILTER (WHERE dst_port > 0), '') AS ports,
       COALESCE(SUM(sum_sessions), 0)::bigint AS matches,
       MAX(max_at) AS last_match
  FROM network_flow_rollups
 WHERE org_id = $1 AND cluster_id = $2
   AND COALESCE(src_workload,'') <> '' AND COALESCE(dst_workload,'') <> ''
 GROUP BY src_workload, dst_workload, verdict
 ORDER BY matches DESC NULLS LAST
 LIMIT 3000`, subj.OrgID, clusterID)
	if err != nil {
		// rollups may be absent in non-runtime envs; degrade to an empty rule set.
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"rules": []networkRuleDTO{}, "cluster_id": clusterID.String()})
		return
	}
	defer rows.Close()

	out := []networkRuleDTO{}
	var id uint32 = 1000
	for rows.Next() {
		var d networkRuleDTO
		var verdict, ports string
		var apps []string
		var matches int64
		var lastMatch *time.Time
		if err := rows.Scan(&d.From, &d.To, &verdict, &apps, &ports, &matches, &lastMatch); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		d.ID = id
		d.Priority = id
		id++
		d.Applications = apps
		if d.Applications == nil {
			d.Applications = []string{}
		}
		d.Ports = ports
		if ports == "" {
			d.Ports = "any"
		}
		// Observed flows are permitted traffic; a 'deny'/'drop' verdict is a violation.
		switch verdict {
		case "deny", "drop", "violate":
			d.Action = "deny"
		default:
			d.Action = "allow"
		}
		d.Learned = true
		d.CfgType = "learned"
		d.MatchCounter = matches
		if lastMatch != nil {
			d.LastMatchTS = lastMatch.Unix()
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	allow, deny := 0, 0
	for i := range out {
		if out[i].Action == "deny" {
			deny++
		} else {
			allow++
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"cluster_id": clusterID.String(),
		"rules":      out,
		"summary":    map[string]int{"total": len(out), "allow": allow, "deny": deny, "learned": len(out)},
	})
}
