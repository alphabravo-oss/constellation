package network

import (
	"encoding/json"
	"hash/fnv"
	"net/http"
	"sort"
	"strings"
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
// observed conversations, then layers user overrides (action/disable/priority/comment)
// and manual (user_created) rules on top.
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

// ruleID is a stable identifier for a (from -> to) pair so the same rule keeps its ID
// across reads and the client can key rows on it. Mutations address rules by from/to.
func ruleID(from, to string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(from))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(to))
	// Keep it in the display range above the learned base (1000+).
	return 1000 + h.Sum32()%1_000_000
}

type ruleOverride struct {
	ports    string
	apps     []string
	action   string
	disable  bool
	comment  string
	priority int
	cfgType  string
}

func (h *Network) loadOverrides(r *http.Request, orgID, clusterID uuid.UUID) (map[string]ruleOverride, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT from_ep, to_ep, ports, applications, action, disable, comment, priority, cfg_type
  FROM network_rule_overrides
 WHERE org_id = $1 AND cluster_id = $2`, orgID, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ruleOverride{}
	for rows.Next() {
		var from, to string
		var o ruleOverride
		if err := rows.Scan(&from, &to, &o.ports, &o.apps, &o.action, &o.disable, &o.comment, &o.priority, &o.cfgType); err != nil {
			return nil, err
		}
		if o.apps == nil {
			o.apps = []string{}
		}
		out[from+"\x00"+to] = o
	}
	return out, rows.Err()
}

// NetworkRules returns the cluster's network policy as an ordered NV-style rule list:
// learned rules (from flow rollups) merged with user overrides and manual rules.
// GET /api/v1/clusters/{id}/network-rules
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

	// Degrade to no overrides if the table hasn't been migrated yet — the learned
	// rule set still renders, so a lagging migration never blanks the page.
	overrides, err := h.loadOverrides(r, subj.OrgID, clusterID)
	if err != nil {
		overrides = map[string]ruleOverride{}
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
		// rollups may be absent in non-runtime envs; still surface manual rules below.
		rows = nil
	}

	out := []networkRuleDTO{}
	seen := map[string]bool{}
	if rows != nil {
		defer rows.Close()
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
			key := d.From + "\x00" + d.To
			if seen[key] {
				continue
			}
			seen[key] = true
			d.ID = ruleID(d.From, d.To)
			d.Priority = d.ID
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
			if o, has := overrides[key]; has {
				d.Action = o.action
				d.Disable = o.disable
				d.Comment = o.comment
				d.Priority = uint32(o.priority)
				d.CfgType = "learned_override"
			}
			out = append(out, d)
		}
		if err := rows.Err(); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}

	// Manual (user_created) rules for pairs the rollups never observed.
	for key, o := range overrides {
		if seen[key] || o.cfgType != "user_created" {
			continue
		}
		parts := strings.SplitN(key, "\x00", 2)
		d := networkRuleDTO{
			ID:           ruleID(parts[0], parts[1]),
			From:         parts[0],
			To:           parts[1],
			Ports:        o.ports,
			Applications: o.apps,
			Action:       o.action,
			Disable:      o.disable,
			Comment:      o.comment,
			Priority:     uint32(o.priority),
			CfgType:      "user_created",
		}
		if d.Ports == "" {
			d.Ports = "any"
		}
		out = append(out, d)
	}

	// Manual rules first (lowest priority number), then learned by match volume.
	sort.SliceStable(out, func(i, j int) bool {
		ci, cj := out[i].CfgType != "learned", out[j].CfgType != "learned"
		if ci != cj {
			return ci // configured rules sort ahead of purely-learned ones
		}
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].MatchCounter > out[j].MatchCounter
	})

	allow, deny, learned, disabled := 0, 0, 0, 0
	for i := range out {
		if out[i].Action == "deny" {
			deny++
		} else {
			allow++
		}
		if out[i].Learned {
			learned++
		}
		if out[i].Disable {
			disabled++
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"cluster_id": clusterID.String(),
		"rules":      out,
		"summary":    map[string]int{"total": len(out), "allow": allow, "deny": deny, "learned": learned, "disabled": disabled},
	})
}

type ruleMutation struct {
	From         string   `json:"from"`
	To           string   `json:"to"`
	Ports        string   `json:"ports"`
	Applications []string `json:"applications"`
	Action       string   `json:"action"`
	Disable      bool     `json:"disable"`
	Comment      string   `json:"comment"`
	Priority     int      `json:"priority"`
}

// UpsertNetworkRule creates a manual rule or overrides a learned one (action / disable /
// priority / comment). PUT|POST /api/v1/clusters/{id}/network-rules
func (h *Network) UpsertNetworkRule(w http.ResponseWriter, r *http.Request) {
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
	var body ruleMutation
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	body.From = strings.TrimSpace(body.From)
	body.To = strings.TrimSpace(body.To)
	if body.From == "" || body.To == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "from and to are required"})
		return
	}
	if body.Action != "deny" {
		body.Action = "allow"
	}
	if body.Ports == "" {
		body.Ports = "any"
	}
	if body.Applications == nil {
		body.Applications = []string{}
	}
	if body.Priority <= 0 {
		body.Priority = 1000
	}
	// Whether this pair exists in the learned set determines cfg_type.
	var learned bool
	_ = h.db.Pool().QueryRow(r.Context(), `
SELECT EXISTS (
  SELECT 1 FROM network_flow_rollups
   WHERE org_id = $1 AND cluster_id = $2 AND src_workload = $3 AND dst_workload = $4)`,
		subj.OrgID, clusterID, body.From, body.To).Scan(&learned)
	cfgType := "user_created"
	if learned {
		cfgType = "learned_override"
	}
	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO network_rule_overrides
  (org_id, cluster_id, from_ep, to_ep, ports, applications, action, disable, comment, priority, cfg_type, updated_by, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())
ON CONFLICT (org_id, cluster_id, from_ep, to_ep) DO UPDATE SET
  ports = EXCLUDED.ports, applications = EXCLUDED.applications, action = EXCLUDED.action,
  disable = EXCLUDED.disable, comment = EXCLUDED.comment, priority = EXCLUDED.priority,
  cfg_type = EXCLUDED.cfg_type, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		subj.OrgID, clusterID, body.From, body.To, body.Ports, body.Applications,
		body.Action, body.Disable, body.Comment, body.Priority, cfgType, subj.UserID); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "id": ruleID(body.From, body.To), "cfg_type": cfgType})
}

// MoveNetworkRuleToTop bumps a rule to the highest precedence (lowest priority number) so it
// evaluates first — NV's "Add to Top" / "Move to" primitive. Sets the pair's override priority
// to (current min override priority − 10), creating a learned_override row if the pair had none
// (a learned rule keeps its allow action; only precedence changes).
// POST /api/v1/clusters/{id}/network-rules:move-top {from,to}
func (h *Network) MoveNetworkRuleToTop(w http.ResponseWriter, r *http.Request) {
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
	var body struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	body.From, body.To = strings.TrimSpace(body.From), strings.TrimSpace(body.To)
	if body.From == "" || body.To == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "from and to are required"})
		return
	}
	// New top priority: below every existing override. Default 990 when none exist so a first
	// move still lands above the 1000-default upsert baseline.
	var newPri int
	_ = h.db.Pool().QueryRow(r.Context(),
		`SELECT COALESCE(MIN(priority), 1000) - 10 FROM network_rule_overrides WHERE org_id = $1 AND cluster_id = $2`,
		subj.OrgID, clusterID).Scan(&newPri)
	var learned bool
	_ = h.db.Pool().QueryRow(r.Context(), `
SELECT EXISTS (
  SELECT 1 FROM network_flow_rollups
   WHERE org_id = $1 AND cluster_id = $2 AND src_workload = $3 AND dst_workload = $4)`,
		subj.OrgID, clusterID, body.From, body.To).Scan(&learned)
	cfgType := "user_created"
	if learned {
		cfgType = "learned_override"
	}
	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO network_rule_overrides
  (org_id, cluster_id, from_ep, to_ep, priority, cfg_type, updated_by, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
ON CONFLICT (org_id, cluster_id, from_ep, to_ep) DO UPDATE SET
  priority = EXCLUDED.priority, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		subj.OrgID, clusterID, body.From, body.To, newPri, cfgType, subj.UserID); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "priority": newPri})
}

// DeleteNetworkRule drops the override for a pair. A manual rule vanishes; a learned rule
// reverts to its learned defaults. DELETE /api/v1/clusters/{id}/network-rules?from=&to=
func (h *Network) DeleteNetworkRule(w http.ResponseWriter, r *http.Request) {
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
	from := strings.TrimSpace(r.URL.Query().Get("from"))
	to := strings.TrimSpace(r.URL.Query().Get("to"))
	if from == "" || to == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "from and to are required"})
		return
	}
	if _, err := h.db.Pool().Exec(r.Context(), `
DELETE FROM network_rule_overrides
 WHERE org_id = $1 AND cluster_id = $2 AND from_ep = $3 AND to_ep = $4`,
		subj.OrgID, clusterID, from, to); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
