package network

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

type networkRuleInventoryRow struct {
	networkRuleDTO
	RowID            string `json:"row_id"`
	FromPlatformRole string `json:"from_platform_role"`
	ToPlatformRole   string `json:"to_platform_role"`
}

type networkRuleInventoryFilters struct {
	Q            string `json:"q"`
	From         string `json:"from"`
	To           string `json:"to"`
	Action       string `json:"action"`
	Status       string `json:"status"`
	CfgType      string `json:"cfg_type"`
	HidePlatform bool   `json:"hide_platform"`
}

// Additive read-only inventory leaves portable YAML and policy writes intact.
func (h *Network) NetworkRulesInventory(w http.ResponseWriter, r *http.Request) {
	h.networkRulesInventory(w, r, false)
}
func (h *Network) NetworkRulesInventoryCSV(w http.ResponseWriter, r *http.Request) {
	h.networkRulesInventory(w, r, true)
}

func networkRuleInventoryOptions(q url.Values) (inventorylist.Options, networkRuleInventoryFilters, error) {
	o := inventorylist.Options{Limit: 100, Sort: q.Get("sort"), Order: q.Get("order")}
	f := networkRuleInventoryFilters{Q: strings.TrimSpace(q.Get("q")), From: strings.TrimSpace(q.Get("from")), To: strings.TrimSpace(q.Get("to"))}
	for key, values := range q {
		if len(values) != 1 {
			return o, f, fmt.Errorf("duplicate %s", key)
		}
	}
	for _, key := range []string{"limit", "offset"} {
		if values, present := q[key]; present {
			n, err := strconv.ParseInt(values[0], 10, 64)
			if err != nil || n < 0 || key == "limit" && (n < 1 || n > 500) || key == "offset" && n > inventorylist.MaxOffset {
				return o, f, fmt.Errorf("invalid %s", key)
			}
			if key == "limit" {
				o.Limit = int(n)
			} else {
				o.Offset = int(n)
			}
		}
	}
	var err error
	if f.Action, err = inventorylist.Filter(q, "action", "allow", "deny"); err != nil {
		return o, f, err
	}
	if f.Status, err = inventorylist.Filter(q, "status", "enabled", "disabled"); err != nil {
		return o, f, err
	}
	if f.CfgType, err = inventorylist.Filter(q, "cfg_type", "learned", "learned_override", "user_created"); err != nil {
		return o, f, err
	}
	if raw := q.Get("hide_platform"); raw != "" {
		if raw != "true" && raw != "false" {
			return o, f, fmt.Errorf("invalid hide_platform")
		}
		f.HidePlatform = raw == "true"
	}
	sorts := map[string]string{"evaluation": "(CASE WHEN cfg_type='learned' THEN 1 ELSE 0 END,priority,-match_counter)", "priority": "priority", "from": "lower(from_ep)", "to": "lower(to_ep)", "action": "action", "matches": "match_counter", "last_match": "last_match_timestamp", "type": "cfg_type", "status": "disable", "apps": "array_to_string(applications,',')", "ports": "ports", "id": "display_id"}
	if o.Sort == "" {
		o.Sort = "evaluation"
	}
	expression, ok := sorts[o.Sort]
	if !ok {
		return o, f, fmt.Errorf("unsupported sort")
	}
	if o.Order == "" {
		o.Order = "asc"
	}
	if o.Order != "asc" && o.Order != "desc" {
		return o, f, fmt.Errorf("order must be asc or desc")
	}
	o.OrderSQL = expression + " " + strings.ToUpper(o.Order) + " NULLS LAST,id ASC"
	return o, f, nil
}

func networkRuleInventoryDefinition(org, cluster uuid.UUID, f networkRuleInventoryFilters) inventorylist.Definition {
	// One winning observed verdict group per pair preserves legacy behavior;
	// explicit tie-breakers remove prior dependence on arbitrary database order.
	sql := `WITH observed AS (
 SELECT src_workload AS from_ep,dst_workload AS to_ep,verdict,
 COALESCE(array_agg(DISTINCT COALESCE(NULLIF(l7_protocol,''),protocol) ORDER BY COALESCE(NULLIF(l7_protocol,''),protocol)) FILTER(WHERE COALESCE(NULLIF(l7_protocol,''),protocol)<>''),'{}') AS apps,
 COALESCE(string_agg(DISTINCT dst_port::text,',' ORDER BY dst_port::text) FILTER(WHERE dst_port>0),'any') AS ports,
 COALESCE(sum(sum_sessions),0)::bigint AS matches,max(max_at) AS last_match
 FROM network_flow_rollups WHERE org_id=$1 AND cluster_id=$2 AND COALESCE(src_workload,'')<>'' AND COALESCE(dst_workload,'')<>'' GROUP BY src_workload,dst_workload,verdict
 ), winners AS (SELECT DISTINCT ON(from_ep,to_ep) * FROM observed ORDER BY from_ep,to_ep,matches DESC,last_match DESC NULLS LAST,verdict ASC),
 authored AS (SELECT * FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2),
 merged AS (
 SELECT COALESCE(w.from_ep,a.from_ep) AS from_ep,COALESCE(w.to_ep,a.to_ep) AS to_ep,
 CASE WHEN w.from_ep IS NOT NULL THEN w.ports ELSE COALESCE(NULLIF(a.ports,''),'any') END AS ports,
 CASE WHEN w.from_ep IS NOT NULL THEN w.apps ELSE a.applications END AS applications,
 COALESCE(a.action,CASE WHEN w.verdict IN('deny','drop','violate') THEN 'deny' ELSE 'allow' END) AS action,
 COALESCE(a.disable,false) AS disable,COALESCE(a.comment,'') AS comment,
 COALESCE(a.priority::bigint,network_rule_display_id(w.from_ep,w.to_ep)) AS priority,
 w.from_ep IS NOT NULL AS learned,
 CASE WHEN w.from_ep IS NULL THEN 'user_created' WHEN a.from_ep IS NULL THEN 'learned' ELSE 'learned_override' END AS cfg_type,
 COALESCE(w.matches,0)::bigint AS match_counter,COALESCE(floor(extract(epoch FROM w.last_match))::bigint,0)::bigint AS last_match_timestamp
 FROM winners w FULL JOIN authored a USING(from_ep,to_ep)
 WHERE w.from_ep IS NOT NULL OR a.cfg_type='user_created'
 ) SELECT jsonb_build_array(m.from_ep,m.to_ep)::text,network_rule_display_id(m.from_ep,m.to_ep),m.*,
 ` + handler.EvidencePlatformRoleSQL("$1::uuid", "$2::uuid", "m.from_ep", "''") + `,` + handler.EvidencePlatformRoleSQL("$1::uuid", "$2::uuid", "m.to_ep", "''") + ` FROM merged m`
	d := inventorylist.Definition{SQL: sql, Columns: "id,display_id,from_ep,to_ep,ports,applications,action,disable,comment,priority,learned,cfg_type,match_counter,last_match_timestamp,from_platform_role,to_platform_role", Args: []any{org, cluster}, Summary: `jsonb_build_object('total',count(*),'allow',count(*) FILTER(WHERE action='allow'),'deny',count(*) FILTER(WHERE action='deny'),'learned',count(*) FILTER(WHERE learned),'disabled',count(*) FILTER(WHERE disable))`}
	predicates := []string{"true"}
	bind := func(value any) string { d.Args = append(d.Args, value); return fmt.Sprintf("$%d", len(d.Args)) }
	if f.Q != "" {
		pattern := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(f.Q) + "%"
		predicates = append(predicates, `concat_ws(' ',from_ep,to_ep,ports,array_to_string(applications,','),comment) ILIKE `+bind(pattern)+` ESCAPE '\'`)
	}
	if f.From != "" {
		predicates = append(predicates, "from_ep="+bind(f.From))
	}
	if f.To != "" {
		predicates = append(predicates, "to_ep="+bind(f.To))
	}
	if f.Action != "" {
		predicates = append(predicates, "action="+bind(f.Action))
	}
	if f.CfgType != "" {
		predicates = append(predicates, "cfg_type="+bind(f.CfgType))
	}
	if f.Status != "" {
		predicates = append(predicates, "disable="+bind(f.Status == "disabled"))
	}
	if f.HidePlatform {
		predicates = append(predicates, "from_platform_role='' AND to_platform_role=''")
	}
	d.Where = strings.Join(predicates, " AND ")
	return d
}
func scanNetworkRuleInventory(row inventorylist.Row) (networkRuleInventoryRow, error) {
	var r networkRuleInventoryRow
	err := row.Scan(&r.RowID, &r.ID, &r.From, &r.To, &r.Ports, &r.Applications, &r.Action, &r.Disable, &r.Comment, &r.Priority, &r.Learned, &r.CfgType, &r.MatchCounter, &r.LastMatchTS, &r.FromPlatformRole, &r.ToPlatformRole)
	if r.Applications == nil {
		r.Applications = []string{}
	}
	return r, err
}
func (h *Network) networkRulesInventory(w http.ResponseWriter, r *http.Request, export bool) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		apiutil.WriteStatus(r.Context(), w, 401, "subject required")
		return
	}
	cluster, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 400, "invalid cluster id")
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 400, "invalid query")
		return
	}
	o, f, err := networkRuleInventoryOptions(values)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 400, err.Error())
		return
	}
	var owned bool
	if err := h.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND org_id=$2)`, cluster, sub.OrgID).Scan(&owned); err != nil {
		apiutil.WriteStatus(r.Context(), w, 500, err.Error())
		return
	}
	if !owned {
		apiutil.WriteStatus(r.Context(), w, 404, "cluster not found")
		return
	}
	d := networkRuleInventoryDefinition(sub.OrgID, cluster, f)
	if export {
		headers := []string{"row_id", "id", "cluster_id", "from", "to", "ports", "applications", "action", "disable", "comment", "priority", "learned", "cfg_type", "match_counter", "last_match_timestamp", "from_platform_role", "to_platform_role"}
		cells := func(row networkRuleInventoryRow) []string {
			apps, _ := json.Marshal(row.Applications)
			return []string{row.RowID, strconv.FormatUint(uint64(row.ID), 10), cluster.String(), row.From, row.To, row.Ports, string(apps), row.Action, strconv.FormatBool(row.Disable), row.Comment, strconv.FormatInt(row.Priority, 10), strconv.FormatBool(row.Learned), row.CfgType, strconv.FormatInt(row.MatchCounter, 10), strconv.FormatInt(row.LastMatchTS, 10), row.FromPlatformRole, row.ToPlatformRole}
		}
		body, meta, err := inventorylist.CSV(r.Context(), h.db.Pool(), d, o, scanNetworkRuleInventory, headers, cells)
		if err != nil {
			apiutil.WriteStatus(r.Context(), w, 500, err.Error())
			return
		}
		inventorylist.WriteCSV(w, "network-rules.csv", body, meta)
		return
	}
	rows, meta, err := inventorylist.Read(r.Context(), h.db.Pool(), d, o, scanNetworkRuleInventory)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 500, err.Error())
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"cluster_id": cluster, "rules": rows, "total": meta.Total, "has_more": meta.HasMore, "summary": meta.Summary, "limit": o.Limit, "offset": o.Offset, "sort": o.Sort, "order": o.Order, "filters": f, "source": "retained_flow_rollups_and_authored_overrides", "summary_scope": "matching_rules", "source_complete": true})
}
