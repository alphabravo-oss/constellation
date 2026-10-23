package complianceevidence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alphabravocompany/constellation/pkg/compliance"
)

const ExportLimit = 100000

func normalizeInventoryQuery(q Query) (Query, string, error) {
	q.Scope = strings.ToLower(strings.TrimSpace(q.Scope))
	if q.Scope == "all" {
		q.Scope = ""
	}
	switch q.Scope {
	case "", ScopeNode, ScopeKubernetes, ScopeWorkload, ScopeCloud:
	default:
		return q, "", fmt.Errorf("unsupported compliance evidence scope %q", q.Scope)
	}
	q.Framework = strings.TrimSpace(q.Framework)
	if q.Framework == "all" {
		q.Framework = ""
	}
	q.Namespace = strings.TrimSpace(q.Namespace)
	q.ControlID = strings.TrimSpace(q.ControlID)
	q.Search = strings.TrimSpace(q.Search)
	q.Target = strings.TrimSpace(q.Target)
	if q.Status == "all" {
		q.Status = ""
	}
	switch q.Status {
	case "", "pass", "fail", "manual", "not_applicable", "exempted":
	default:
		return q, "", fmt.Errorf("unsupported evidence status")
	}
	if q.Limit <= 0 {
		q.Limit = 1000
	}
	if q.Limit > ExportLimit {
		return q, "", fmt.Errorf("invalid evidence limit")
	}
	if q.Offset < 0 || q.Offset > 1000000 {
		return q, "", fmt.Errorf("invalid evidence offset")
	}
	if q.Sort == "" {
		q.Sort = "observed"
	}
	if q.Order == "" {
		q.Order = "desc"
	}
	if q.Order != "asc" && q.Order != "desc" {
		return q, "", fmt.Errorf("invalid evidence order")
	}
	sorts := map[string]string{"observed": "observed_at", "scope": "scope", "target": "lower(target)", "framework": "ROW(lower(framework),lower(control_id))", "control": "ROW(lower(control_id),lower(framework))", "status": "effective_status", "severity": "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"}
	expression, ok := sorts[q.Sort]
	if !ok {
		return q, "", fmt.Errorf("unsupported evidence sort")
	}
	return q, expression + " " + strings.ToUpper(q.Order) + " NULLS LAST, id ASC", nil
}

// ValidateQuery permits handlers to reject invalid input before querying sources.
func ValidateQuery(q Query) (Query, error) {
	normalized, _, err := normalizeInventoryQuery(q)
	return normalized, err
}

func inventoryMappingJSON() ([]byte, []byte, error) {
	type mapping struct {
		InternalID string            `json:"internal_id"`
		Framework  string            `json:"framework"`
		ControlID  string            `json:"control_id"`
		Title      string            `json:"title"`
		Severity   string            `json:"severity"`
		Tags       compliance.TagsV2 `json:"tags"`
	}
	mappings := []mapping{}
	seen := map[string]bool{}
	for _, m := range compliance.CoreMappings {
		if seen[m.InternalID] {
			continue
		}
		seen[m.InternalID] = true
		for framework, control := range m.Controls {
			mappings = append(mappings, mapping{m.InternalID, framework, control, m.Title, m.Severity, compliance.BuildTagsV2(m.InternalID)})
		}
	}
	type hostRule struct {
		ControlID   string `json:"control_id"`
		InternalID  string `json:"internal_id"`
		Severity    string `json:"severity"`
		Remediation string `json:"remediation"`
	}
	rules := []hostRule{}
	for _, control := range []string{"1.1.1", "1.1.2", "3.2.1", "3.2.2", "3.3.1", "5.1.2", "5.1.3", "5.2.5", "5.2.10", "6.1.2"} {
		rules = append(rules, hostRule{control, internalIDForHostCIS(control), severityForHostCIS(control), remediationForHostCIS(control)})
	}
	encoded, err := json.Marshal(mappings)
	if err != nil {
		return nil, nil, err
	}
	hosts, err := json.Marshal(rules)
	return encoded, hosts, err
}

const evidenceSummaryJSON = `'pass',count(*) FILTER(WHERE effective_status='pass'),'fail',count(*) FILTER(WHERE effective_status='fail'),'exempted',count(*) FILTER(WHERE effective_status='exempted'),'not_applicable',count(*) FILTER(WHERE effective_status='not_applicable'),'manual',count(*) FILTER(WHERE effective_status NOT IN ('pass','fail','exempted','not_applicable')),'total',count(*)`

// readInventory returns a bounded page plus counts over every matching normalized
// evidence row, from one read-only snapshot. SQL performs mapping expansion and
// exemption overlay before filtering, counting, sorting and LIMIT/OFFSET.
func (c Collector) readInventory(ctx context.Context, q Query) (Result, error) {
	q, order, err := normalizeInventoryQuery(q)
	if err != nil {
		return Result{}, err
	}
	mappings, hosts, err := inventoryMappingJSON()
	if err != nil {
		return Result{}, err
	}
	args := []any{q.OrgID, uuidArg(q.ClusterID), q.Namespace, mappings, hosts, q.Targets, q.Scope, q.Framework, q.ControlID, q.Status, q.Search, q.Target}
	var encoded, items []byte
	summarySQL := `SELECT jsonb_build_object(` + evidenceSummaryJSON + `) || jsonb_build_object('by_scope',COALESCE((SELECT jsonb_object_agg(scope,counts) FROM (SELECT scope,jsonb_build_object(` + evidenceSummaryJSON + `) AS counts FROM matching GROUP BY scope) grouped),'{}'::jsonb)) AS data FROM matching`
	// Reuse one normalized evidence snapshot for the summary and selected page.
	// Only the bounded page is encoded as response JSON.
	query := evidenceInventorySQL + `, summary AS (` + summarySQL + `), page AS (
 SELECT ` + evidenceItemJSON + ` AS item,row_number() OVER(ORDER BY ` + order + `) AS ordinal FROM matching ORDER BY ` + order + ` LIMIT $13 OFFSET $14
 ) SELECT summary.data,COALESCE((SELECT jsonb_agg(item ORDER BY ordinal) FROM page),'[]'::jsonb) FROM summary`
	if err := c.Pool.QueryRow(ctx, query, append(args, q.Limit, q.Offset)...).Scan(&encoded, &items); err != nil {
		return Result{}, fmt.Errorf("read compliance evidence: %w", err)
	}
	result := Result{Items: []Item{}, Limit: q.Limit, Offset: q.Offset, Sort: q.Sort, Order: q.Order, ClusterID: q.ClusterID, Scope: q.Scope, Framework: q.Framework, Namespace: q.Namespace, ControlID: q.ControlID, Status: q.Status, Search: q.Search, Target: q.Target}
	if err := json.Unmarshal(encoded, &result.Summary); err != nil {
		return Result{}, err
	}
	if err := json.Unmarshal(items, &result.Items); err != nil {
		return Result{}, err
	}
	result.Total = result.Summary.Total
	result.HasMore = result.Total > q.Offset+len(result.Items)
	return result, nil
}
