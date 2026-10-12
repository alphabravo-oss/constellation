package findings

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	searchdsl "github.com/alphabravocompany/constellation/pkg/search/dsl"
	"github.com/google/uuid"
)

// One predicate contract for instance pages, lifecycle totals, rollups and CSV.
// Values are always parameters; expressions and sort columns come from allowlists.
func findingFilter(orgID uuid.UUID, values url.Values, includeLifecycle, includeFixable bool) (string, []any, error) {
	args := []any{orgID}
	parts := []string{"org_id = $1", "(kind <> 'vulnerability' OR COALESCE(target_type, '') <> 'workload')"}
	add := func(column string, value any) {
		args = append(args, value)
		parts = append(parts, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	if scope := values.Get("id_scope"); scope != "" {
		if scope != "all" {
			return "", nil, fmt.Errorf("invalid id_scope")
		}
		// Dashboard distinct-ID counters ignore NULL IDs; preserve advisories.
		parts = append(parts, "external_id IS NOT NULL")
	}
	mode, err := sqlx.GroupModeRank(values.Get("group_mode"))
	if err != nil {
		return "", nil, err
	}
	if mode != 0 {
		args = append(args, mode)
		parts = append(parts, "kind='vulnerability' AND target_type='image-workload' AND EXISTS (SELECT 1 FROM image_workload_links mode_link JOIN ("+sqlx.GroupModesSQL("findings.org_id", "findings.cluster_id")+") mode_group ON mode_group.org_id=mode_link.org_id AND mode_group.cluster_id=mode_link.cluster_id AND mode_group.workload_id=mode_link.workload_id WHERE mode_link.org_id=findings.org_id AND mode_link.cluster_id=findings.cluster_id AND mode_link.image_digest=findings.target_ref AND mode_group.rank=$"+strconv.Itoa(len(args))+")")
	}
	if target := values.Get("target_type"); target != "" {
		switch target {
		case "image", "image-workload", "host", "platform", "workload", "registry", "repository", "serverless":
			add("target_type", target)
		default:
			return "", nil, fmt.Errorf("invalid target_type")
		}
	}
	if kind := values.Get("kind"); kind != "" {
		add("kind", kind)
	}
	if includeLifecycle {
		if lifecycle := values.Get("lifecycle"); lifecycle != "" {
			add("lifecycle", lifecycle)
		}
	}
	if raw := values.Get("cluster_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return "", nil, fmt.Errorf("invalid cluster_id")
		}
		add("cluster_id", id)
	}
	compiled, err := searchdsl.Compile(values.Get("q"), findingsSearchSchema)
	if err != nil {
		return "", nil, fmt.Errorf("search: %w", err)
	}
	if !compiled.Empty() {
		parts = append(parts, sqlx.ShiftPlaceholders(compiled.Where, len(args)))
		args = append(args, compiled.Args...)
	}
	if includeFixable && findingFixableRequested(values) {
		parts = append(parts, findingFixableSQL)
	}
	return strings.Join(parts, " AND "), args, nil
}
func findingFixableRequested(values url.Values) bool {
	return values.Get("fixable") == "1" || values.Get("fixable") == "true"
}
func findingOffset(values url.Values) int {
	offset, _ := strconv.Atoi(values.Get("offset"))
	if offset < 0 {
		return 0
	}
	return offset
}
func findingOrder(values url.Values) (string, error) {
	columns := map[string]string{
		"risk":        "risk_score",
		"severity":    "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END",
		"cve":         "COALESCE(external_id,'')",
		"title":       "title",
		"package":     findingPackageSQL,
		"fixed":       findingFixedSQL,
		"asset":       "asset_id",
		"lifecycle":   "lifecycle",
		"kind":        "kind",
		"last_seen":   "last_seen_at",
		"age":         "last_seen_at",
		"cvss_vector": "COALESCE(detail_json->>'cvss_vector','')",
		"cvss":        "CASE WHEN COALESCE(detail_json->>'cvss_base','') ~ '^[0-9]+([.][0-9]+)?$' THEN (detail_json->>'cvss_base')::float8 ELSE 0 END",
	}
	key := values.Get("sort")
	if key == "" {
		return "risk_score DESC, last_seen_at DESC, id ASC", nil
	}
	column, ok := columns[key]
	if !ok {
		return "", fmt.Errorf("invalid sort")
	}
	order := strings.ToUpper(values.Get("order"))
	if order == "" {
		order = "ASC"
	}
	if order != "ASC" && order != "DESC" {
		return "", fmt.Errorf("invalid order")
	}
	return column + " " + order + ", id ASC", nil
}
