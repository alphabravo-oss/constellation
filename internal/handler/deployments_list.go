package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type deploymentListFilter struct {
	args                []any
	base, role, visible string
	limit, offset       int
}

func deploymentListFilters(r *http.Request, orgID uuid.UUID) (deploymentListFilter, error) {
	values := r.URL.Query()
	filter := deploymentListFilter{args: []any{orgID}, limit: 100}
	bind := func(value any) string {
		filter.args = append(filter.args, value)
		return "$" + strconv.Itoa(len(filter.args))
	}
	parts := []string{"d.org_id=$1"}
	cluster, err := parseClusterIDParam(r)
	if err != nil {
		return filter, err
	}
	if cluster != nil {
		parts = append(parts, "d.cluster_id="+bind(cluster))
	}
	if ns := values.Get("namespace"); ns != "" {
		parts = append(parts, "d.namespace="+bind(ns))
	}
	if allowed, ok := NamespaceFilterFrom(r.Context()); ok {
		parts = append(parts, "d.namespace=ANY("+bind(allowed)+"::text[])")
	}
	search := strings.TrimSpace(values.Get("q"))
	if search == "" {
		search = strings.TrimSpace(values.Get("name"))
	}
	if search != "" {
		arg := bind(search)
		parts = append(parts, "(strpos(lower(d.name),lower("+arg+"::text))>0 OR strpos(lower(d.namespace||'/'||d.name),lower("+arg+"::text))>0)")
	}
	filter.base = "WITH classified AS (SELECT d.*, " + platformRoleSQL("d.namespace", "d.labels") + " AS platform_role FROM deployments d WHERE " + strings.Join(parts, " AND ") + ") "
	filter.role = "true"
	switch role := values.Get("platform_role"); role {
	case "", "all":
	case "core":
		filter.role = "platform_role='core'"
	case "none":
		filter.role = "platform_role=''"
	default:
		return filter, fmt.Errorf("invalid platform_role")
	}
	hide := false
	if raw := values.Get("hide_platform"); raw != "" {
		hide, err = strconv.ParseBool(raw)
		if err != nil {
			return filter, fmt.Errorf("invalid hide_platform")
		}
	}
	filter.visible = filter.role
	if hide {
		filter.visible += " AND platform_role=''"
	}
	if limit, err := strconv.Atoi(values.Get("limit")); err == nil && limit > 0 && limit <= 500 {
		filter.limit = limit
	}
	if offset, err := strconv.Atoi(values.Get("offset")); err == nil && offset > 0 {
		filter.offset = offset
	}
	return filter, nil
}

const deploymentListColumns = `id,cluster_id,namespace,name,kind,COALESCE(labels,'{}'::jsonb),platform_role,risk_score,COALESCE(risk_factors,'{}'::jsonb),finding_count,critical_count,high_count,first_seen_at,last_seen_at`
const deploymentListOrder = `risk_score DESC,last_seen_at DESC,id ASC`

type deploymentListRow struct {
	ID            uuid.UUID       `json:"id"`
	ClusterID     *uuid.UUID      `json:"cluster_id,omitempty"`
	Namespace     string          `json:"namespace"`
	Name          string          `json:"name"`
	Kind          string          `json:"kind"`
	Labels        json.RawMessage `json:"labels"`
	PlatformRole  string          `json:"platform_role,omitempty"`
	RiskScore     int             `json:"risk_score"`
	RiskFactors   json.RawMessage `json:"risk_factors"`
	FindingCount  int             `json:"finding_count"`
	CriticalCount int             `json:"critical_count"`
	HighCount     int             `json:"high_count"`
	FirstSeen     string          `json:"first_seen_at"`
	LastSeen      string          `json:"last_seen_at"`
}

func scanDeploymentListRow(rows pgx.Rows) (deploymentListRow, error) {
	var row deploymentListRow
	var first, last time.Time
	err := rows.Scan(&row.ID, &row.ClusterID, &row.Namespace, &row.Name, &row.Kind, &row.Labels, &row.PlatformRole, &row.RiskScore, &row.RiskFactors, &row.FindingCount, &row.CriticalCount, &row.HighCount, &first, &last)
	row.FirstSeen = first.UTC().Format(time.RFC3339)
	row.LastSeen = last.UTC().Format(time.RFC3339)
	return row, err
}

type deploymentListSummary struct {
	Total         int64 `json:"total"`
	AtRisk        int64 `json:"at_risk"`
	FindingCount  int64 `json:"finding_count"`
	CriticalCount int64 `json:"critical_count"`
	HighCount     int64 `json:"high_count"`
}

// List filters source rows before LIMIT and returns matching totals and risk
// summaries from the same read snapshot as the page.
func (h *Deployments) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	filter, err := deploymentListFilters(r, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	tx, err := h.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var summary deploymentListSummary
	var platformCount int64
	counts := filter.base + "SELECT count(*) FILTER(WHERE " + filter.visible + "),count(*) FILTER(WHERE platform_role<>''),count(*) FILTER(WHERE " + filter.visible + " AND risk_score>=60),COALESCE(sum(finding_count) FILTER(WHERE " + filter.visible + "),0),COALESCE(sum(critical_count) FILTER(WHERE " + filter.visible + "),0),COALESCE(sum(high_count) FILTER(WHERE " + filter.visible + "),0) FROM classified WHERE " + filter.role
	if err := tx.QueryRow(r.Context(), counts, filter.args...).Scan(&summary.Total, &platformCount, &summary.AtRisk, &summary.FindingCount, &summary.CriticalCount, &summary.HighCount); err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	args := append(append([]any{}, filter.args...), filter.limit, filter.offset)
	query := filter.base + "SELECT " + deploymentListColumns + " FROM classified WHERE " + filter.visible + " ORDER BY " + deploymentListOrder + " LIMIT $" + strconv.Itoa(len(args)-1) + " OFFSET $" + strconv.Itoa(len(args))
	rows, err := tx.Query(r.Context(), query, args...)
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := make([]deploymentListRow, 0, filter.limit)
	for rows.Next() {
		row, err := scanDeploymentListRow(rows)
		if err != nil {
			jsonError(w, 500, err.Error())
			return
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	rows.Close()
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deployments": out, "limit": filter.limit, "offset": filter.offset, "total": summary.Total, "has_more": int64(filter.offset)+int64(len(out)) < summary.Total, "platform_count": platformCount, "summary": summary})
}

// ExportCSV streams the full matching inventory. Visibility affects only this
// read, never telemetry collection, detection, policy or enforcement.
func (h *Deployments) ExportCSV(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, 401, "no subject")
		return
	}
	filter, err := deploymentListFilters(r, subj.OrgID)
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), filter.base+"SELECT "+deploymentListColumns+" FROM classified WHERE "+filter.visible+" ORDER BY "+deploymentListOrder, filter.args...)
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="constellation-workloads.csv"`)
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"Namespace", "Platform Role", "Name", "Kind", "Risk", "Findings", "Critical", "High", "Privileged", "RunAsRoot", "HostNetwork", "LastSeen"}); err != nil {
		panic(http.ErrAbortHandler)
	}
	for rows.Next() {
		row, err := scanDeploymentListRow(rows)
		if err != nil {
			panic(http.ErrAbortHandler)
		}
		if err := writer.Write([]string{row.Namespace, row.PlatformRole, row.Name, row.Kind, strconv.Itoa(row.RiskScore), strconv.Itoa(row.FindingCount), strconv.Itoa(row.CriticalCount), strconv.Itoa(row.HighCount), deploymentRiskFlag(row.RiskFactors, "privileged"), deploymentRiskFlag(row.RiskFactors, "run_as_root"), deploymentRiskFlag(row.RiskFactors, "host_network"), row.LastSeen}); err != nil {
			panic(http.ErrAbortHandler)
		}
	}
	if err := rows.Err(); err != nil {
		panic(http.ErrAbortHandler)
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		panic(http.ErrAbortHandler)
	}
}
func deploymentRiskFlag(raw json.RawMessage, key string) string {
	var factors map[string]any
	if json.Unmarshal(raw, &factors) != nil {
		return ""
	}
	var value float64
	switch typed := factors[key].(type) {
	case float64:
		value = typed
	case string:
		value, _ = strconv.ParseFloat(typed, 64)
	case bool:
		if typed {
			value = 1
		}
	}
	if value > 0 {
		return "yes"
	}
	return ""
}
