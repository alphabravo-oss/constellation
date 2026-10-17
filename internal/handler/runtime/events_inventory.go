package runtime

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

// EventDTO keeps the physical (id,at) identity alongside the producer UUID.
type EventDTO struct {
	RowID            string          `json:"row_id"`
	ClusterID        uuid.UUID       `json:"cluster_id"`
	PlatformRole     string          `json:"platform_role"`
	ID               uuid.UUID       `json:"id"`
	At               time.Time       `json:"at"`
	Kind             string          `json:"kind"`
	Source           string          `json:"source"`
	Severity         string          `json:"severity"`
	Verdict          string          `json:"verdict"`
	NodeID           string          `json:"node_id"`
	WorkloadID       string          `json:"workload_id"`
	Namespace        string          `json:"namespace,omitempty"`
	ContainerID      string          `json:"container_id,omitempty"`
	AttackTechniques []string        `json:"attack_techniques"`
	Payload          json.RawMessage `json:"payload"`
}

type eventInventoryQuery struct {
	ClusterID *uuid.UUID `json:"cluster_id,omitempty"`
	Search    string     `json:"q"`
	Workload  string     `json:"workload"`
	Kind      string     `json:"kind"`
	Source    string     `json:"source"`
	Severity  string     `json:"severity"`
	Verdict   string     `json:"verdict"`
	Namespace string     `json:"namespace"`
	Node      string     `json:"node"`
	After     string     `json:"after"`
	Before    string     `json:"before"`
	Limit     int        `json:"limit"`
	Offset    int        `json:"offset"`
	Sort      string     `json:"sort"`
	Order     string     `json:"order"`
}
type eventInventorySummary struct {
	Total             int `json:"total"`
	Alerting          int `json:"alerting"`
	Blocks            int `json:"blocks"`
	Quarantines       int `json:"quarantines"`
	AffectedWorkloads int `json:"affected_workloads"`
	Observed          int `json:"observed"`
}
type eventInventoryResponse struct {
	eventInventoryQuery
	Events  []EventDTO            `json:"events"`
	Total   int                   `json:"total"`
	HasMore bool                  `json:"has_more"`
	Summary eventInventorySummary `json:"summary"`
}

const eventSeveritySQL = `(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)`

var eventInventorySorts = map[string]string{"at": "at", "workload": "lower(workload_id)", "kind": "lower(kind)", "source": "lower(source)", "severity": eventSeveritySQL, "verdict": "lower(verdict)", "namespace": "lower(COALESCE(namespace,''))", "node": "lower(node_id)"}

func parseEventInventory(values url.Values) (eventInventoryQuery, error) {
	q := eventInventoryQuery{Search: strings.TrimSpace(values.Get("q")), Workload: strings.TrimSpace(values.Get("workload")), Kind: strings.Join(splitCSV(values.Get("kind")), ","), Source: strings.Join(splitCSV(values.Get("source")), ","), Severity: strings.ToLower(strings.TrimSpace(values.Get("severity"))), Verdict: strings.Join(splitCSV(values.Get("verdict")), ","), Namespace: strings.TrimSpace(values.Get("namespace")), Node: strings.TrimSpace(values.Get("node")), Limit: 100, Sort: values.Get("sort"), Order: values.Get("order")}
	if raw := values.Get("cluster_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return q, fmt.Errorf("invalid cluster_id")
		}
		q.ClusterID = &id
	}
	for _, field := range []struct {
		name     string
		value    *int
		min, max int
	}{{"limit", &q.Limit, 1, 1000}, {"offset", &q.Offset, 0, inventorylist.MaxOffset}} {
		if values.Has(field.name) {
			n, err := strconv.Atoi(values.Get(field.name))
			if err != nil || n < field.min || n > field.max {
				return q, fmt.Errorf("invalid %s", field.name)
			}
			*field.value = n
		}
	}
	if q.Sort == "" {
		q.Sort = "at"
	}
	if _, ok := eventInventorySorts[q.Sort]; !ok {
		return q, fmt.Errorf("unsupported sort")
	}
	if q.Order == "" {
		q.Order = "desc"
	}
	if q.Order != "asc" && q.Order != "desc" {
		return q, fmt.Errorf("invalid order")
	}
	switch q.Severity {
	case "", "info", "low", "medium", "high", "critical":
	default:
		return q, fmt.Errorf("invalid severity")
	}
	for _, verdict := range splitCSV(q.Verdict) {
		switch verdict {
		case "observed", "alert", "block", "quarantine":
		default:
			return q, fmt.Errorf("invalid verdict")
		}
	}
	var after, before time.Time
	for _, field := range []struct {
		name   string
		value  *string
		parsed *time.Time
	}{{"after", &q.After, &after}, {"before", &q.Before, &before}} {
		if values.Has(field.name) {
			value, err := time.Parse(time.RFC3339Nano, values.Get(field.name))
			if err != nil {
				return q, fmt.Errorf("invalid %s", field.name)
			}
			*field.value = value.UTC().Format(time.RFC3339Nano)
			*field.parsed = value
		}
	}
	if !after.IsZero() && !before.IsZero() && !after.Before(before) {
		return q, fmt.Errorf("after must precede before")
	}
	return q, nil
}

func eventInventoryDefinition(orgID uuid.UUID, q eventInventoryQuery) (string, []any) {
	args := []any{orgID}
	where := []string{"e.org_id=$1", "EXISTS(SELECT 1 FROM clusters c WHERE c.id=e.cluster_id AND c.org_id=$1)"}
	add := func(value any, condition string) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(condition, len(args)))
	}
	if q.ClusterID != nil {
		add(*q.ClusterID, "e.cluster_id=$%d")
	}
	if q.Kind != "" {
		add(splitCSV(q.Kind), "e.kind=ANY($%d)")
	}
	if q.Source != "" {
		add(splitCSV(q.Source), "e.source=ANY($%d)")
	}
	if q.Verdict != "" {
		add(splitCSV(q.Verdict), "e.verdict=ANY($%d)")
	}
	if q.Severity != "" {
		add(severityTier(q.Severity), eventSeveritySQL+">=$%d")
	}
	if q.Workload != "" {
		add(q.Workload, "strpos(lower(e.workload_id),lower($%d))>0")
	}
	if q.Search != "" {
		add(q.Search, "strpos(lower(concat_ws(' ',e.workload_id,e.kind,e.source,e.severity,e.verdict,e.node_id,e.namespace,e.container_id,e.payload::text)),lower($%d))>0")
	}
	if q.Namespace != "" {
		add(q.Namespace, "e.namespace=$%d")
	}
	if q.Node != "" {
		add(q.Node, "e.node_id=$%d")
	}
	if q.After != "" {
		add(q.After, "e.at>=$%d::timestamptz")
	}
	if q.Before != "" {
		add(q.Before, "e.at<$%d::timestamptz")
	}
	return " FROM events e WHERE " + strings.Join(where, " AND "), args
}

func (h *EventsIngest) readEventInventory(ctx context.Context, orgID uuid.UUID, q eventInventoryQuery) (eventInventoryResponse, error) {
	result := eventInventoryResponse{eventInventoryQuery: q, Events: []EventDTO{}}
	tx, err := h.db.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	from, args := eventInventoryDefinition(orgID, q)
	count := `SELECT count(*),count(*) FILTER(WHERE verdict IN('alert','block','quarantine')),count(*) FILTER(WHERE verdict='block'),count(*) FILTER(WHERE verdict='quarantine'),count(DISTINCT (cluster_id,workload_id)) FILTER(WHERE btrim(workload_id)<>''),count(*) FILTER(WHERE verdict='observed')` + from
	s := &result.Summary
	if err := tx.QueryRow(ctx, count, args...).Scan(&s.Total, &s.Alerting, &s.Blocks, &s.Quarantines, &s.AffectedWorkloads, &s.Observed); err != nil {
		return result, err
	}
	order := eventInventorySorts[q.Sort] + " " + strings.ToUpper(q.Order) + " NULLS LAST, at DESC, id ASC"
	query := `SELECT id,cluster_id,at,kind,source,severity,verdict,node_id,workload_id,COALESCE(namespace,''),COALESCE(container_id,''),attack_techniques,payload` + from + fmt.Sprintf(" ORDER BY %s LIMIT $%d OFFSET $%d", order, len(args)+1, len(args)+2)
	rows, err := tx.Query(ctx, query, append(append([]any{}, args...), q.Limit, q.Offset)...)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var item EventDTO
		var payload []byte
		if err := rows.Scan(&item.ID, &item.ClusterID, &item.At, &item.Kind, &item.Source, &item.Severity, &item.Verdict, &item.NodeID, &item.WorkloadID, &item.Namespace, &item.ContainerID, &item.AttackTechniques, &payload); err != nil {
			rows.Close()
			return result, err
		}
		item.Payload = payload
		item.RowID = item.ID.String() + "@" + item.At.UTC().Format(time.RFC3339Nano)
		if item.AttackTechniques == nil {
			item.AttackTechniques = []string{}
		}
		result.Events = append(result.Events, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	// Bound role-resolution batches while keeping all enrichment in this snapshot.
	for start := 0; start < len(result.Events); start += 1000 {
		end := min(start+1000, len(result.Events))
		identities := make([]handler.PlatformWorkloadIdentity, end-start)
		for i, event := range result.Events[start:end] {
			identities[i] = handler.PlatformWorkloadIdentity{ClusterID: event.ClusterID, Workload: event.WorkloadID, Namespace: event.Namespace}
		}
		roles, err := handler.EvidencePlatformRoles(ctx, tx, orgID, identities)
		if err != nil {
			return result, err
		}
		for i, role := range roles {
			result.Events[start+i].PlatformRole = role
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return result, err
	}
	result.Total = s.Total
	result.HasMore = s.Total > q.Offset+len(result.Events)
	return result, nil
}

func (h *EventsIngest) List(w http.ResponseWriter, r *http.Request) {
	h.writeEventInventory(w, r, false)
}

// ListCSV exports the same matching history across pages, capped at 100,000 rows.
func (h *EventsIngest) ListCSV(w http.ResponseWriter, r *http.Request) {
	h.writeEventInventory(w, r, true)
}
func (h *EventsIngest) writeEventInventory(w http.ResponseWriter, r *http.Request, export bool) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok || subj.OrgID == uuid.Nil {
		jsonError(w, 401, "subject required")
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		jsonError(w, 400, "invalid query encoding")
		return
	}
	q, err := parseEventInventory(values)
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if q.ClusterID != nil {
		var owned bool
		if err := h.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND org_id=$2)`, q.ClusterID, subj.OrgID).Scan(&owned); err != nil {
			jsonError(w, 500, "event scope could not be verified")
			return
		}
		if !owned {
			jsonError(w, 404, "cluster not found")
			return
		}
	}
	if export {
		q.Limit = inventorylist.ExportLimit
		q.Offset = 0
	}
	result, err := h.readEventInventory(r.Context(), subj.OrgID, q)
	if err != nil {
		jsonError(w, 500, "runtime events could not be loaded")
		return
	}
	if !export {
		httpx.WriteJSON(w, 200, result)
		return
	}
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	_ = writer.Write([]string{"row_id", "id", "cluster_id", "platform_role", "at", "kind", "source", "severity", "verdict", "node_id", "workload_id", "namespace", "container_id", "attack_techniques", "payload"})
	for _, event := range result.Events {
		_ = writer.Write([]string{event.RowID, event.ID.String(), event.ClusterID.String(), event.PlatformRole, event.At.UTC().Format(time.RFC3339Nano), event.Kind, event.Source, event.Severity, event.Verdict, event.NodeID, event.WorkloadID, event.Namespace, event.ContainerID, strings.Join(event.AttackTechniques, ","), string(event.Payload)})
	}
	writer.Flush()
	if writer.Error() != nil {
		jsonError(w, 500, "runtime event export failed")
		return
	}
	inventorylist.WriteCSV(w, "constellation-runtime-events.csv", buffer.Bytes(), inventorylist.Metadata{Total: int64(result.Total)})
}
