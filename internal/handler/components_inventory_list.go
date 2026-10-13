package handler

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/google/uuid"
)

type componentListOptions struct {
	q, component, status, role, sort, order string
	limit, offset                           int
}

func componentListQuery(r *http.Request) (componentListOptions, error) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return componentListOptions{}, fmt.Errorf("invalid query string")
	}
	o := componentListOptions{q: strings.TrimSpace(values.Get("q")), component: strings.TrimSpace(values.Get("component")), status: strings.TrimSpace(values.Get("status")), role: strings.TrimSpace(values.Get("role")), sort: values.Get("sort"), order: strings.ToLower(values.Get("order")), limit: parseComponentInventoryLimit(r)}
	if o.status == "all" {
		o.status = ""
	}
	if o.role == "all" {
		o.role = ""
	}
	if o.sort == "" {
		o.sort = "component"
	}
	if o.order == "" {
		o.order = "asc"
	}
	if !componentListAllowed(o.status, "", "healthy", "degraded", "stale", "drift", "crashlooping", "missing", "not-observed") {
		return o, fmt.Errorf("unsupported status")
	}
	if !componentListAllowed(o.role, "", "controller", "enforcer", "scanner", "admission", "discoverer", "other") {
		return o, fmt.Errorf("unsupported role")
	}
	if !componentListAllowed(o.sort, "component", "build", "runtime", "status", "hostname", "restarts", "heartbeat") {
		return o, fmt.Errorf("unsupported sort")
	}
	if !componentListAllowed(o.order, "asc", "desc") {
		return o, fmt.Errorf("order must be asc or desc")
	}
	o.offset, _ = strconv.Atoi(values.Get("offset"))
	if o.offset < 0 {
		o.offset = 0
	}
	return o, nil
}
func componentListAllowed(value string, allowed ...string) bool {
	for _, a := range allowed {
		if value == a {
			return true
		}
	}
	return false
}

var componentAliasRules = []struct {
	expression *regexp.Regexp
	id, label  string
}{
	{regexp.MustCompile(`\b(scanner|scan-worker|vuln|cve)\b`), "scanner", "Scanner"},
	{regexp.MustCompile(`\b(admission|webhook)\b`), "admission", "Admission"},
	{regexp.MustCompile(`\b(enforcer|runtime-agent|agent|sensor|node-agent)\b`), "enforcer", "Enforcer"},
	{regexp.MustCompile(`\b(discoverer|discovery|importer|collector|inventory)\b`), "discoverer", "Import / Discovery"},
	{regexp.MustCompile(`\b(controller|control-plane|api)\b`), "controller", "Controller"},
}

func componentListAlias(item componentInstanceDTO) (string, string) {
	text := strings.ToLower(strings.Join([]string{item.Component, item.DisplayName, item.Role, item.Kind}, " "))
	for _, rule := range componentAliasRules {
		if rule.expression.MatchString(text) {
			return rule.id, rule.label
		}
	}
	return "other", "Other"
}
func componentListMatch(item componentInstanceDTO, o componentListOptions) bool {
	role, label := componentListAlias(item)
	if o.component != "" && item.Component != o.component || o.status != "" && item.Status != o.status || o.role != "" && role != o.role {
		return false
	}
	if o.q == "" {
		return true
	}
	needle := strings.ToLower(o.q)
	for _, value := range []string{item.Component, item.DisplayName, item.Role, label, item.Scope, item.Kind, item.Hostname, item.Version, item.Commit, item.ClusterName, item.StatusReason} {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}
func componentListSort(items []componentInstanceDTO, o componentListOptions) {
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		order := 0
		switch o.sort {
		case "component":
			order = componentCompareStrings(a.Component, b.Component)
			if order == 0 {
				order = componentCompareStrings(a.ClusterName, b.ClusterName)
			}
			if order == 0 {
				order = componentCompareStrings(a.Hostname, b.Hostname)
			}
		case "build":
			order = componentCompareStrings(a.Version, b.Version)
			if order == 0 {
				order = componentCompareStrings(a.Commit, b.Commit)
			}
		case "runtime":
			order = componentCompareInt(a.UptimeSeconds, b.UptimeSeconds)
		case "status":
			order = componentCompareInt(int64(componentListStatusRank(a.Status)), int64(componentListStatusRank(b.Status)))
		case "hostname":
			order = componentCompareStrings(a.Hostname, b.Hostname)
		case "restarts":
			order = componentCompareInt(int64(a.RestartCount), int64(b.RestartCount))
		case "heartbeat":
			if a.LastSeenAt.Before(b.LastSeenAt) {
				order = -1
			} else if a.LastSeenAt.After(b.LastSeenAt) {
				order = 1
			}
		}
		if order == 0 {
			return a.ID.String() < b.ID.String()
		}
		if o.order == "desc" {
			return order > 0
		}
		return order < 0
	})
}
func componentCompareStrings(a, b string) int {
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}
func componentCompareInt(a, b int64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
func componentListStatusRank(status string) int {
	switch status {
	case "healthy":
		return 0
	case "not-observed":
		return 1
	case "degraded":
		return 2
	case "drift":
		return 3
	case "stale":
		return 4
	case "crashlooping":
		return 5
	case "missing":
		return 6
	}
	return 7
}

func (h *ComponentsInventory) ExportCSV(w http.ResponseWriter, r *http.Request) {
	h.writeInventoryList(w, r, true)
}
func (h *ComponentsInventory) writeInventoryList(w http.ResponseWriter, r *http.Request, export bool) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, 401, "subject required")
		return
	}
	o, err := componentListQuery(r)
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	cluster, ok := optionalUUIDQuery(w, r, "cluster_id")
	if !ok {
		return
	}
	hbs, names, err := h.loadInventoryHeartbeats(r.Context(), subj.OrgID)
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	if cluster != nil {
		if _, owned := names[*cluster]; !owned {
			jsonError(w, 404, "cluster not found")
			return
		}
	}
	scored, err := h.scoreInventoryHeartbeats(r.Context(), subj.OrgID, hbs, names)
	if err != nil {
		jsonError(w, 500, "restart evidence: "+err.Error())
		return
	}
	scoped := make([]componentInstanceDTO, 0, len(hbs))
	matching := make([]componentInstanceDTO, 0, len(hbs))
	counts := map[string]int{"all": 0, "controller": 0, "enforcer": 0, "scanner": 0, "admission": 0, "discoverer": 0, "other": 0}
	for i, hb := range hbs {
		if cluster != nil && (hb.ClusterID == nil || *hb.ClusterID != *cluster) {
			continue
		}
		item := componentInstanceFromHeartbeat(hb, scored[i])
		scoped = append(scoped, item)
		role, _ := componentListAlias(item)
		counts["all"]++
		counts[role]++
		if componentListMatch(item, o) {
			matching = append(matching, item)
		}
	}
	componentListSort(matching, o)
	total := len(matching)
	if export {
		var body bytes.Buffer
		writer := csv.NewWriter(&body)
		err = writer.Write([]string{"Instance ID", "Cluster ID", "Component", "Display name", "Role", "Console role", "Scope", "Kind", "Hostname", "Status", "Status reason", "Version", "Commit", "Uptime seconds", "Restart count", "First seen", "Last seen", "System config revision"})
		end := total
		if end > inventorylist.ExportLimit {
			end = inventorylist.ExportLimit
		}
		for _, item := range matching[:end] {
			if err != nil {
				break
			}
			clusterID := ""
			if item.ClusterID != nil {
				clusterID = item.ClusterID.String()
			}
			_, label := componentListAlias(item)
			err = writer.Write([]string{item.ID.String(), clusterID, item.Component, item.DisplayName, item.Role, label, item.Scope, item.Kind, item.Hostname, item.Status, item.StatusReason, item.Version, item.Commit, strconv.FormatInt(item.UptimeSeconds, 10), strconv.Itoa(item.RestartCount), item.FirstSeenAt.Format(time.RFC3339), item.LastSeenAt.Format(time.RFC3339), componentReportedConfigRevision(item.Metadata)})
		}
		writer.Flush()
		if err == nil {
			err = writer.Error()
		}
		if err != nil {
			jsonError(w, 500, "CSV: "+err.Error())
			return
		}
		inventorylist.WriteCSV(w, "constellation-components.csv", body.Bytes(), inventorylist.Metadata{Total: int64(total)})
		return
	}
	rollups := componentInventoryRollups(scoped, cluster != nil, "")
	componentListCapacity(rollups, scoped)
	start := o.offset
	if start > total {
		start = total
	}
	end := start + o.limit
	if end > total {
		end = total
	}
	writeJSON(w, 200, map[string]any{"summary": componentInventorySummary(rollups), "rollups": rollups, "components": matching[start:end], "cluster_id": cluster, "q": o.q, "component": o.component, "status": o.status, "role": o.role, "sort": o.sort, "order": o.order, "limit": o.limit, "offset": o.offset, "total": total, "has_more": o.offset+end-start < total, "role_counts": counts, "source_window_hours": 24})
}
func componentListCapacity(rollups []componentInventoryRollupDTO, instances []componentInstanceDTO) {
	for i := range rollups {
		var active, max, idle int64
		seen := false
		for _, item := range instances {
			if item.Component != rollups[i].Component {
				continue
			}
			for key, target := range map[string]*int64{"active_jobs": &active, "max_concurrent": &max, "idle_capacity": &idle} {
				if value, ok := componentCapacityNumber(item.Metadata[key]); ok {
					*target += value
					seen = true
				}
			}
		}
		if seen {
			rollups[i].ScannerCapacity = map[string]int64{"active_jobs": active, "max_concurrent": max, "idle_capacity": idle}
		}
	}
}
func componentCapacityNumber(value any) (int64, bool) {
	switch n := value.(type) {
	case float64:
		if n >= 0 && n < 1e12 && n == float64(int64(n)) {
			return int64(n), true
		}
	case int:
		if n >= 0 {
			return int64(n), true
		}
	case int64:
		if n >= 0 {
			return n, true
		}
	case string:
		parsed, err := strconv.ParseInt(n, 10, 64)
		if err == nil && parsed >= 0 && parsed < 1e12 {
			return parsed, true
		}
	}
	return 0, false
}

// Components preserve every heartbeat row, so their restart classification must
// also retain every matching event and isolate same-named sibling-cluster hosts.
// The system-health overview keeps its existing collapsed scoring contract.
func (h *ComponentsInventory) scoreInventoryHeartbeats(ctx context.Context, org uuid.UUID, hbs []HeartbeatRow, names map[uuid.UUID]string) ([]heartbeatDTO, error) {
	rows, err := h.db.Pool().Query(ctx, `SELECT cluster_id,component,hostname,count(*) FROM component_restart_events WHERE org_id=$1 AND detected_at>NOW()-INTERVAL '1 hour' AND (cluster_id IS NULL OR EXISTS(SELECT 1 FROM clusters WHERE id=cluster_id AND org_id=$1)) GROUP BY cluster_id,component,hostname`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var cluster *uuid.UUID
		var component, host string
		var count int
		if err := rows.Scan(&cluster, &component, &host, &count); err != nil {
			return nil, err
		}
		counts[component+"\x00"+clusterKey(cluster)+"\x00"+host] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	keyed := make([]HeartbeatRow, len(hbs))
	copy(keyed, hbs)
	for i := range keyed {
		keyed[i].Hostname = clusterKey(keyed[i].ClusterID) + "\x00" + keyed[i].Hostname
	}
	scored := scoreHeartbeatInstances(keyed, names, counts)
	for i := range scored {
		scored[i].Hostname = hbs[i].Hostname
	}
	return scored, nil
}

// Use one owned heartbeat population for list and exact-instance classification.
// The heartbeat query retains every reported instance from the trailing24h source.
func (h *ComponentsInventory) loadInventoryHeartbeats(ctx context.Context, org uuid.UUID) ([]HeartbeatRow, map[uuid.UUID]string, error) {
	names := map[uuid.UUID]string{}
	rows, err := h.db.Pool().Query(ctx, `SELECT id,name FROM clusters WHERE org_id=$1`, org)
	if err != nil {
		return nil, nil, fmt.Errorf("clusters: %w", err)
	}
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("clusters: %w", err)
		}
		names[id] = name
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("clusters: %w", err)
	}
	hbs, err := LoadHeartbeats(ctx, h.db.Pool(), org)
	if err != nil {
		return nil, nil, fmt.Errorf("heartbeats: %w", err)
	}
	owned := make([]HeartbeatRow, 0, len(hbs))
	for _, hb := range hbs {
		if hb.ClusterID != nil {
			if _, ok := names[*hb.ClusterID]; !ok {
				continue
			}
		}
		owned = append(owned, hb)
	}
	return owned, names, nil
}

// componentReportedConfigRevision mirrors the console's explicit revision key.
// Unrelated metadata, malformed values and unsafe integers are not evidence.
func componentReportedConfigRevision(metadata map[string]any) string {
	const maxSafe = 9007199254740991
	value := metadata["system_config_revision"]
	var number float64
	switch typed := value.(type) {
	case float64:
		number = typed
	case int:
		number = float64(typed)
	case int64:
		number = float64(typed)
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return ""
		}
		number = parsed
	case string:
		// ECMAScript String.trim whitespace, matching the console's metadata parser.
		text := strings.Trim(typed, "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff")
		if text == "" {
			return ""
		}
		for _, digit := range text {
			if digit < '0' || digit > '9' {
				return ""
			}
		}
		parsed, err := strconv.ParseUint(strings.TrimLeft(text, "0"), 10, 64)
		if strings.TrimLeft(text, "0") == "" {
			return "0"
		}
		if err != nil || parsed > maxSafe {
			return ""
		}
		return strconv.FormatUint(parsed, 10)
	default:
		return ""
	}
	if math.IsNaN(number) || math.IsInf(number, 0) || number < 0 || number > maxSafe || math.Trunc(number) != number {
		return ""
	}
	if number == 0 {
		return "0"
	}
	return strconv.FormatFloat(number, 'f', 0, 64)
}
