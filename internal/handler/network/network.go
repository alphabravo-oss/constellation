// Network endpoints power the NeuVector-style Traffic Map.
package network

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/netutil"
)

type Network struct {
	db *db.DB
}

func NewNetwork(d *db.DB) *Network { return &Network{db: d} }

// Map returns workloads plus observed network edges aggregated over a recent window.
func (h *Network) Map(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 24*30 {
		hours = 24
	}
	namespace := r.URL.Query().Get("namespace")
	verdict := strings.ToLower(r.URL.Query().Get("verdict"))
	clusterID, err := h.resolveNetworkCluster(r, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	clusters, err := h.networkClusters(r, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	workloads, err := h.workloads(r, subj.OrgID, clusterID, namespace)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	flows, err := h.flows(r, subj.OrgID, clusterID, hours, namespace, verdict)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	recentFlows, err := h.recentFlows(r, subj.OrgID, clusterID, hours, namespace, verdict)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	seen := map[string]bool{}
	for _, wl := range workloads {
		seen[wl["id"].(string)] = true
	}
	for _, f := range flows {
		for _, key := range []string{"src", "dst"} {
			id := f[key].(string)
			if seen[id] {
				continue
			}
			seen[id] = true
			ns, name := netutil.SplitWorkload(id)
			kind := "External"
			if ns != "external" {
				kind = "Workload"
			}
			workloads = append(workloads, map[string]any{
				"id": id, "namespace": ns, "name": name, "kind": kind,
				"risk_score": 0, "finding_count": 0,
				"critical_count": 0, "high_count": 0,
			})
		}
	}

	summary := map[string]any{
		"window_hours":  hours,
		"workloads":     len(workloads),
		"flows":         len(flows),
		"recent_flows":  len(recentFlows),
		"total_bytes":   sumNetworkMetric(flows, "bytes"),
		"total_packets": sumNetworkMetric(flows, "packets"),
		"allowed":       countNetworkFlows(flows, "state", "ok"),
		"alerted":       countNetworkFlows(flows, "state", "warn"),
		"blocked":       countNetworkFlows(flows, "state", "denied"),
		"clusters":      clusters,
	}
	if clusterID != nil {
		summary["selected_cluster_id"] = clusterID.String()
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"summary":      summary,
		"workloads":    workloads,
		"flows":        flows,
		"recent_flows": recentFlows,
	})
}

func (h *Network) resolveNetworkCluster(r *http.Request, orgID uuid.UUID) (*uuid.UUID, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid cluster_id")
		}
		var exists bool
		if err := h.db.Pool().QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM clusters WHERE org_id = $1 AND id = $2)`, orgID, parsed).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			return nil, fmt.Errorf("cluster not found")
		}
		return &parsed, nil
	}
	var selected uuid.UUID
	if err := h.db.Pool().QueryRow(r.Context(), `
SELECT id
  FROM clusters
 WHERE org_id = $1
 ORDER BY CASE WHEN state = 'connected' THEN 0 ELSE 1 END, last_heartbeat_at DESC NULLS LAST, created_at ASC
 LIMIT 1`, orgID).Scan(&selected); err != nil {
		return nil, nil
	}
	return &selected, nil
}

func (h *Network) networkClusters(r *http.Request, orgID uuid.UUID) ([]map[string]any, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id::text, name, state
  FROM clusters
 WHERE org_id = $1
 ORDER BY CASE WHEN state = 'connected' THEN 0 ELSE 1 END, name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, name, state string
		if err := rows.Scan(&id, &name, &state); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "name": name, "state": state})
	}
	return out, rows.Err()
}

func (h *Network) workloads(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, namespace string) ([]map[string]any, error) {
	// wl_mode: each workload's strongest group policy_mode (NV node badging — Discover/
	// Monitor/Protect). A workload's mode is the max over the groups it belongs to; resolved
	// via groups.members ("ns/name"), the same source the dashboard/exposure rollups use.
	rows, err := h.db.Pool().Query(r.Context(), `
WITH wl_mode AS (
  SELECT jsonb_array_elements_text(g.members) AS wl,
         MAX(CASE g.policy_mode WHEN 'protect' THEN 3 WHEN 'monitor' THEN 2 ELSE 1 END) AS r
    FROM groups g
   WHERE g.org_id = $1 AND ($2::uuid IS NULL OR g.cluster_id = $2)
   GROUP BY 1)
SELECT d.cluster_id::text, COALESCE(c.name, ''), d.namespace, d.name, d.kind, d.risk_score, d.finding_count, d.critical_count, d.high_count,
       CASE m.r WHEN 3 THEN 'protect' WHEN 2 THEN 'monitor' WHEN 1 THEN 'discover' ELSE '' END AS policy_mode
  FROM deployments d
  LEFT JOIN clusters c ON c.id = d.cluster_id
  LEFT JOIN wl_mode m ON m.wl = d.namespace || '/' || d.name
 WHERE d.org_id = $1
   AND ($2::uuid IS NULL OR d.cluster_id = $2)
   AND ($3::text = '' OR d.namespace = $3)
 ORDER BY namespace, name`, orgID, clusterID, namespace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var cluster, clusterName, ns, name, kind, policyMode string
		var risk, findings, critical, high int
		if err := rows.Scan(&cluster, &clusterName, &ns, &name, &kind, &risk, &findings, &critical, &high, &policyMode); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id": fmt.Sprintf("%s/%s", ns, name), "namespace": ns, "name": name, "kind": kind,
			"cluster_id": cluster, "cluster_name": clusterName,
			"risk_score": risk, "finding_count": findings,
			"critical_count": critical, "high_count": high,
			"policy_mode": policyMode,
		})
	}
	return out, rows.Err()
}

func (h *Network) flows(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, hours int, namespace, verdict string) ([]map[string]any, error) {
	// Source precedence (Wave 4 / NET-3): dp > hubble > bpf > declared >
	// synthetic. dp rows carry real on-wire byte/session counts and L7 from
	// DPI parsers; hubble rows (Cilium-eBPF clusters where dp is structurally
	// blind) carry real verdict + byte counts from the Hubble observer API but
	// no DPI L7, so they rank just below dp and above the synthetic bpf
	// connect-event aggregator. The UI fades anything lower once a
	// higher-precedence source is available. The any-source MIN below is just
	// a tie-breaker — we override it from the boolean flags in code.
	// NET perf: read from the network_flow_rollups pre-aggregate (migration 115,
	// kept hot by RollupRefresher) instead of GROUP BY-ing a full day of raw
	// network_flows on every load. Re-aggregating hourly buckets across the
	// window touches ~(distinct conversations x hours) rows, not millions. The
	// scan below is unchanged: column order and types match the raw query.
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT cluster_id::text, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict,
       COALESCE(MIN(min_src_addr), ''), COALESCE(MIN(min_dst_addr), ''), COALESCE(MIN(min_src_port), 0),
       SUM(sum_bytes)::bigint, SUM(sum_packets)::bigint, SUM(flow_count)::bigint, MAX(max_at),
       BOOL_OR(has_dp)     AS has_dp,
       BOOL_OR(has_hubble) AS has_hubble,
       BOOL_OR(has_bpf)    AS has_bpf,
       MIN(min_source) AS any_source,
       COALESCE(SUM(sum_client_bytes)::bigint, 0) AS client_bytes,
       COALESCE(SUM(sum_server_bytes)::bigint, 0) AS server_bytes,
       COALESCE(SUM(sum_sessions)::bigint, 0)     AS sessions,
       MAX(max_threat_id)                          AS max_threat_id,
       MAX(max_severity)                           AS max_severity,
       MAX(max_application)                        AS max_application,
       COALESCE(MIN(NULLIF(fqdn, '')), '')         AS fqdn
  FROM network_flow_rollups
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND bucket >= date_trunc('hour', NOW() - ($3::text || ' hours')::interval)
   AND ($4::text = '' OR src_workload LIKE $4 || '/%' OR dst_workload LIKE $4 || '/%')
   AND ($5::text = '' OR lower(verdict) = $5)
 GROUP BY cluster_id, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict
 ORDER BY MAX(max_at) DESC, SUM(sum_bytes) DESC
 LIMIT 300`, orgID, clusterID, fmt.Sprintf("%d", hours), namespace, verdict)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var cluster, src, dst, proto, l7, v string
		var srcAddr, dstAddr string
		var port, srcPort int
		var bytes, packets, samples int64
		var last time.Time
		var hasDP, hasHubble, hasBPF bool
		var anySource string
		var clientBytes, serverBytes, sessions int64
		var maxThreatID, maxApplication *int32
		var maxSeverity *int16
		var fqdn string
		if err := rows.Scan(&cluster, &src, &dst, &proto, &l7, &port, &v,
			&srcAddr, &dstAddr, &srcPort,
			&bytes, &packets, &samples, &last,
			&hasDP, &hasHubble, &hasBPF, &anySource,
			&clientBytes, &serverBytes, &sessions,
			&maxThreatID, &maxSeverity, &maxApplication, &fqdn,
		); err != nil {
			return nil, err
		}
		id := netutil.StableFlowID(cluster, src, dst, proto, l7, port, v)
		source := anySource
		switch {
		case hasDP:
			source = "dp"
		case hasHubble:
			source = "hubble"
		case hasBPF:
			source = "bpf"
		}
		row := map[string]any{
			"id": id, "src": src, "dst": dst,
			"cluster_id": cluster,
			"src_addr":   srcAddr, "dst_addr": dstAddr, "src_port": srcPort,
			"protocol": strings.ToUpper(proto), "l7_protocol": strings.ToUpper(l7),
			"dst_port": port, "verdict": strings.ToLower(v), "state": stateForVerdict(v),
			"traffic_scope": trafficScope(src, dst),
			"bytes":         bytes, "packets": packets, "samples": samples,
			"source":       source,
			"last_seen_at": last.UTC().Format(time.RFC3339),
		}
		// Surface dp metrics only when we have them — keeps the payload
		// terse for BPF/synthetic-only flows and makes "dp data available"
		// explicit on the wire.
		if hasDP {
			row["client_bytes"] = clientBytes
			row["server_bytes"] = serverBytes
			row["sessions"] = sessions
			if maxApplication != nil && *maxApplication > 0 {
				row["application_id"] = *maxApplication
			}
			if maxThreatID != nil && *maxThreatID > 0 {
				row["threat_id"] = *maxThreatID
				// Resolve a name so the edge/inspector can label the threat even when the
				// packet-level runtime_threats row has aged out of the 24h window or been
				// purged — otherwise the edge shows a threat the drilldown can't find.
				row["threat_name"] = threatNameForFlow(*maxThreatID)
			}
			if maxSeverity != nil && *maxSeverity > 0 {
				row["severity"] = *maxSeverity
			}
		}
		if fqdn != "" {
			row["fqdn"] = fqdn
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// threatNameForFlow resolves a dp threat id to a readable name for the flow row. DPI
// built-ins (1001-2027) use the shared NeuVector name table; WAF sensor hits (40000-49999)
// get a generic label here (the full CRS rule name lives in the runtime package, which the
// threats-list endpoint uses). This lets the edge/inspector show a name even without the
// full runtime_threats row.
func threatNameForFlow(id int32) string {
	if id >= 40000 && id <= 49999 {
		return fmt.Sprintf("WAF signature %d", id)
	}
	if n := handler.NeuVectorThreatName(uint32(id)); n != "" {
		return n
	}
	return fmt.Sprintf("signature %d", id)
}

func (h *Network) recentFlows(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, hours int, namespace, verdict string) ([]map[string]any, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT cluster_id::text, src_workload, dst_workload, protocol, COALESCE(l7_protocol,''), COALESCE(dst_port,0), verdict,
       COALESCE(src_addr, ''), COALESCE(dst_addr, ''), COALESCE(src_port, 0),
       bytes, packets, at, source
  FROM network_flows
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND at >= NOW() - ($3::text || ' hours')::interval
   AND ($4::text = '' OR src_workload LIKE $4 || '/%' OR dst_workload LIKE $4 || '/%')
   AND ($5::text = '' OR lower(verdict) = $5)
 ORDER BY at DESC
 LIMIT 50`, orgID, clusterID, fmt.Sprintf("%d", hours), namespace, verdict)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var cluster, src, dst, proto, l7, v string
		var srcAddr, dstAddr string
		var port, srcPort int
		var bytes, packets int64
		var at time.Time
		var source string
		if err := rows.Scan(&cluster, &src, &dst, &proto, &l7, &port, &v, &srcAddr, &dstAddr, &srcPort, &bytes, &packets, &at, &source); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id":      netutil.StableFlowID("sample", cluster, src, dst, proto, l7, port, v, at.UnixNano()),
			"flow_id": netutil.StableFlowID(cluster, src, dst, proto, l7, port, v),
			"src":     src, "dst": dst,
			"cluster_id": cluster,
			"src_addr":   srcAddr, "dst_addr": dstAddr, "src_port": srcPort,
			"protocol": strings.ToUpper(proto), "l7_protocol": strings.ToUpper(l7),
			"dst_port": port, "verdict": strings.ToLower(v), "state": stateForVerdict(v),
			"traffic_scope": trafficScope(src, dst),
			"bytes":         bytes, "packets": packets,
			"source":      source,
			"observed_at": at.UTC().Format(time.RFC3339),
		})
	}
	return out, rows.Err()
}

func sumNetworkMetric(flows []map[string]any, key string) int64 {
	var total int64
	for _, flow := range flows {
		switch v := flow[key].(type) {
		case int64:
			total += v
		case int:
			total += int64(v)
		}
	}
	return total
}

func countNetworkFlows(flows []map[string]any, key, value string) int {
	total := 0
	for _, flow := range flows {
		if flow[key] == value {
			total++
		}
	}
	return total
}

func trafficScope(src, dst string) string {
	srcExternal := strings.HasPrefix(src, "external/")
	dstExternal := strings.HasPrefix(dst, "external/")
	switch {
	case srcExternal && dstExternal:
		return "external"
	case srcExternal:
		return "ingress-external"
	case dstExternal:
		return "egress-external"
	default:
		srcNS, _ := netutil.SplitWorkload(src)
		dstNS, _ := netutil.SplitWorkload(dst)
		if srcNS != dstNS {
			return "cross-namespace"
		}
		return "internal"
	}
}

func stateForVerdict(v string) string {
	switch strings.ToLower(v) {
	case "block", "blocked", "deny", "denied":
		return "denied"
	case "alert", "warn", "monitor":
		return "warn"
	case "declared":
		return "declared"
	default:
		return "ok"
	}
}
