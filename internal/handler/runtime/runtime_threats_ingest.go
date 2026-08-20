// Wave 5: runtime-agent ingest + listing for DPI signature hits.
//
//	POST /api/v1/runtime-threats:bulk   — runtime-agent bulk upload
//	                                      (auth: runtime-agent-token)
//	GET  /api/v1/runtime-threats        — user-facing list (read-findings verb)
//
// The runtime-agent's dp supervisor surfaces DPMsgThreatLog records (decoded
// in internal/runtime/dp) as `dp.EventThreat`. The agent uploads them here;
// one POST body is an array of ThreatIngestRow, mirroring the shape of the
// network-flows ingest. Each row becomes one INSERT into `runtime_threats`.
//
// The captured packet bytes (up to DPLOG_MAX_PKT_LEN ≈ 2 KB) ride along as
// a base64-encoded JSON `packet` field — net/json byte-slice encoding does
// the base64 automatically; we just hand it through to bytea on insert.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/notify"
	"github.com/alphabravocompany/constellation/pkg/rbac"
	"github.com/alphabravocompany/constellation/pkg/response"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// RuntimeThreats serves both the runtime-agent ingest path and the user-
// facing list endpoint. Auth is dispatched at the router level — the same
// struct can sit behind two different middleware chains.
type RuntimeThreats struct {
	db *db.DB

	// P0-5 real-time alerting fan-out. All optional/injected, mirroring the
	// EventsIngest fan-out (audit + notify + response engines). When a hook is
	// nil that leg is skipped; a bare NewRuntimeThreats still only INSERTs, so
	// existing call sites keep working. See WithAlerting / With* below.
	audit             *audit.Logger
	dispatcher        *notify.Dispatcher
	respond           func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event)
	evalResponseRules func(ctx context.Context, orgID uuid.UUID, ev *responserule.Event) ([]responserule.Action, error)

	// dedup collapses a flood of identical threats (same threat_id + src/dst +
	// port) into a single alert per window. Always non-nil (set by the
	// constructor); the window is env-configurable via threatDedupWindow.
	dedup *threatDedup
}

// NewRuntimeThreats constructs the handler. By default it only persists rows;
// wire the fan-out with WithAudit / WithDispatcher / WithResponseEngine /
// WithResponseRuleEngine (or the WithAlerting convenience) to light up P0-5
// real-time alerting.
func NewRuntimeThreats(d *db.DB) *RuntimeThreats {
	return &RuntimeThreats{db: d, dedup: newThreatDedup(threatDedupWindow)}
}

// ThreatIngestRow is the wire shape the runtime-agent POSTs. Mirrors the
// fields decoded from DPMsgThreatLog (third_party/neuvector/defs.h:391-412).
// JSON tags must match what cmd/constellation-runtime-agent emits.
type ThreatIngestRow struct {
	At          time.Time `json:"at"`
	Node        string    `json:"node,omitempty"`
	EPMAC       string    `json:"ep_mac,omitempty"`
	WorkloadID  string    `json:"workload_id,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	PodName     string    `json:"pod_name,omitempty"`
	ThreatID    uint32    `json:"threat_id"`
	Severity    uint8     `json:"severity"`
	Action      uint8     `json:"action"`
	Application uint32    `json:"application,omitempty"`
	Msg         string    `json:"msg,omitempty"`
	DlpNameHash uint32    `json:"dlp_name_hash,omitempty"`

	IPProto   uint8  `json:"ip_proto,omitempty"`
	EtherType uint16 `json:"ether_type,omitempty"`
	SrcIP     string `json:"src_ip,omitempty"`
	SrcPort   int    `json:"src_port,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	DstPort   int    `json:"dst_port,omitempty"`
	ICMPCode  uint8  `json:"icmp_code,omitempty"`
	ICMPType  uint8  `json:"icmp_type,omitempty"`

	Packet []byte `json:"packet,omitempty"` // base64-encoded in JSON
	PktLen int    `json:"pkt_len,omitempty"`
	CapLen int    `json:"cap_len,omitempty"`

	PktIngress  bool `json:"pkt_ingress,omitempty"`
	SessIngress bool `json:"sess_ingress,omitempty"`
	TapMode     bool `json:"tap,omitempty"`

	ReportedAt time.Time `json:"reported_at,omitempty"`
}

// ThreatIngestResponse summarizes the result of a bulk POST.
type ThreatIngestResponse struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected,omitempty"`
	// Alerts is the number of threats that actually fanned out to
	// audit/notify/response this batch (post-dedup, at/above the severity
	// threshold). A flood collapses to a small number here.
	Alerts int `json:"alerts,omitempty"`
}

// Hard cap per request. Real-world: threats are rare (a busy enforcer might
// emit a few per minute under attack), so 500 is generous.
const maxThreatBatchSize = 500

// Captured-packet cap. dp's DPLOG_MAX_PKT_LEN = 2048; we accept up to 4 KB
// to absorb any small future expansion and to make boundary bugs loud.
const maxThreatPacketBytes = 4096

// Bulk inserts a batch of threats. Auth is runtime-agent-token; cluster_id
// is resolved best-effort against the agent's org.
func (h *RuntimeThreats) Bulk(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20) // 4 MiB — generous because of packet bytes

	var rows []ThreatIngestRow
	if err := json.NewDecoder(r.Body).Decode(&rows); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if len(rows) == 0 {
		httpx.WriteJSON(w, http.StatusOK, ThreatIngestResponse{})
		return
	}
	if len(rows) > maxThreatBatchSize {
		jsonError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("batch > %d", maxThreatBatchSize))
		return
	}

	// Resolve the org's primary cluster_id as the fallback when we can't
	// map a row to a specific cluster. The agent doesn't know its cluster
	// — we trust the token's org and pick the agent's connected cluster.
	var defaultCluster uuid.UUID
	_ = h.db.Pool().QueryRow(r.Context(),
		`SELECT id FROM clusters WHERE org_id = $1
		 ORDER BY CASE WHEN state = 'connected' THEN 0 ELSE 1 END,
		          last_heartbeat_at DESC NULLS LAST, created_at ASC
		 LIMIT 1`, tok.OrgID).
		Scan(&defaultCluster)

	ipResolver := handler.NewIPResolver(r.Context(), h.db, tok.OrgID, flowRowsForThreatAttribution(rows))

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	const insertSQL = `
INSERT INTO runtime_threats
  (org_id, cluster_id, node, ep_mac, workload_id, namespace, pod_name,
   threat_id, severity, action, application, msg, dlp_name_hash,
   ip_proto, ether_type, src_ip, src_port, dst_ip, dst_port,
   icmp_code, icmp_type,
   packet, pkt_len, cap_len,
   pkt_ingress, sess_ingress, tap_mode,
   reported_at, at)
VALUES ($1,$2, NULLIF($3,''), NULLIF($4,''), NULLIF($5,''), NULLIF($6,''), NULLIF($7,''),
        $8,$9,$10, NULLIF($11,0::int), NULLIF($12,''), NULLIF($13,0::bigint),
        NULLIF($14,0::smallint), NULLIF($15,0::int),
        NULLIF($16,''), NULLIF($17,0::int), NULLIF($18,''), NULLIF($19,0::int),
        NULLIF($20,0::smallint), NULLIF($21,0::smallint),
        $22, NULLIF($23,0::int), NULLIF($24,0::int),
        $25, $26, $27,
        $28, $29)`

	var accepted, rejected int
	// Rows that were persisted this batch, carried to the post-commit fan-out
	// (P0-5). Collected inside the loop so we reuse the same cluster/workload
	// attribution the insert used, then alerted on AFTER commit so a notify /
	// audit hiccup can never roll back the ingest.
	pending := make([]pendingThreatAlert, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		if row.ThreatID == 0 {
			// A zero ThreatID means "no signature fired" — dp shouldn't
			// emit a threat log for that, but defend against agents that
			// upload bad rows anyway.
			rejected++
			continue
		}
		if row.At.IsZero() {
			row.At = time.Now().UTC()
		}
		if row.ReportedAt.IsZero() {
			row.ReportedAt = row.At
		}
		// Truncate runaway packet payloads to maxThreatPacketBytes so a
		// misbehaving agent can't blow up the DB row size.
		pkt := row.Packet
		if len(pkt) > maxThreatPacketBytes {
			pkt = pkt[:maxThreatPacketBytes]
		}
		// Cluster resolution: best-effort lookup via ep_mac → pod_ips →
		// deployment.cluster_id is more than this wave needs; we fall back
		// to the org's primary cluster. Future wave (when the operator's
		// pod resolver lands) can plumb a real per-flow lookup here.
		cid := defaultCluster
		if cid == uuid.Nil {
			rejected++
			continue
		}
		workloadID, namespace, podName := runtimeThreatAttribution(row, ipResolver)
		if _, err := tx.Exec(r.Context(), insertSQL,
			tok.OrgID, cid, strings.TrimSpace(row.Node), strings.ToLower(strings.TrimSpace(row.EPMAC)),
			workloadID, namespace, podName,
			int32(row.ThreatID), int16(row.Severity), int16(row.Action),
			int32(row.Application), strings.TrimSpace(row.Msg), int64(row.DlpNameHash),
			int16(row.IPProto), int32(row.EtherType),
			strings.TrimSpace(row.SrcIP), row.SrcPort, strings.TrimSpace(row.DstIP), row.DstPort,
			int16(row.ICMPCode), int16(row.ICMPType),
			pkt, len(pkt), row.CapLen,
			row.PktIngress, row.SessIngress, row.TapMode,
			row.ReportedAt.UTC(), row.At.UTC(),
		); err != nil {
			jsonError(w, http.StatusInternalServerError, "insert: "+err.Error())
			return
		}
		accepted++
		pending = append(pending, pendingThreatAlert{
			row:        row,
			clusterID:  cid,
			workloadID: workloadID,
			namespace:  namespace,
			podName:    podName,
		})
	}

	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit: "+err.Error())
		return
	}

	// P0-5: fan out at/above the severity threshold, deduped so a flood is one
	// alert not thousands. Best-effort and post-commit — never affects the 200.
	alerts := h.fanOutThreats(r.Context(), tok.OrgID, pending)

	slog.Default().Debug("runtime_threats ingest",
		slog.Int("accepted", accepted), slog.Int("rejected", rejected),
		slog.Int("alerts", alerts), slog.String("org", tok.OrgID.String()))
	httpx.WriteJSON(w, http.StatusOK, ThreatIngestResponse{Accepted: accepted, Rejected: rejected, Alerts: alerts})
}

func flowRowsForThreatAttribution(rows []ThreatIngestRow) handler.FlowIngestRequest {
	out := make(handler.FlowIngestRequest, 0, len(rows))
	for i := range rows {
		seed, addr := runtimeThreatWorkloadSeed(&rows[i])
		row := handler.FlowIngestRow{
			SrcWorkload: seed,
			DstWorkload: seed,
			SrcAddr:     rows[i].SrcIP,
			DstAddr:     rows[i].DstIP,
			Protocol:    "tcp",
			At:          rows[i].At,
		}
		if addr != "" {
			row.SrcAddr = addr
			row.DstAddr = addr
		}
		out = append(out, row)
	}
	return out
}

func runtimeThreatAttribution(row *ThreatIngestRow, resolver *handler.IPResolver) (workloadID, namespace, podName string) {
	workloadID = strings.TrimSpace(row.WorkloadID)
	namespace = strings.TrimSpace(row.Namespace)
	podName = strings.TrimSpace(row.PodName)
	if workloadID == "" || strings.HasPrefix(workloadID, "cluster/") {
		seed, addr := runtimeThreatWorkloadSeed(row)
		if seed != "" {
			workloadID = seed
		}
		if resolver != nil && seed != "" {
			if resolved, ok := resolver.Resolve(seed, addr, "node/"+strings.TrimSpace(row.Node), row.At); ok {
				workloadID = resolved
			}
		}
	}
	if namespace == "" {
		if ns, name, ok := splitNamespacedName(workloadID); ok {
			namespace = ns
			if podName == "" && strings.HasPrefix(name, "pod/") {
				podName = strings.TrimPrefix(name, "pod/")
			}
		}
	}
	return workloadID, namespace, podName
}

func runtimeThreatWorkloadSeed(row *ThreatIngestRow) (workloadID, addr string) {
	if row == nil {
		return "", ""
	}
	if workloadID := strings.TrimSpace(row.WorkloadID); workloadID != "" {
		return workloadID, ""
	}
	addr = strings.TrimSpace(row.SrcIP)
	if row.SessIngress {
		addr = strings.TrimSpace(row.DstIP)
	}
	if normalized, ok := normalizeIP(addr); ok {
		return "cluster/" + normalized, normalized
	}
	if epmac := strings.ToLower(strings.TrimSpace(row.EPMAC)); epmac != "" {
		return "node-local/" + strings.ReplaceAll(epmac, ":", ""), ""
	}
	if node := strings.TrimSpace(row.Node); node != "" {
		return "node/" + node, ""
	}
	return "", ""
}

// RuntimeThreatRow is the read-side shape returned by List. Excludes the
// captured packet bytes by default — too noisy for a list view; the user
// fetches Get(id) for the full row when drilling in.
type RuntimeThreatRow struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	ClusterID   string    `json:"cluster_id"`
	Node        string    `json:"node,omitempty"`
	EPMAC       string    `json:"ep_mac,omitempty"`
	WorkloadID  string    `json:"workload_id,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	PodName     string    `json:"pod_name,omitempty"`
	ThreatID    int32     `json:"threat_id"`
	ThreatName  string    `json:"threat_name,omitempty"` // pretty label derived from ID
	Category    string    `json:"category,omitempty"`    // "ips" | "dlp" | "waf", derived from threat_id range
	Severity    int16     `json:"severity"`
	Action      int16     `json:"action"`
	Application int32     `json:"application,omitempty"`
	Msg         string    `json:"msg,omitempty"`
	IPProto     int16     `json:"ip_proto,omitempty"`
	SrcIP       string    `json:"src_ip,omitempty"`
	SrcPort     int       `json:"src_port,omitempty"`
	DstIP       string    `json:"dst_ip,omitempty"`
	DstPort     int       `json:"dst_port,omitempty"`
	PktLen      int       `json:"pkt_len,omitempty"`
	CapLen      int       `json:"cap_len,omitempty"`
	PktIngress  bool      `json:"pkt_ingress"`
	SessIngress bool      `json:"sess_ingress"`
	ReportedAt  time.Time `json:"reported_at"`
	At          time.Time `json:"at"`
}

// List returns recent threats. Filters: ?hours= (default 24, max 720),
// ?severity_min= (1..9), ?cluster_id=, ?workload_id=, ?category=dlp|waf.
func (h *RuntimeThreats) List(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	hours := clampInt(parseIntDefault(r.URL.Query().Get("hours"), 24), 1, 720)
	sevMin := clampInt(parseIntDefault(r.URL.Query().Get("severity_min"), 0), 0, 9)
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	workloadIDFilter := strings.TrimSpace(r.URL.Query().Get("workload_id"))
	categoryFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("category")))
	if categoryFilter != "" && categoryFilter != "dlp" && categoryFilter != "waf" && categoryFilter != "ips" {
		jsonError(w, http.StatusBadRequest, "category must be dlp, waf, or ips")
		return
	}

	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id::text, org_id::text, cluster_id::text,
       COALESCE(node,''), COALESCE(ep_mac,''), COALESCE(workload_id,''), COALESCE(namespace,''), COALESCE(pod_name,''),
       threat_id, severity, action,
       COALESCE(application,0), COALESCE(msg,''),
       COALESCE(ip_proto,0::smallint),
       COALESCE(src_ip,''), COALESCE(src_port,0),
       COALESCE(dst_ip,''), COALESCE(dst_port,0),
       COALESCE(pkt_len,0), COALESCE(cap_len,0),
       pkt_ingress, sess_ingress,
       reported_at, at
  FROM runtime_threats
 WHERE org_id = $1
   AND at >= NOW() - ($2::text || ' hours')::interval
   AND ($3::text = '' OR cluster_id::text = $3)
   AND severity >= $4::smallint
   AND ($5::text = '' OR workload_id = $5)
   AND ($6::text = '' OR (CASE
            WHEN threat_id >= 40000 AND threat_id < 50000 THEN 'waf'
            WHEN threat_id >= 20000 AND threat_id < 40000 THEN 'dlp'
            ELSE 'ips'
        END) = $6)
 ORDER BY at DESC
 LIMIT 500`,
		sub.OrgID, fmt.Sprintf("%d", hours), clusterID, int16(sevMin), workloadIDFilter, categoryFilter)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	out := make([]RuntimeThreatRow, 0, 32)
	for rows.Next() {
		var t RuntimeThreatRow
		if err := rows.Scan(
			&t.ID, &t.OrgID, &t.ClusterID,
			&t.Node, &t.EPMAC, &t.WorkloadID, &t.Namespace, &t.PodName,
			&t.ThreatID, &t.Severity, &t.Action,
			&t.Application, &t.Msg,
			&t.IPProto,
			&t.SrcIP, &t.SrcPort,
			&t.DstIP, &t.DstPort,
			&t.PktLen, &t.CapLen,
			&t.PktIngress, &t.SessIngress,
			&t.ReportedAt, &t.At,
		); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		t.ThreatName = resolveThreatName(uint32(t.ThreatID))
		t.Category = threatCategory(t.ThreatID)
		out = append(out, t)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"threats": out})
}

// VerbList is the rbac verb gate for List.
func (h *RuntimeThreats) VerbList() rbac.Verb { return rbac.VerbReadFindings }

// RuntimeThreatDetail extends RuntimeThreatRow with the captured packet
// bytes (base64-encoded by Go's net/json) and a best-effort L7 preview.
// Returned only by the per-id Get endpoint so list payloads stay terse.
type RuntimeThreatDetail struct {
	RuntimeThreatRow
	// Packet is the bytes dp copied off the wire. Up to ~2 KB. Encoded as
	// base64 in JSON (Go's default for []byte) so the UI can paint a hex
	// dump or hand the bytes off to a decoder.
	Packet []byte `json:"packet,omitempty"`
	// L7 carries a parsed peek of the captured payload — what the user
	// most often wants to see. See parsePacketL7. Nil when the payload
	// doesn't match a known shape.
	L7 *ThreatL7Preview `json:"l7,omitempty"`
}

// ThreatL7Preview is the high-signal payload summary surfaced alongside the
// hex dump. We fill exactly one of HTTP/DNS today; future parsers can
// extend the shape without breaking older clients.
type ThreatL7Preview struct {
	Kind string              `json:"kind"` // "http" | "dns" | "tls" | ""
	HTTP *HTTPRequestPreview `json:"http,omitempty"`
	DNS  *DNSQueryPreview    `json:"dns,omitempty"`
	TLS  *TLSHelloPreview    `json:"tls,omitempty"`
}

type HTTPRequestPreview struct {
	Method  string            `json:"method"`
	Target  string            `json:"target"`
	Version string            `json:"version,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type DNSQueryPreview struct {
	QName string `json:"qname,omitempty"`
	QType string `json:"qtype,omitempty"`
}

type TLSHelloPreview struct {
	SNI     string `json:"sni,omitempty"`
	Version string `json:"version,omitempty"`
}

// Get returns one threat row in full, including the captured packet bytes
// and an L7 preview. URL path: /api/v1/runtime-threats/{id}.
func (h *RuntimeThreats) Get(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id := strings.TrimSpace(pathTail(r.URL.Path))
	if id == "" {
		jsonError(w, http.StatusBadRequest, "missing id")
		return
	}

	var t RuntimeThreatDetail
	var packet []byte
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT id::text, org_id::text, cluster_id::text,
       COALESCE(node,''), COALESCE(ep_mac,''), COALESCE(workload_id,''), COALESCE(namespace,''), COALESCE(pod_name,''),
       threat_id, severity, action,
       COALESCE(application,0), COALESCE(msg,''),
       COALESCE(ip_proto,0::smallint),
       COALESCE(src_ip,''), COALESCE(src_port,0),
       COALESCE(dst_ip,''), COALESCE(dst_port,0),
       COALESCE(pkt_len,0), COALESCE(cap_len,0),
       pkt_ingress, sess_ingress,
       reported_at, at,
       COALESCE(packet, ''::bytea)
  FROM runtime_threats
 WHERE id = $1::uuid AND org_id = $2`,
		id, sub.OrgID).
		Scan(&t.ID, &t.OrgID, &t.ClusterID,
			&t.Node, &t.EPMAC, &t.WorkloadID, &t.Namespace, &t.PodName,
			&t.ThreatID, &t.Severity, &t.Action,
			&t.Application, &t.Msg,
			&t.IPProto,
			&t.SrcIP, &t.SrcPort,
			&t.DstIP, &t.DstPort,
			&t.PktLen, &t.CapLen,
			&t.PktIngress, &t.SessIngress,
			&t.ReportedAt, &t.At,
			&packet)
	if err != nil {
		// Distinguish "doesn't exist / not yours" (404) from "DB problem" (500).
		// pgx returns pgx.ErrNoRows for empty results — we use a string check to
		// avoid importing the driver here.
		if strings.Contains(err.Error(), "no rows") {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	t.ThreatName = resolveThreatName(uint32(t.ThreatID))
	t.Category = threatCategory(t.ThreatID)
	t.Packet = packet
	if preview := parsePacketL7(packet, t.DstPort); preview != nil {
		t.L7 = preview
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

// VerbGet — same gate as List.
func (h *RuntimeThreats) VerbGet() rbac.Verb { return rbac.VerbReadFindings }

// pathTail returns the last "/foo" segment of a URL path. We don't have chi
// available in this file's existing import set; the route is wired with
// "/runtime-threats/{id}" so chi has already validated the segment exists.
// We extract via straight-string ops to avoid pulling chi into this file.
func pathTail(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

// threatCategory classifies a NeuVector threat_id into its DPI engine bucket, matching
// NeuVector's own classification (controller/cache/cache.go isWafThreatID/isDlpThreatID,
// controller/api/apis.go rule-id ranges): custom WAF-sensor rules occupy [40000,50000),
// DLP rules occupy [20000,40000), and everything below that — the built-in IPS/IDS DPI
// signatures (flood detectors 1001-1003 and the protocol-anomaly/exploit signatures
// 2001-2027, e.g. PING_DEATH, TCP_SMURF, SQL_INJECTION) — is "ips". The old filter keyed on
// dlp_name_hash, which mislabeled every built-in IPS signature (hash=0) as 'waf' and put real
// custom WAF hits (hash>0) in 'dlp'; the threat_id range is the authoritative discriminator.
func threatCategory(threatID int32) string {
	switch {
	case threatID >= 40000 && threatID < 50000:
		return "waf"
	case threatID >= 20000 && threatID < 40000:
		return "dlp"
	default:
		return "ips"
	}
}

func parseIntDefault(s string, def int) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
		return n
	}
	return def
}

func clampInt(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}
