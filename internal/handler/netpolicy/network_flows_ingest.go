// Wave M1: runtime-agent ingest path for L4 network flows.
//
//	POST /api/v1/network-flows:bulk     — runtime-agent bulk insert
//	                                       (auth: runtime-agent-token)
//
// The cmd/constellation-runtime-agent daemonset already streams tcp_connect /
// inet_csk_accept observations into the `events` partitioned table via
// POST /api/v1/events:bulk (Wave I4). That table is great for forensics but
// is not what the NeuVector-style Network Map renders against — the UI reads
// from `network_flows`, a separate partitioned table keyed on
// (src_workload, dst_workload, dst_port, protocol).
//
// This endpoint is the bridge: the agent aggregates raw BPF events into 30s
// buckets, summing per-bucket packet counts and (estimated) bytes, and POSTs
// the bucketed rows here. Each row becomes one INSERT into network_flows with
// source='bpf' so the UI can fade-out stale synthetic rows independently from
// fresh BPF-sourced ones.
//
// Authn:
//   - Uses the same RuntimeAgentTokenMiddleware as /api/v1/events:bulk.
//   - The token is org-scoped; we resolve cluster_id by best-effort against
//     `deployments` (matching the src or dst workload) and fall back to the
//     org's primary connected cluster, mirroring events_ingest's heuristic.
//
// Byte counts:
//   - BPF tcp_connect/accept probes do not emit byte counters today; the
//     agent submits an l7-aware estimate (HTTP=512B/pkt, gRPC=128B/pkt, ...).
//     This is a "soft estimate" — flagged via source='bpf' in the row and a
//     `bytes_estimated=true` flag in the payload so the UI / queries can
//     differentiate when real counters land in a later wave.
//
// The flow wire-shape (handler.FlowIngestRow / FlowIngestRequest) and the
// per-request workload/IP resolvers live in the parent handler package
// (network_flow_resolve.go) because the runtime threat-ingest path shares
// them; this handler consumes them through handler's exported seams.
package netpolicy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/livegraph"
	netpolicy "github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// NetworkFlowsIngest handles POST /api/v1/network-flows:bulk.
type NetworkFlowsIngest struct {
	db      *db.DB
	live    *livegraph.Store // optional hot cache (plan B5); nil when disabled
	matches *MatchStatsStore // A7: per-rule match telemetry
	nbe     *NBEStore        // B6: cross-namespace boundary enforcement
}

// NewNetworkFlowsIngest constructs the handler.
func NewNetworkFlowsIngest(d *db.DB) *NetworkFlowsIngest {
	return &NetworkFlowsIngest{db: d, matches: NewMatchStatsStore(d), nbe: NewNBEStore(d)}
}

// WithLiveGraph attaches the in-memory conversation-graph cache so accepted
// rows are mirrored into the hot graph and fanned out to SSE subscribers.
// No-op semantics preserved when the store is nil.
func (h *NetworkFlowsIngest) WithLiveGraph(s *livegraph.Store) *NetworkFlowsIngest {
	h.live = s
	return h
}

// FlowIngestResponse summarizes what was accepted.
type FlowIngestResponse struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected,omitempty"`
	// A7: how many accepted rows carried a matched rule id and thus bumped a
	// per-rule match counter.
	RuleMatches int `json:"rule_matches,omitempty"`
	// B6: cross-namespace flows flagged (observe or protect) and, of those,
	// how many were marked deny under a namespace in protect mode.
	NBEFlagged int `json:"nbe_flagged,omitempty"`
	NBEDenied  int `json:"nbe_denied,omitempty"`
}

// Bulk handles POST /api/v1/network-flows:bulk. Validates the body and
// persists every well-formed row into `network_flows` in a single transaction.
//
// Hard cap of 1000 rows per request: the agent aggregates into 30s buckets,
// so this is well above what a single node should ever produce in one batch.
func (h *NetworkFlowsIngest) Bulk(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB cap

	var rows handler.FlowIngestRequest
	if err := json.NewDecoder(r.Body).Decode(&rows); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if len(rows) == 0 {
		httpx.WriteJSON(w, http.StatusOK, FlowIngestResponse{})
		return
	}
	if len(rows) > 1000 {
		jsonError(w, http.StatusRequestEntityTooLarge, "batch > 1000")
		return
	}

	// Pre-resolve the org's default cluster_id (used when neither workload
	// matches a deployment row). Mirrors events_ingest.go.
	var defaultCluster uuid.UUID
	_ = h.db.Pool().QueryRow(r.Context(),
		`SELECT id FROM clusters WHERE org_id = $1
		 ORDER BY CASE WHEN state = 'connected' THEN 0 ELSE 1 END,
		          last_heartbeat_at DESC NULLS LAST, created_at ASC
		 LIMIT 1`, tok.OrgID).
		Scan(&defaultCluster)

	resolver := handler.NewClusterResolver(h.db, tok.OrgID, defaultCluster)

	// Wave M2: batched IP resolution. Build the set of distinct addresses in
	// this batch and look them up against pod_ips + cluster_services in two
	// queries total, then use the maps to rewrite "cluster/<ip>" workloads
	// into "<ns>/<deployment>" or "<ns>/<service>" before insert. Well-known
	// IPs (loopback / metadata / CGNAT / multicast / link-local) are mapped
	// without a DB hit.
	ipResolver := handler.NewIPResolver(r.Context(), h.db, tok.OrgID, rows)

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	const insertSQL = `
INSERT INTO network_flows
  (org_id, cluster_id, src_workload, dst_workload, src_addr, dst_addr,
   src_port, dst_port, protocol, l7_protocol, bytes, packets, verdict,
   source, at,
   client_bytes, server_bytes, sessions, application, policy_action,
   policy_id, threat_id, severity, ep_mac, fqdn)
VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),
        NULLIF($7,0),NULLIF($8,0),$9,NULLIF($10,''),$11,$12,$13,$14,$15,
        NULLIF($16,0::bigint), NULLIF($17,0::bigint), NULLIF($18,0::bigint),
        NULLIF($19,0::int), NULLIF($20,''),
        NULLIF($21,0::bigint), NULLIF($22,0::int), NULLIF($23,0::smallint),
        NULLIF($24,''), NULLIF($25,''))`

	var accepted, rejected int
	// Plan B5: buffer accepted rows and fan them into the hot graph / SSE only
	// after tx.Commit succeeds. Publishing inside the loop would leak rows into
	// the in-memory graph that a later insert/commit failure rolls back in the
	// DB, causing DB/live divergence until TTL eviction.
	var pending []livegraph.Flow

	// A7: accumulate per-(cluster,rule) match increments across the batch so a
	// batch of flows for the same rule costs one UPSERT after commit, not one
	// per row. Written best-effort post-commit (see below).
	ruleHits := map[uuid.UUID]map[int64]ruleHit{}
	var ruleMatches int
	// B6: per-cluster NBE mode maps, loaded lazily once per cluster seen in the
	// batch. Absent namespace => NBEOff (feature is opt-in).
	nbeModes := map[uuid.UUID]map[string]netpolicy.NBEMode{}
	var nbeFlagged, nbeDenied int
	for i := range rows {
		row := &rows[i]
		if row.SrcWorkload == "" || row.DstWorkload == "" || row.Protocol == "" {
			rejected++
			continue
		}
		// Wave M2: resolve raw IPs (anything the agent labeled as
		// "cluster/<ip>" or anything we can identify as well-known) into
		// named workloads. Falls through unchanged if nothing matches.
		// `resolved` is true when the resolver actively rewrote the workload
		// — used below to skip the external-collapse step for well-known
		// labels like "external/cloud-metadata" or "external/cgnat-x.y.z.w"
		// that we *want* to keep visible.
		newSrc, srcResolved := ipResolver.Resolve(row.SrcWorkload, row.SrcAddr, row.SrcWorkload, row.At)
		newDst, dstResolved := ipResolver.Resolve(row.DstWorkload, row.DstAddr, row.SrcWorkload, row.At)
		row.SrcWorkload = newSrc
		row.DstWorkload = newDst

		// NeuVector convention (share/clus_apis.go: CLUSWLExternal): collapse
		// every "external/<ip-or-host>" destination into a single "external"
		// workload bucket so the Network Map doesn't grow one node per
		// upstream IP. The actual address is preserved in dst_addr for the
		// per-row popover. Apply on the server too so any agent that hasn't
		// yet been upgraded to the M1-renamed shape still produces a clean
		// graph. Skip collapse when the resolver classified the row as a
		// well-known label we want to keep (cloud-metadata / CGNAT / mDNS).
		if !dstResolved && strings.HasPrefix(row.DstWorkload, "external/") {
			row.DstWorkload = "external"
		}
		if !srcResolved && strings.HasPrefix(row.SrcWorkload, "external/") {
			row.SrcWorkload = "external"
		}
		if row.At.IsZero() {
			row.At = time.Now().UTC()
		}
		verdict := strings.ToLower(strings.TrimSpace(row.Verdict))
		if verdict == "" {
			verdict = "allow"
		}
		cid := resolver.Lookup(r.Context(), row.SrcWorkload, row.DstWorkload)
		if cid == uuid.Nil {
			// network_flows.cluster_id is NOT NULL — drop the row rather
			// than insert a synthetic zero UUID and pollute the index.
			rejected++
			continue
		}
		source := strings.ToLower(strings.TrimSpace(row.Source))
		switch source {
		case "dp", "bpf", "hubble", "synthetic", "declared":
			// known. NET-3: "hubble" is the Cilium-eBPF ingest source — on
			// Cilium clusters our iptables/dp datapath is structurally blind
			// (cnidetect.SafeForNFQUEUE()==false), so the runtime-agent
			// streams flows from the Hubble relay observer API instead. These
			// rows carry real verdict + per-flow byte counts, so they rank
			// just below "dp" and above "bpf" in the read precedence below.
		case "":
			source = "bpf"
		default:
			// Unknown values fall back to "bpf" rather than poisoning the
			// table with arbitrary strings.
			source = "bpf"
		}
		// If client+server bytes are reported but the legacy `bytes` field is
		// zero, derive bytes so existing SUM(bytes) queries keep working.
		if row.Bytes == 0 && (row.ClientBytes > 0 || row.ServerBytes > 0) {
			row.Bytes = row.ClientBytes + row.ServerBytes
		}
		// If sessions are reported but packets is zero, surface sessions as
		// the packet proxy — dp doesn't count packets separately, but every
		// session is at minimum 1 packet, so this is a safe lower bound.
		if row.Packets == 0 && row.Sessions > 0 {
			row.Packets = row.Sessions
		}
		policyAction := strings.ToLower(strings.TrimSpace(row.PolicyAction))
		// B6: cross-namespace network boundary enforcement. Resolve the dst
		// namespace's NBE mode (default off) and evaluate the src->dst pair.
		// Under observe a boundary crossing is surfaced (policy_action=violate);
		// under protect it is denied (policy_action=deny). Only stamp when the
		// agent didn't already report a policy_action, so real datapath verdicts
		// are never clobbered. SAFETY: default off => no-op; observe never
		// changes the observed `verdict` (what actually happened), only the
		// advisory policy_action.
		srcNS := namespaceOf(row.SrcWorkload)
		dstNS := namespaceOf(row.DstWorkload)
		modes, ok := nbeModes[cid]
		if !ok {
			modes, _ = h.nbe.ModesForCluster(r.Context(), tok.OrgID, cid)
			if modes == nil {
				modes = map[string]netpolicy.NBEMode{}
			}
			nbeModes[cid] = modes
		}
		dec := netpolicy.EvaluateNBE(srcNS, dstNS, modes[dstNS])
		if dec.Flagged {
			nbeFlagged++
			if dec.Deny {
				nbeDenied++
				if policyAction == "" {
					policyAction = "deny"
				}
			} else if policyAction == "" {
				policyAction = "violate"
			}
		}
		if _, err := tx.Exec(r.Context(), insertSQL,
			tok.OrgID, cid,
			row.SrcWorkload, row.DstWorkload,
			row.SrcAddr, row.DstAddr,
			row.SrcPort, row.DstPort,
			strings.ToLower(row.Protocol), strings.ToLower(row.L7Protocol),
			row.Bytes, row.Packets, verdict,
			source, row.At.UTC(),
			row.ClientBytes, row.ServerBytes, row.Sessions,
			int32(row.Application), policyAction,
			int64(row.PolicyID), int32(row.ThreatID), int16(row.Severity),
			strings.ToLower(strings.TrimSpace(row.EPMAC)),
			strings.ToLower(strings.TrimSpace(row.Fqdn)),
		); err != nil {
			jsonError(w, http.StatusInternalServerError, "insert: "+err.Error())
			return
		}
		accepted++
		// A7: attribute this flow to the rule that produced its verdict.
		// network_flows.policy_id carries the matched dp rule id (NeuVector
		// CLUSConnection.PolicyId), so a non-zero value is a rule match. Count
		// one match per aggregated flow bucket (sessions when reported, else 1)
		// and advance the rule's last_matched_at to this flow's timestamp.
		if row.PolicyID != 0 {
			cluster := ruleHits[cid]
			if cluster == nil {
				cluster = map[int64]ruleHit{}
				ruleHits[cid] = cluster
			}
			inc := int64(1)
			if row.Sessions > 0 {
				inc = row.Sessions
			}
			h2 := cluster[int64(row.PolicyID)]
			h2.count += inc
			if row.At.After(h2.last) {
				h2.last = row.At.UTC()
			}
			cluster[int64(row.PolicyID)] = h2
			ruleMatches++
		}
		// Plan B5: mirror the accepted row into the hot in-memory graph and
		// fan it out to live SSE subscribers. Buffered here and published only
		// after tx.Commit succeeds so a rolled-back batch never lingers in the
		// hot graph. Best-effort; never blocks ingest.
		if h.live != nil {
			pending = append(pending, livegraph.Flow{
				OrgID: tok.OrgID, ClusterID: cid,
				SrcWorkload: row.SrcWorkload, DstWorkload: row.DstWorkload,
				Protocol: strings.ToLower(row.Protocol), Port: row.DstPort,
				L7: strings.ToLower(row.L7Protocol), Verdict: verdict,
				Severity: int(row.Severity), Bytes: row.Bytes, Packets: row.Packets,
				At: row.At.UTC(),
			})
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit: "+err.Error())
		return
	}
	// Commit succeeded — now safe to publish the buffered rows to the hot graph.
	if h.live != nil {
		for i := range pending {
			h.live.Publish(pending[i])
		}
	}
	// A7: flush accumulated per-rule match counters, best-effort and outside the
	// flow-insert tx (already committed) so a stats write can never roll back
	// accepted flows. A failure here is telemetry loss, not data loss.
	for cluster, hits := range ruleHits {
		if err := h.matches.RecordMatches(r.Context(), tok.OrgID, cluster, hits); err != nil {
			slog.Default().Warn("network_rule_match_stats upsert failed",
				slog.String("err", err.Error()), slog.String("cluster", cluster.String()))
		}
	}
	slog.Default().Debug("network_flows ingest",
		slog.Int("accepted", accepted), slog.Int("rejected", rejected),
		slog.Int("rule_matches", ruleMatches),
		slog.Int("nbe_flagged", nbeFlagged),
		slog.String("org", tok.OrgID.String()))

	httpx.WriteJSON(w, http.StatusOK, FlowIngestResponse{
		Accepted: accepted, Rejected: rejected,
		RuleMatches: ruleMatches, NBEFlagged: nbeFlagged, NBEDenied: nbeDenied,
	})
}
