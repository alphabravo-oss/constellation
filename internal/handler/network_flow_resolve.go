// Cross-domain L4 network-flow ingest plumbing: the row wire-shape plus the
// per-request IP resolver. This stays in the parent `handler`
// package because it is shared by two domains — the netpolicy ingest handler
// (handler/netpolicy.NetworkFlowsIngest.Bulk) and the runtime threat-ingest
// handler (runtime_threats_ingest.go). The netpolicy sub-package consumes it
// through the exported seams at the bottom of this file; the parent
// runtime_threats path keeps using the unexported originals unchanged.
package handler

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
)

// FlowIngestRow is the wire shape sent by the runtime-agent. Field names are
// snake_case and stable — the agent's main.go emits exactly these keys.
//
// The agent doesn't know its cluster_id; the server derives it from the
// runtime-agent token's resolved cluster binding.
//
// Wave 4: dp-sourced rows additionally populate ClientBytes/ServerBytes (the
// per-direction byte counts from DPMsgConnect), Sessions (count of distinct
// 5-tuples aggregated into this bucket), Application (dp's L7 app id),
// PolicyAction / PolicyID (dp's policy verdict), ThreatID / Severity (set
// when a signature fired), EPMAC (the workload's veth MAC, used for
// attribution), and Source ("dp" for real, "bpf" for the legacy synthetic
// path). Legacy BPF callers may omit all of these; rows then land with
// NULL values and the read query handles that.
type FlowIngestRow struct {
	SrcWorkload string    `json:"src_workload"`
	DstWorkload string    `json:"dst_workload"`
	SrcAddr     string    `json:"src_addr,omitempty"`
	SrcPort     int       `json:"src_port,omitempty"`
	DstAddr     string    `json:"dst_addr,omitempty"`
	DstPort     int       `json:"dst_port,omitempty"`
	Protocol    string    `json:"protocol"`
	L7Protocol  string    `json:"l7_protocol,omitempty"`
	Bytes       int64     `json:"bytes,omitempty"`
	Packets     int64     `json:"packets,omitempty"`
	Verdict     string    `json:"verdict,omitempty"`
	At          time.Time `json:"at"`

	// Wave 4 (dp-sourced) extensions. Zero values mean "not reported".
	ClientBytes  int64  `json:"client_bytes,omitempty"`
	ServerBytes  int64  `json:"server_bytes,omitempty"`
	Sessions     int64  `json:"sessions,omitempty"`
	Application  uint32 `json:"application,omitempty"`
	PolicyAction string `json:"policy_action,omitempty"`
	PolicyID     uint32 `json:"policy_id,omitempty"`
	ThreatID     uint32 `json:"threat_id,omitempty"`
	Severity     uint8  `json:"severity,omitempty"`
	EPMAC        string `json:"ep_mac,omitempty"`

	// Fqdn is the destination DNS name observed for an egress-to-external flow
	// (F1). Set by the runtime-agent from Cilium Hubble flow destination_names;
	// empty for in-cluster / ingress flows and for the legacy bpf/dp paths.
	// Persisted into network_flows.fqdn and read back by the policy generator,
	// which anchors the egress allow rule to a Cilium toFQDNs selector.
	Fqdn string `json:"fqdn,omitempty"`

	// Source declares row provenance: "dp" (real, from NeuVector dp) or
	// "bpf" (synthetic, from the legacy BPF connect-event aggregator).
	// Empty defaults to "bpf" so older agents keep landing in the same bucket.
	Source string `json:"source,omitempty"`
}

// FlowIngestRequest is the wire shape POST'd: a JSON array (envelope-less so
// the agent can stream-encode in one pass).
type FlowIngestRequest = []FlowIngestRow

// ---------------------------------------------------------------------------
// Wave M2: batched IP -> workload resolution
//
// ipResolver is built once per request body. Up front it collects every
// distinct address that appears in src_addr or dst_addr (and every IP
// embedded in a "cluster/<ip>" workload label) and runs two batched SELECTs
// against pod_ips + cluster_services. The per-row resolve() call is then a
// pure map lookup with no DB round-trips.
//
// Lookup precedence:
//  1. Well-known IP table (well_known_ips.go)        - loopback / metadata / CGNAT / multicast / link-local
//  2. pod_ips                                        - "<ns>/<deployment>"
//  3. cluster_services                               - "<ns>/<service>"
//  4. Original label (e.g. "cluster/10.42.0.4")      - fallback
//
// "cluster/<ip>" labels are recognized and unwrapped so the IP behind them
// can also be resolved.
//
// Migration 117 made pod_ips (and, since 036, cluster_services) history-
// retaining: a single IP can have MULTIPLE rows over time, one per pod/service
// generation, each stamped with [first_seen_at, last_seen_at]. So we key each
// IP to a *slice* of ipCandidate windows and let resolve() time-bracket on the
// flow's timestamp instead of trusting a single (now-ambiguous) IP->label map.
type ipResolver struct {
	db    *db.DB
	orgID uuid.UUID
	pods  map[string][]ipCandidate // key: addr.String() -> "<ns>/<deployment>" generations
	svcs  map[string][]ipCandidate // key: addr.String() -> "<ns>/<svc-name>" generations
}

// ipCandidate is one historical binding of an IP to a workload label, valid for
// the half-open-ish window [firstSeen, lastSeen + grace]. resolve() picks the
// candidate whose window contains the flow's time.
type ipCandidate struct {
	label     string
	firstSeen time.Time
	lastSeen  time.Time
}

// resolveGrace extends a candidate's lastSeen so a flow observed slightly after
// the discoverer last saw the pod (clock skew / sweep lag) still matches.
const resolveGrace = 5 * time.Minute

// pickCandidate returns the label whose [firstSeen, lastSeen+grace] window
// brackets `at`. If none brackets it, it falls back (best-effort) to the
// candidate with the most recent lastSeen. Returns ("", false) only when there
// are no candidates at all.
func pickCandidate(cands []ipCandidate, at time.Time) (string, bool) {
	if len(cands) == 0 {
		return "", false
	}
	for _, c := range cands {
		if !at.Before(c.firstSeen) && !at.After(c.lastSeen.Add(resolveGrace)) {
			return c.label, true
		}
	}
	best := cands[0]
	for _, c := range cands[1:] {
		if c.lastSeen.After(best.lastSeen) {
			best = c
		}
	}
	return best.label, true
}

func newIPResolverForCluster(ctx context.Context, d *db.DB, orgID, clusterID uuid.UUID, rows FlowIngestRequest) *ipResolver {
	r := &ipResolver{db: d, orgID: orgID, pods: map[string][]ipCandidate{}, svcs: map[string][]ipCandidate{}}
	seen := map[string]struct{}{}
	add := func(s string) {
		if s == "" {
			return
		}
		if a, ok := normalizeIP(s); ok {
			seen[a] = struct{}{}
		}
	}
	for i := range rows {
		row := &rows[i]
		add(row.SrcAddr)
		add(row.DstAddr)
		add(extractClusterIP(row.SrcWorkload))
		add(extractClusterIP(row.DstWorkload))
	}
	if len(seen) == 0 {
		return r
	}
	ips := make([]string, 0, len(seen))
	for ip := range seen {
		ips = append(ips, ip)
	}
	// pod_ips: one row per (pod generation, ip) since migration 117. Collect
	// every generation's window so resolve() can time-bracket.
	if rs, err := d.Pool().Query(ctx, `
SELECT host(ip), namespace, COALESCE(deployment, pod_name), first_seen_at, last_seen_at
  FROM pod_ips
 WHERE org_id = $1 AND ip = ANY($2::inet[])
   AND cluster_id = $3`, orgID, ips, clusterID); err == nil {
		defer rs.Close()
		for rs.Next() {
			var ip, ns, name string
			var firstSeen, lastSeen time.Time
			if err := rs.Scan(&ip, &ns, &name, &firstSeen, &lastSeen); err == nil {
				if a, ok := normalizeIP(ip); ok {
					r.pods[a] = append(r.pods[a], ipCandidate{label: ns + "/" + name, firstSeen: firstSeen, lastSeen: lastSeen})
				}
			}
		}
	} else {
		slog.Default().Warn("resolve pod_ips", slog.String("err", err.Error()))
	}
	// cluster_services: also history-retaining (first_seen_at/last_seen_at from
	// migration 036), so time-bracket its ClusterIP generations too.
	if rs, err := d.Pool().Query(ctx, `
SELECT host(cluster_ip), namespace, name, first_seen_at, last_seen_at
  FROM cluster_services
 WHERE org_id = $1 AND cluster_ip = ANY($2::inet[])
   AND cluster_id = $3`, orgID, ips, clusterID); err == nil {
		defer rs.Close()
		for rs.Next() {
			var ip, ns, name string
			var firstSeen, lastSeen time.Time
			if err := rs.Scan(&ip, &ns, &name, &firstSeen, &lastSeen); err == nil {
				if a, ok := normalizeIP(ip); ok {
					r.svcs[a] = append(r.svcs[a], ipCandidate{label: ns + "/" + name, firstSeen: firstSeen, lastSeen: lastSeen})
				}
			}
		}
	} else {
		slog.Default().Warn("resolve cluster_services", slog.String("err", err.Error()))
	}
	return r
}

// resolve maps a (workload, addr) pair to its best-known label as of flow time
// `at`. nodeHint is the *source* workload of the flow, used so loopback
// observed on a node can be attributed to that node rather than a generic
// "node-local/loopback" label. `at` selects the pod/service generation whose
// [first_seen_at, last_seen_at + grace] window brackets the flow (see
// pickCandidate) — correct across pod churn and IP reuse.
func (r *ipResolver) resolve(workload, addr, nodeHint string, at time.Time) (string, bool) {
	candidate := addr
	if candidate == "" {
		candidate = extractClusterIP(workload)
	}
	if candidate == "" {
		return workload, false
	}
	key, ok := normalizeIP(candidate)
	if !ok {
		return workload, false
	}
	if parsed, err := netip.ParseAddr(key); err == nil {
		nodeName := ""
		if strings.HasPrefix(nodeHint, "node/") {
			nodeName = nodeHint[len("node/"):]
		}
		if label, isWellKnown := lookupWellKnown(parsed, nodeName); isWellKnown {
			return label, true
		}
	}
	if v, ok := pickCandidate(r.pods[key], at); ok {
		return v, true
	}
	if v, ok := pickCandidate(r.svcs[key], at); ok {
		return v, true
	}
	return workload, false
}

// extractClusterIP returns the IP from a "cluster/<ip>" workload label or "".
func extractClusterIP(workload string) string {
	if !strings.HasPrefix(workload, "cluster/") {
		return ""
	}
	return workload[len("cluster/"):]
}

// normalizeIP canonicalizes a string IP (strips zone, expands IPv4 mapped) so
// map keys agree across input formats. Returns the canonical string and ok.
func normalizeIP(s string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	return a.WithZone("").String(), true
}

// ---------------------------------------------------------------------------
// Exported seams for the handler/netpolicy sub-package.
//
// The netpolicy ingest handler lives in a sub-package that imports `handler`
// (for the Subject/runtime-agent-token seams), so `handler` must not import it
// back. These thin exported wrappers let netpolicy.NetworkFlowsIngest.Bulk
// drive the same resolver subsystem without duplicating it.

// IPResolver is the exported alias of the per-request batched IP->workload
// resolver used by the netpolicy ingest handler.
type IPResolver = ipResolver

// NewIPResolverForCluster resolves IPs only within the reporting cluster.
func NewIPResolverForCluster(ctx context.Context, d *db.DB, orgID, clusterID uuid.UUID, rows FlowIngestRequest) *IPResolver {
	return newIPResolverForCluster(ctx, d, orgID, clusterID, rows)
}

// Resolve maps a (workload, addr) pair to its best-known label as of flow time
// `at` (the flow row's timestamp), selecting the correct pod/service
// generation for a reused IP.
func (r *ipResolver) Resolve(workload, addr, nodeHint string, at time.Time) (string, bool) {
	return r.resolve(workload, addr, nodeHint, at)
}
