// Wave 4: convert dp connection events to flowIngestRow.
//
// dp emits one DPMsgConnect per (EPMAC, client_ip, server_ip, server_port,
// ip_proto, policy_id) bucket every report cycle. Each event carries real
// on-wire byte / session counts, dp's L7 app id from DPI parsers, and the
// policy verdict the dp engine attached. We translate that into the wire
// shape /api/v1/network-flows:bulk accepts, plus the workload-name
// heuristics the existing pipeline uses for in-cluster vs external
// destinations. The server-side ingest handler does the final
// "cluster/<ip>" → "<ns>/<deployment>" resolution via pod_ips/services
// tables (handler/network_flows_ingest.go).
package main

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// flowIngestRow is the wire shape sent to POST /api/v1/network-flows:bulk.
// Mirrors handler.FlowIngestRow exactly — keep field tags in lockstep.
//
// All meaningful fields are dp-sourced (Wave 4+): ClientBytes/ServerBytes for
// real on-wire byte counts per direction, Sessions for the per-bucket session
// count, Application for dp's DPI L7 id, PolicyAction + PolicyID for the
// policy verdict, ThreatID + Severity when a signature fired, EPMAC for
// workload attribution. The legacy Bytes/Packets columns stay for back-compat
// with the existing UI queries; we populate Bytes = client+server and Packets
// = sessions (lower bound) so SUM(bytes) and SUM(packets) keep working.
type flowIngestRow struct {
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

	ClientBytes  int64  `json:"client_bytes,omitempty"`
	ServerBytes  int64  `json:"server_bytes,omitempty"`
	Sessions     int64  `json:"sessions,omitempty"`
	Application  uint32 `json:"application,omitempty"`
	PolicyAction string `json:"policy_action,omitempty"`
	PolicyID     uint32 `json:"policy_id,omitempty"`
	ThreatID     uint32 `json:"threat_id,omitempty"`
	Severity     uint8  `json:"severity,omitempty"`
	EPMAC        string `json:"ep_mac,omitempty"`
	Source       string `json:"source,omitempty"`

	// XFFReattributed marks a flow whose peer (client) was re-pointed from an
	// envoy/linkerd sidecar hop to the real X-Forwarded-For origin (A6). The
	// server may ignore this hint; it exists so the UI can badge collapsed
	// mesh flows and so tests can assert the re-attribution fired.
	XFFReattributed bool `json:"xff_reattributed,omitempty"`

	// Fqdn is the destination DNS name for an egress-to-external flow (F1).
	// Only the Hubble lane populates it (from observer.Flow.destination_names);
	// the dp/bpf lanes leave it empty.
	Fqdn string `json:"fqdn,omitempty"`
}

// dpConnToFlowIngest builds a flowIngestRow from a single dp connection event.
// `node` is the agent's CONSTELLATION_NODE_NAME. `session` is an optional
// matching DPMsgSession (Wave C1) — when supplied, ClientBytes/ServerBytes
// are populated from its directional counters instead of being collapsed
// into ClientBytes. When session is nil we fall back to the legacy
// "total in client_bytes" behavior.
func dpConnToFlowIngest(ev dp.Event, node string, session *dp.Session) flowIngestRow {
	c := ev.Conn
	row := flowIngestRow{
		Protocol:    ipProtoToString(c.IPProto),
		L7Protocol:  dpAppToL7(c.Application),
		Bytes:       int64(c.Bytes),
		Sessions:    int64(c.Sessions),
		Application: uint32(c.Application),
		PolicyID:    c.PolicyID,
		ThreatID:    c.ThreatID,
		Severity:    c.Severity,
		EPMAC:       c.EPMAC.String(),
		Source:      "dp",
		At:          ev.At,
	}

	// Wave C1: prefer the session-cache's directional split. DPMsgConnect
	// only carries one summed Bytes field (dp/ctrl.c:2693 sums client +
	// server before emit); DPMsgSession carries them separately. If the
	// supervisor's session-list poll has seen this 5-tuple in the last
	// poll cycle, use that wing-split. Otherwise fall back to the legacy
	// "everything in ClientBytes" so the column is populated either way.
	if session != nil {
		row.ClientBytes = int64(session.ClientBytes)
		row.ServerBytes = int64(session.ServerBytes)
		// If dp aggregated MORE bytes between session-cache refresh and
		// the connect emit, the agg counter wins for the legacy Bytes
		// total — but we trust the session for the split shape.
		if int64(c.Bytes) < row.ClientBytes+row.ServerBytes {
			row.Bytes = row.ClientBytes + row.ServerBytes
		}
	} else {
		row.ClientBytes = int64(c.Bytes)
	}

	// Policy verdict — the API treats this as the row's verdict label too,
	// so callers can filter by policy_action OR verdict.
	row.PolicyAction = dp.PolicyActionString(c.PolicyAction)
	row.Verdict = row.PolicyAction

	// Endpoint addresses. dp reports both ClientIP and ServerIP in network
	// order; ServerPort is the listening port (always populated), ClientPort
	// is the ephemeral port (only set when meaningful, eg. for DNS tunneling
	// detection — see dp/ctrl.c:2706).
	clientIP := c.ClientIP.String()
	serverIP := c.ServerIP.String()
	row.SrcAddr = clientIP
	row.DstAddr = serverIP
	if c.ClientPort != 0 {
		row.SrcPort = int(c.ClientPort)
	}
	if c.ServerPort != 0 {
		row.DstPort = int(c.ServerPort)
	}

	// A6: sidecar / service-mesh XFF re-attribution. When dp flagged this
	// conversation as a mesh-to-server / X-Forwarded-For hop, the client we
	// see on the wire is the in-pod envoy/linkerd proxy, NOT the real remote
	// client. If the matching session carries the forwarded-for origin, collapse
	// the proxy hop and re-point the peer to the true client. This mirrors
	// NeuVector agent/timer.go updateSidecarConnection + the connect_ingress
	// ClientWL collapse (there the LOCAL side is re-pointed to the pod; here we
	// re-point the PEER side to the real client the sidecar forwarded for).
	//
	// Ingress-only: XFF is meaningful when the local workload is the SERVER
	// receiving a proxied request. dp's g_xff_enabled defaults OFF (ctrl.c),
	// so this consumer is dormant until XFF is turned on in the data plane —
	// it never fabricates a client when the origin is absent.
	if xff := reattributeXFF(c, session); xff.Applied && c.Ingress {
		clientIP = xff.ClientIP
		row.SrcAddr = clientIP
		row.XFFReattributed = true
		if xff.ClientPort != 0 {
			row.SrcPort = int(xff.ClientPort)
		}
		if xff.L7 != "" {
			row.L7Protocol = xff.L7
		}
	}

	// Direction. dp's `Ingress` flag means "the workload is the server" — ie.
	// inbound to the pod. When Ingress, the workload is the server side
	// (dst_workload); otherwise the workload is the client side (src_workload).
	//
	// Wave 8a: workload identity is the WORKLOAD'S OWN IP, wrapped as
	// "cluster/<ip>". The server-side ingest handler already runs an
	// ipResolver against pod_ips → "<ns>/<deployment>" (populated by the
	// constellation-discoverer); using the IP as the label lights that path
	// up for the workload side too — closes the gap where MAC-based labels
	// never resolved. ep_mac is preserved as a separate column for forensics
	// and for the threat-attribution join.
	//
	// Host-network case (#7): a host-network pod has no pod IP of its own — it
	// shares the node's InternalIP. Labeling that as "cluster/<node-ip>" makes
	// the server resolve it to the NODE, so every host-network pod on the node
	// collapses to one indistinguishable "node" workload. classifyWorkload
	// detects the node's own IP (nodeSelfIPs) and prefers the endpoint MAC so
	// distinct host-network pods stay separate. The peer-side classification is
	// unchanged from Wave 4.
	var workloadIP string
	if c.Ingress {
		workloadIP = serverIP
	} else {
		workloadIP = clientIP
	}
	workloadID := classifyWorkload(workloadIP, c.EPMAC, node, nodeSelfIPs)
	peerLabel := classifyPeer(serverIP, clientIP, c.Ingress)

	if c.Ingress {
		// Workload is the server (receiving). Peer is the client.
		row.SrcWorkload = peerLabel
		row.DstWorkload = workloadID
	} else {
		// Workload is the client (initiating). Peer is the server.
		row.SrcWorkload = workloadID
		row.DstWorkload = peerLabel
	}

	return row
}

// classifyWorkload builds a stable label for the local-pod side of a flow.
// Preference order:
//
//  1. "cluster/<ip>" when the workload's own IP is private AND is not one of
//     the node's own addresses — the server's ipResolver maps it to
//     "<ns>/<deployment>" via the pod_ips table constellation-discoverer keeps
//     fresh.
//  2. "node-local/<mac>" when we have an EPMAC but no pod-distinguishing IP —
//     either no usable IP at all, or a host-network pod whose IP is the node's
//     own (#7). Using the endpoint MAC keeps distinct host-network pods apart
//     instead of collapsing them all onto the node.
//  3. "node/<name>" as the final fallback so the row always has provenance.
//
// nodeIPs is the set of addresses that belong to this node's own netns; a
// workload IP found there is the host-network case, not a real pod IP.
func classifyWorkload(workloadIP string, epmac net.HardwareAddr, node string, nodeIPs map[string]bool) string {
	if workloadIP != "" {
		if addr, err := netip.ParseAddr(workloadIP); err == nil && addr.IsValid() &&
			(addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()) {
			// #7 host-network: the workload shares the node's InternalIP, so
			// "cluster/<node-ip>" would resolve to the NODE and merge every
			// host-network pod. Prefer the pod-distinguishing MAC; fall through
			// to node/<name> only when even the MAC is missing.
			if nodeIPs[workloadIP] {
				if epmac != nil {
					return "node-local/" + strings.ReplaceAll(epmac.String(), ":", "")
				}
				return "node/" + node
			}
			return "cluster/" + workloadIP
		}
	}
	if epmac != nil {
		return "node-local/" + strings.ReplaceAll(epmac.String(), ":", "")
	}
	return "node/" + node
}

// nodeSelfIPs is the set of IP addresses in this agent's own network
// namespace, used by classifyWorkload to spot the host-network case (#7). The
// runtime-agent runs as a hostNetwork DaemonSet, so its netns IS the node's —
// net.InterfaceAddrs() therefore returns the node's own addresses (InternalIP,
// loopback, and any CNI/bridge addresses that live on the host).
//
// ponytail: heuristic — scraping local interfaces is the crude signal. It can
// over-match (CNI bridge / secondary host addresses are included, so a flow
// legitimately using such an address gets a node-local label) and under-match
// (if the agent is ever run without hostNetwork it sees the wrong netns). The
// precise-signal upgrade is to match against the node's authoritative
// InternalIP(s) from the cluster inventory (constellation-discoverer's node
// list) once that is plumbed through to the agent, rather than guessing from
// whatever addresses happen to be in the local netns.
var nodeSelfIPs = detectNodeSelfIPs()

func detectNodeSelfIPs() map[string]bool {
	out := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			out[v.IP.String()] = true
		case *net.IPAddr:
			out[v.IP.String()] = true
		}
	}
	return out
}

// ipProtoToString maps the IANA protocol numbers dp reports to the lowercase
// strings the ingest handler expects (and the read query lowercases for
// comparison).
func ipProtoToString(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	default:
		return fmt.Sprintf("ipproto-%d", p)
	}
}

// dpAppToL7 maps dp's APP_* identifiers (third_party/neuvector/dp/apis.h) to
// the canonical lowercase L7 labels the Network Map UI understands. dp's
// values are stable across versions; the IDs come from DPI parser detection.
// Falls back to "" so the UI uses the port-heuristic display name.
func dpAppToL7(app uint16) string {
	switch app {
	case 1001:
		return "http"
	case 1002:
		return "ssl"
	case 1003:
		return "ssh"
	case 1004:
		return "dns"
	case 1005:
		return "dhcp"
	case 1006:
		return "ntp"
	case 1007:
		return "tftp"
	case 1008:
		return "echo"
	case 1009:
		return "rtsp"
	case 1010:
		return "sip"
	case 1011:
		return "mqtt"
	case 1012:
		return "syslog"

	// Database protocols (dp/apis.h ranges).
	case 2001:
		return "mysql"
	case 2002:
		return "redis"
	case 2003:
		return "postgres"
	case 2004:
		return "mongodb"
	case 2005:
		return "kafka"
	case 2006:
		return "couchbase"
	case 2007:
		return "cassandra"
	case 2008:
		return "tns"
	case 2009:
		return "tds"
	case 2010:
		return "zookeeper"
	case 2011:
		return "spark"
	case 2012:
		return "grpc"
	}
	return ""
}

// ethTypeIPv4 is the EtherType dp stamps on IPv4 sessions (defs.h). Used to
// trim the fixed 16-byte XffIP buffer down to its meaningful v4 octets.
const ethTypeIPv4 = 0x0800

// xffReattribution is the result of collapsing a sidecar/mesh hop to the real
// client behind it. Applied is false when the connection is not a mesh hop or
// the forwarded-for origin is unavailable (fail-safe: leave the flow as-is).
type xffReattribution struct {
	Applied    bool
	ClientIP   string
	ClientPort uint16
	L7         string // L7 label from the session's XffApp, "" when unknown
}

// reattributeXFF derives the real client for a sidecar/service-mesh connection.
// dp sets ConnFlagXFF / ConnFlagMeshToSvr on the DPMsgConnect (proto.go) and
// carries the forwarded-for origin (XffIP/XffApp/XffPort) on the DPMsgSession —
// the two are decoded but nothing consumed them until this A6 consumer. When the
// connection is a mesh hop AND a matching session exposes a non-zero XffIP, we
// return that origin so the flow-builder can re-point the peer.
func reattributeXFF(c *dp.Connection, session *dp.Session) xffReattribution {
	if c == nil || (!c.XFF && !c.MeshToSvr) {
		return xffReattribution{}
	}
	if session == nil {
		return xffReattribution{}
	}
	clientIP := xffOriginIP(session)
	if clientIP == "" {
		return xffReattribution{}
	}
	return xffReattribution{
		Applied:    true,
		ClientIP:   clientIP,
		ClientPort: session.XffPort,
		L7:         dpAppToL7(session.XffApp),
	}
}

// xffOriginIP renders the session's forwarded-for origin. proto.decodeSession
// stores XffIP as the raw 16-byte field regardless of family; for IPv4 sessions
// only the low 4 octets are meaningful, so trim them before rendering (otherwise
// net.IP would print a garbage v6 form). Returns "" for an absent/zero origin.
func xffOriginIP(session *dp.Session) string {
	ip := session.XffIP
	if len(ip) == 0 {
		return ""
	}
	if session.EtherType == ethTypeIPv4 && len(ip) >= 4 {
		ip = ip[:4]
	}
	allZero := true
	for _, b := range ip {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	parsed := net.IP(ip)
	if parsed.IsUnspecified() {
		return ""
	}
	return parsed.String()
}

// classifyPeer labels the non-workload side of a dp connection. The peer IP
// is the server when Ingress=false (peer is what the local workload talks to)
// or the client when Ingress=true (peer is what reached the local workload).
//
// The label uses the existing convention: "cluster/<ip>" for RFC1918-private
// IPs (the server-side ingest resolves these into <ns>/<deployment> via
// pod_ips/cluster_services), and "external/<ip>" for everything else (which
// the ingest collapses to a single "external" workload node so the graph
// doesn't sprout one external node per upstream IP).
func classifyPeer(serverIP, clientIP string, ingress bool) string {
	peer := serverIP
	if ingress {
		peer = clientIP
	}
	if peer == "" {
		return "external"
	}
	addr, err := netip.ParseAddr(peer)
	if err != nil || !addr.IsValid() {
		return "external"
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return "cluster/" + peer
	}
	return "external/" + peer
}
