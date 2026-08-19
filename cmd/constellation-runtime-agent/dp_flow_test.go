package main

import (
	"net"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// TestDpConnToFlowIngest_WorkloadResolution covers Wave 8a: the workload
// label is derived from the workload's own IP (server-side IP on ingress,
// client-side IP on egress), wrapped as cluster/<ip> so the server's
// ipResolver lights up. EPMAC stays as a separate column for forensics.
func TestDpConnToFlowIngest_WorkloadResolution(t *testing.T) {
	cases := []struct {
		name       string
		ingress    bool
		clientIP   string
		serverIP   string
		wantSrc    string
		wantDst    string
	}{
		{
			// Ingress: pod (10.42.0.5) is the server. Peer is external (1.2.3.4).
			// Workload label uses the pod's own IP for server-side resolution.
			name:     "ingress from external",
			ingress:  true,
			clientIP: "1.2.3.4",
			serverIP: "10.42.0.5",
			wantSrc:  "external/1.2.3.4",
			wantDst:  "cluster/10.42.0.5",
		},
		{
			// Egress: pod (10.42.0.5) is the client. Peer is in-cluster service.
			name:     "egress to in-cluster service",
			ingress:  false,
			clientIP: "10.42.0.5",
			serverIP: "10.43.0.1",
			wantSrc:  "cluster/10.42.0.5",
			wantDst:  "cluster/10.43.0.1",
		},
		{
			// Egress: pod (10.42.0.5) hitting external service.
			name:     "egress to external",
			ingress:  false,
			clientIP: "10.42.0.5",
			serverIP: "1.1.1.1",
			wantSrc:  "cluster/10.42.0.5",
			wantDst:  "external/1.1.1.1",
		},
	}

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := dp.Event{
				Kind: dp.EventConnection,
				At:   time.Now().UTC(),
				Conn: &dp.Connection{
					EPMAC:    mac,
					IPProto:  6,
					ClientIP: net.ParseIP(tc.clientIP),
					ServerIP: net.ParseIP(tc.serverIP),
					Ingress:  tc.ingress,
				},
			}
			row := dpConnToFlowIngest(ev, "test-node", nil)
			if row.SrcWorkload != tc.wantSrc {
				t.Errorf("SrcWorkload = %q want %q", row.SrcWorkload, tc.wantSrc)
			}
			if row.DstWorkload != tc.wantDst {
				t.Errorf("DstWorkload = %q want %q", row.DstWorkload, tc.wantDst)
			}
			if row.EPMAC != "aa:bb:cc:dd:ee:ff" {
				t.Errorf("EPMAC dropped: %q", row.EPMAC)
			}
		})
	}
}

// TestDpConnToFlowIngest_SessionCacheSplit — Wave C1: when a matching
// session is supplied, ClientBytes/ServerBytes carry the directional split
// instead of the legacy collapse-into-ClientBytes.
func TestDpConnToFlowIngest_SessionCacheSplit(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	ev := dp.Event{
		Kind: dp.EventConnection,
		At:   time.Now().UTC(),
		Conn: &dp.Connection{
			EPMAC:    mac,
			IPProto:  6,
			ClientIP: net.ParseIP("10.42.0.5"),
			ServerIP: net.ParseIP("10.43.0.1"),
			Bytes:    12000,
			Ingress:  false,
		},
	}
	sess := &dp.Session{
		ClientIP:    net.ParseIP("10.42.0.5"),
		ServerIP:    net.ParseIP("10.43.0.1"),
		ClientBytes: 4000,
		ServerBytes: 8000,
	}
	row := dpConnToFlowIngest(ev, "test-node", sess)
	if row.ClientBytes != 4000 {
		t.Errorf("ClientBytes = %d, want 4000", row.ClientBytes)
	}
	if row.ServerBytes != 8000 {
		t.Errorf("ServerBytes = %d, want 8000", row.ServerBytes)
	}
	// Bytes total stays at the connect counter (12000) since 4000+8000=12000
	// exactly matches; no rewrite needed.
	if row.Bytes != 12000 {
		t.Errorf("Bytes = %d, want 12000", row.Bytes)
	}
}

// TestDpConnToFlowIngest_NilSessionFallback — without a session match, the
// agent keeps the legacy "everything in ClientBytes" shape so the column
// stays populated and SUM(bytes) queries still total correctly.
func TestDpConnToFlowIngest_NilSessionFallback(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	ev := dp.Event{
		Kind: dp.EventConnection,
		At:   time.Now().UTC(),
		Conn: &dp.Connection{
			EPMAC:    mac,
			IPProto:  6,
			ClientIP: net.ParseIP("10.42.0.5"),
			ServerIP: net.ParseIP("10.43.0.1"),
			Bytes:    12000,
		},
	}
	row := dpConnToFlowIngest(ev, "test-node", nil)
	if row.ClientBytes != 12000 {
		t.Errorf("legacy fallback ClientBytes = %d, want 12000", row.ClientBytes)
	}
	if row.ServerBytes != 0 {
		t.Errorf("legacy fallback ServerBytes = %d, want 0", row.ServerBytes)
	}
}

// TestClassifyWorkload_Fallbacks covers the priority order: IP > MAC > node,
// plus the #7 host-network case where the workload IP is the node's own IP.
func TestClassifyWorkload_Fallbacks(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	// nodeIPs simulates the node's own addresses (the host-network case).
	nodeIPs := map[string]bool{"10.0.0.1": true}
	cases := []struct {
		name    string
		ip      string
		mac     net.HardwareAddr
		node    string
		nodeIPs map[string]bool
		want    string
	}{
		{"private ip wins", "10.0.0.1", mac, "n1", nil, "cluster/10.0.0.1"},
		{"public ip skipped, mac used", "8.8.8.8", mac, "n1", nil, "node-local/aabbccddeeff"},
		{"no ip, mac used", "", mac, "n1", nil, "node-local/aabbccddeeff"},
		{"no ip no mac, node used", "", nil, "node-1", nil, "node/node-1"},
		{"loopback counts as private", "127.0.0.1", mac, "n1", nil, "cluster/127.0.0.1"},
		// #7: host-network pod shares the node's IP — prefer the MAC so
		// distinct host-network pods don't collapse onto "cluster/<node-ip>".
		{"host-network pod uses mac not node-ip", "10.0.0.1", mac, "n1", nodeIPs, "node-local/aabbccddeeff"},
		// #7: host-network with no MAC falls all the way to node/<name>.
		{"host-network pod no mac uses node", "10.0.0.1", nil, "n1", nodeIPs, "node/n1"},
		// A real pod IP that is NOT the node's own IP stays cluster/<ip>.
		{"real pod ip stays cluster", "10.42.0.7", mac, "n1", nodeIPs, "cluster/10.42.0.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyWorkload(tc.ip, tc.mac, tc.node, tc.nodeIPs)
			if got != tc.want {
				t.Errorf("classifyWorkload(%q,%v,%q) = %q want %q", tc.ip, tc.mac, tc.node, got, tc.want)
			}
		})
	}
}

// wireXffIP builds a DPMsgSession-shaped XffIP for an IPv4 origin: dp places the
// v4 octets in the FIRST 4 bytes of the fixed 16-byte field (proto.decodeSession
// stores the raw buffer), so the trim in xffOriginIP recovers them.
func wireXffIP(v4 string) net.IP {
	ip := make(net.IP, 16)
	copy(ip, net.ParseIP(v4).To4())
	return ip
}

// TestReattributeXFF_PureDecision exercises the A6 sidecar/mesh collapse guard.
func TestReattributeXFF_PureDecision(t *testing.T) {
	origin := wireXffIP("203.0.113.7")

	// Not a mesh hop -> no re-attribution regardless of session contents.
	if got := reattributeXFF(&dp.Connection{}, &dp.Session{EtherType: 0x0800, XffIP: origin}); got.Applied {
		t.Fatalf("non-mesh conn should not re-attribute: %+v", got)
	}
	// Mesh hop but nil session -> not applied (fail-safe).
	if got := reattributeXFF(&dp.Connection{MeshToSvr: true}, nil); got.Applied {
		t.Fatalf("nil session should not re-attribute: %+v", got)
	}
	// Mesh hop but zero XffIP -> not applied.
	if got := reattributeXFF(&dp.Connection{XFF: true}, &dp.Session{EtherType: 0x0800, XffIP: make(net.IP, 16)}); got.Applied {
		t.Fatalf("zero xff ip should not re-attribute: %+v", got)
	}
	// Mesh hop + valid origin -> applied, with port + L7 carried through.
	got := reattributeXFF(&dp.Connection{MeshToSvr: true}, &dp.Session{
		EtherType: 0x0800, XffIP: origin, XffPort: 44321, XffApp: 1001, // 1001 == http
	})
	if !got.Applied || got.ClientIP != "203.0.113.7" || got.ClientPort != 44321 || got.L7 != "http" {
		t.Fatalf("expected applied http re-attribution, got %+v", got)
	}
}

// TestDpConnToFlowIngest_XFFReattribution proves the flow-builder collapses an
// ingress envoy/linkerd hop to the real client behind X-Forwarded-For.
func TestDpConnToFlowIngest_XFFReattribution(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	ev := dp.Event{
		Kind: dp.EventConnection,
		At:   time.Now().UTC(),
		Conn: &dp.Connection{
			EPMAC:      mac,
			IPProto:    6,
			ClientIP:   net.ParseIP("10.42.0.9"), // the in-pod sidecar proxy
			ServerIP:   net.ParseIP("10.42.0.5"), // the local workload (server)
			ServerPort: 8080,
			Ingress:    true,
			MeshToSvr:  true,
		},
	}
	sess := &dp.Session{
		EtherType: 0x0800,
		ClientIP:  net.ParseIP("10.42.0.9"),
		ServerIP:  net.ParseIP("10.42.0.5"),
		XffIP:     wireXffIP("198.51.100.23"), // the real remote client
		XffPort:   51999,
	}
	row := dpConnToFlowIngest(ev, "test-node", sess)
	if !row.XFFReattributed {
		t.Fatalf("expected XFFReattributed=true, row=%+v", row)
	}
	if row.SrcAddr != "198.51.100.23" {
		t.Errorf("SrcAddr = %q, want the XFF origin 198.51.100.23", row.SrcAddr)
	}
	if row.SrcPort != 51999 {
		t.Errorf("SrcPort = %d, want 51999", row.SrcPort)
	}
	// The peer (src workload) must now classify from the real client, not the
	// sidecar's cluster IP.
	if row.SrcWorkload != "external/198.51.100.23" {
		t.Errorf("SrcWorkload = %q, want external/198.51.100.23", row.SrcWorkload)
	}
}
