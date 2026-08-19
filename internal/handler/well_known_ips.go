// Wave M2: classify well-known IPs the BPF agent observes so the Network Map
// never shows raw addresses for them.
//
// Used at the head of the resolver chain in network_flows_ingest.go (Bulk):
// before consulting pod_ips / cluster_services, the resolver asks
// lookupWellKnown() — if it returns isWellKnown=true the resolver uses the
// returned label verbatim. Anything not in this map falls through to the
// database lookups.
//
// Mappings (per spec):
//   127.0.0.0/8, ::1            -> node/<nodeName>  (or node-local/loopback)
//   169.254.169.254             -> external/cloud-metadata
//   100.64.0.0/10               -> external/cgnat-<addr>      (CGNAT carrier-grade NAT)
//   224.0.0.251                 -> multicast/mdns
//   224.0.0.0/4                 -> multicast/<addr>
//   fe80::/10                   -> link-local/<addr>
package handler

import (
	"net/netip"
)

// lookupWellKnown returns a workload label and a flag indicating whether the
// addr matches a well-known classification. nodeName is the source/destination
// node hint (e.g. taken from the agent's src_workload like "node/<n>") so
// loopback traffic can be attributed to the right host; pass "" if unknown.
func lookupWellKnown(addr netip.Addr, nodeName string) (workload string, isWellKnown bool) {
	if !addr.IsValid() {
		return "", false
	}

	// Loopback (127/8, ::1). Bind to the host node when we know it; otherwise
	// fall back to a generic loopback label so the UI still gets a non-IP node.
	if addr.IsLoopback() {
		if nodeName != "" {
			return "node/" + nodeName, true
		}
		return "node-local/loopback", true
	}

	// mDNS first so it takes precedence over the broader multicast range.
	mdns := netip.MustParseAddr("224.0.0.251")
	if addr == mdns {
		return "multicast/mdns", true
	}

	// Cloud-instance metadata service (AWS/GCP/Azure all use this address).
	metadata := netip.MustParseAddr("169.254.169.254")
	if addr == metadata {
		return "external/cloud-metadata", true
	}

	// Multicast (224/4 IPv4, ff00::/8 IPv6).
	if addr.IsMulticast() {
		return "multicast/" + addr.String(), true
	}

	// CGNAT: 100.64.0.0/10. RFC 6598 carrier-grade NAT — frequently used by
	// service meshes (Cilium/Tailscale) too, so we preserve the address.
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	if cgnat.Contains(addr) {
		return "external/cgnat-" + addr.String(), true
	}

	// IPv6 link-local fe80::/10.
	if addr.IsLinkLocalUnicast() {
		return "link-local/" + addr.String(), true
	}

	return "", false
}
