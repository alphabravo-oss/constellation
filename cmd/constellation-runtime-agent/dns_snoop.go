// FQDN egress, part 2: the production feeder for dp's FQDN resolver.
//
// dp matches FQDN-anchored egress rules by resolved IP, so the agent has to
// teach dp which IPs each allowed name currently maps to. The resolver
// (internal/runtime/dp) learns those mappings from snooped DNS responses via
// Supervisor.FeedDNS — but nothing fed it, so dp's FQDN→IP table stayed empty
// and FQDN rules never matched.
//
// This file holds the portable, unit-tested core: parse a captured IP packet,
// pull out a UDP/53 DNS payload, and run it through a dpi.Engine whose sink
// forwards parsed DNS responses to Supervisor.FeedDNS. The platform-specific
// packet source (AF_PACKET on Linux) lives in dns_snoop_linux.go.
package main

import (
	"encoding/binary"
	"net/netip"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
	"github.com/alphabravocompany/constellation/internal/runtime/dpi"
)

// newDNSSnoopEngine builds a dpi.Engine whose sink forwards every parsed DNS
// response to the supervisor's FQDN resolver. Non-response DNS and non-DNS L7
// events are dropped.
func newDNSSnoopEngine(dpSup *dp.Supervisor) *dpi.Engine {
	return dpi.NewEngine(func(ev dpi.L7Event) {
		if ev.DNS != nil && ev.DNS.Response {
			dpSup.FeedDNS(ev.DNS)
		}
	})
}

// feedDNSPacket extracts a DNS payload from one captured network-layer packet
// (IPv4 or IPv6, no link header — i.e. AF_PACKET SOCK_DGRAM data) and, when the
// packet is UDP to/from port 53, runs it through the engine. Returns true when a
// DNS payload was dispatched. Pure apart from the engine call, so it's testable
// without any sockets.
func feedDNSPacket(engine *dpi.Engine, ipPacket []byte) bool {
	flow, payload, dir, ok := extractDNSPayload(ipPacket)
	if !ok {
		return false
	}
	engine.Process(flow, dir, payload)
	return true
}

// extractDNSPayload parses an IPv4/IPv6 + UDP packet and, when either endpoint
// is port 53, returns the UDP payload plus a dpi.Flow describing the
// conversation. dir is DirResponse when the source port is 53 (server → client)
// and DirRequest otherwise. For IPv6 we walk the extension-header chain to find
// the UDP header; non-UDP packets are ignored — DNS over UDP is the path that
// feeds the resolver.
func extractDNSPayload(ip []byte) (dpi.Flow, []byte, dpi.Direction, bool) {
	if len(ip) < 1 {
		return dpi.Flow{}, nil, 0, false
	}
	var (
		srcAddr, dstAddr netip.Addr
		l4               []byte
	)
	switch ip[0] >> 4 {
	case 4:
		if len(ip) < 20 {
			return dpi.Flow{}, nil, 0, false
		}
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl {
			return dpi.Flow{}, nil, 0, false
		}
		if ip[9] != 17 { // UDP
			return dpi.Flow{}, nil, 0, false
		}
		srcAddr = netip.AddrFrom4([4]byte(ip[12:16]))
		dstAddr = netip.AddrFrom4([4]byte(ip[16:20]))
		l4 = ip[ihl:]
	case 6:
		if len(ip) < 40 {
			return dpi.Flow{}, nil, 0, false
		}
		srcAddr = netip.AddrFrom16([16]byte(ip[8:24]))
		dstAddr = netip.AddrFrom16([16]byte(ip[24:40]))
		// Walk the IPv6 extension-header chain to locate the UDP header. We
		// handle the common Hop-by-Hop / Routing / Fragment / Destination-
		// Options next-header links; anything else (ESP, AH, or an upper-layer
		// that isn't UDP) ends the walk. A truncated header fails the bounds
		// check and we fall back to "no DNS payload" gracefully.
		l4start, ok := ipv6UDPOffset(ip)
		if !ok {
			return dpi.Flow{}, nil, 0, false
		}
		l4 = ip[l4start:]
	default:
		return dpi.Flow{}, nil, 0, false
	}

	if len(l4) < 8 {
		return dpi.Flow{}, nil, 0, false
	}
	srcPort := binary.BigEndian.Uint16(l4[0:2])
	dstPort := binary.BigEndian.Uint16(l4[2:4])
	if srcPort != 53 && dstPort != 53 {
		return dpi.Flow{}, nil, 0, false
	}
	payload := l4[8:]
	if len(payload) == 0 {
		return dpi.Flow{}, nil, 0, false
	}
	dir := dpi.DirRequest
	if srcPort == 53 {
		dir = dpi.DirResponse
	}
	flow := dpi.Flow{
		Src:      netip.AddrPortFrom(srcAddr, srcPort),
		Dst:      netip.AddrPortFrom(dstAddr, dstPort),
		Protocol: "udp",
	}
	return flow, payload, dir, true
}

// ipv6UDPOffset walks the IPv6 extension-header chain starting at the fixed
// 40-byte header's Next Header field and returns the byte offset of the UDP
// header, or (0,false) if the packet doesn't carry UDP or is truncated.
//
// Extension headers we traverse (RFC 8200 §4): Hop-by-Hop (0), Routing (43)
// and Destination Options (60) are TLV headers whose length is
// (Hdr Ext Len + 1) * 8 bytes; the Fragment header (44) is a fixed 8 bytes.
// A non-first fragment carries no L4 header, so we stop there. Every step
// strictly advances the offset, so the loop always terminates.
func ipv6UDPOffset(ip []byte) (int, bool) {
	const udp = 17
	nextHdr := ip[6]
	off := 40
	for nextHdr != udp {
		switch nextHdr {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if off+2 > len(ip) {
				return 0, false
			}
			nextHdr = ip[off]
			off += (int(ip[off+1]) + 1) * 8
		case 44: // Fragment header — fixed 8 bytes
			if off+8 > len(ip) {
				return 0, false
			}
			// Only the first fragment (offset 0) holds the UDP header.
			fragOff := (uint16(ip[off+2])<<8 | uint16(ip[off+3])) &^ uint16(0x0007)
			if fragOff != 0 {
				return 0, false
			}
			nextHdr = ip[off]
			off += 8
		default:
			// ESP/AH/upper-layer that isn't UDP — nothing to feed the resolver.
			return 0, false
		}
		if off > len(ip) {
			return 0, false
		}
	}
	return off, true
}
