package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// buildDNSResponse builds a minimal DNS response for `name` → one A record.
func buildDNSResponse(name string, ip net.IP) []byte {
	var buf bytes.Buffer
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:], 0x4242)
	binary.BigEndian.PutUint16(hdr[2:], 0x8180) // QR=1 response
	binary.BigEndian.PutUint16(hdr[4:], 1)      // qdcount
	binary.BigEndian.PutUint16(hdr[6:], 1)      // ancount
	buf.Write(hdr)
	writeName := func(n string) {
		for _, lbl := range bytes.Split([]byte(n), []byte(".")) {
			buf.WriteByte(byte(len(lbl)))
			buf.Write(lbl)
		}
		buf.WriteByte(0)
	}
	writeName(name)
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QTYPE A
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QCLASS IN
	// Answer
	writeName(name)
	binary.Write(&buf, binary.BigEndian, uint16(1))  // type A
	binary.Write(&buf, binary.BigEndian, uint16(1))  // class IN
	binary.Write(&buf, binary.BigEndian, uint32(60)) // ttl
	v4 := ip.To4()
	binary.Write(&buf, binary.BigEndian, uint16(len(v4)))
	buf.Write(v4)
	return buf.Bytes()
}

// wrapUDPv4 wraps an L7 payload in IPv4 + UDP headers with the given ports.
func wrapUDPv4(srcPort, dstPort uint16, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)

	ip := make([]byte, 20+len(udp))
	ip[0] = 0x45 // v4, ihl=5
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	ip[8] = 64 // ttl
	ip[9] = 17 // UDP
	copy(ip[12:16], net.ParseIP("10.0.0.10").To4())
	copy(ip[16:20], net.ParseIP("10.0.0.20").To4())
	copy(ip[20:], udp)
	return ip
}

func TestExtractDNSPayload(t *testing.T) {
	dns := buildDNSResponse("example.com", net.ParseIP("93.184.216.34"))
	pkt := wrapUDPv4(53, 40000, dns)

	flow, payload, dir, ok := extractDNSPayload(pkt)
	if !ok {
		t.Fatalf("expected DNS payload extracted")
	}
	if dir != 0 /* DirRequest */ && dir != 1 /* DirResponse */ {
		t.Fatalf("unexpected dir %d", dir)
	}
	if flow.Src.Port() != 53 {
		t.Fatalf("src port = %d, want 53", flow.Src.Port())
	}
	if !bytes.Equal(payload, dns) {
		t.Fatalf("payload mismatch")
	}

	// Non-port-53 UDP must be ignored.
	if _, _, _, ok := extractDNSPayload(wrapUDPv4(40000, 8080, dns)); ok {
		t.Fatalf("non-53 packet should not extract")
	}
	// Truncated / junk packets must not panic and must report not-ok.
	if _, _, _, ok := extractDNSPayload([]byte{0x45, 0x00}); ok {
		t.Fatalf("truncated packet should not extract")
	}
	if _, _, _, ok := extractDNSPayload(nil); ok {
		t.Fatalf("nil packet should not extract")
	}
}

func TestFeedDNSPacketUpdatesResolver(t *testing.T) {
	sup := dp.New(dp.Options{})
	sup.SetAllowedFqdns([]string{"example.com"})

	engine := newDNSSnoopEngine(sup)
	pkt := wrapUDPv4(53, 40000, buildDNSResponse("example.com", net.ParseIP("93.184.216.34")))

	if !feedDNSPacket(engine, pkt) {
		t.Fatalf("expected packet to be fed")
	}

	snap := sup.Fqdns().Snapshot()
	ips, ok := snap["example.com"]
	if !ok || len(ips) == 0 {
		t.Fatalf("resolver did not learn example.com: %+v", snap)
	}
	if ips[0].String() != "93.184.216.34" {
		t.Fatalf("learned IP = %s", ips[0])
	}

	// A response for a name NOT in the allow-set must be dropped.
	other := wrapUDPv4(53, 40000, buildDNSResponse("evil.example.org", net.ParseIP("6.6.6.6")))
	feedDNSPacket(engine, other)
	if _, ok := sup.Fqdns().Snapshot()["evil.example.org"]; ok {
		t.Fatalf("non-allowed name must not be learned")
	}
}
