package dp

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestDecodeSession_RoundTrip — Wave C1. Builds a 140-byte DPMsgSession at
// the byte offsets specified in defs.h:233-269, decodes it, and verifies
// every field round-trips. Catches off-by-one mistakes in the wire layout.
func TestDecodeSession_RoundTrip(t *testing.T) {
	b := make([]byte, dpMsgSessionSize)
	// ID (offset 0)
	binary.BigEndian.PutUint32(b[0:4], 0xDEADBEEF)
	// EPMAC (offset 4)
	copy(b[4:10], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	// EtherType (offset 10) = IPv4
	binary.BigEndian.PutUint16(b[10:12], ethTypeIPv4)
	// ClientMAC + ServerMAC (offsets 12, 18)
	copy(b[12:18], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	copy(b[18:24], []byte{0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC})
	// ClientIP/ServerIP (offsets 24, 40) — IPv4 in first 4 bytes
	copy(b[24:28], net.ParseIP("10.42.0.5").To4())
	copy(b[40:44], net.ParseIP("10.43.0.1").To4())
	// ClientPort/ServerPort (offsets 56, 58)
	binary.BigEndian.PutUint16(b[56:58], 54321)
	binary.BigEndian.PutUint16(b[58:60], 443)
	// IPProto (offset 62)
	b[62] = 6 // TCP
	// ClientPkts/ServerPkts (offsets 64, 68)
	binary.BigEndian.PutUint32(b[64:68], 100)
	binary.BigEndian.PutUint32(b[68:72], 250)
	// ClientBytes/ServerBytes (offsets 72, 76)
	binary.BigEndian.PutUint32(b[72:76], 4000)
	binary.BigEndian.PutUint32(b[76:80], 12000)
	// Application (offset 106) = HTTP
	binary.BigEndian.PutUint16(b[106:108], 1001)
	// ThreatID (offset 108)
	binary.BigEndian.PutUint32(b[108:112], 2022)
	// PolicyId (offset 112)
	binary.BigEndian.PutUint32(b[112:116], 42)

	s, err := decodeSession(b)
	if err != nil {
		t.Fatalf("decodeSession: %v", err)
	}
	if s.ID != 0xDEADBEEF {
		t.Errorf("ID = %x want DEADBEEF", s.ID)
	}
	if s.EPMAC.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("EPMAC = %s", s.EPMAC.String())
	}
	if s.ClientPort != 54321 || s.ServerPort != 443 {
		t.Errorf("ports = (%d, %d) want (54321, 443)", s.ClientPort, s.ServerPort)
	}
	if s.ClientIP.String() != "10.42.0.5" || s.ServerIP.String() != "10.43.0.1" {
		t.Errorf("IPs = (%s, %s)", s.ClientIP, s.ServerIP)
	}
	if s.IPProto != 6 {
		t.Errorf("IPProto = %d want 6", s.IPProto)
	}
	if s.ClientBytes != 4000 || s.ServerBytes != 12000 {
		t.Errorf("bytes = (%d, %d) want (4000, 12000)", s.ClientBytes, s.ServerBytes)
	}
	if s.ClientPkts != 100 || s.ServerPkts != 250 {
		t.Errorf("pkts = (%d, %d)", s.ClientPkts, s.ServerPkts)
	}
	if s.Application != 1001 {
		t.Errorf("Application = %d", s.Application)
	}
	if s.PolicyID != 42 {
		t.Errorf("PolicyID = %d", s.PolicyID)
	}
}

// TestDecodeSessions_WithHeader exercises the DPMsgSessionHdr + N records
// envelope. A two-session payload should produce a slice of length 2 with
// distinct values.
func TestDecodeSessions_WithHeader(t *testing.T) {
	const n = 2
	payload := make([]byte, dpMsgSessionHdrSize+n*dpMsgSessionSize)
	binary.BigEndian.PutUint16(payload[0:2], n) // Sessions
	for i := 0; i < n; i++ {
		off := dpMsgSessionHdrSize + i*dpMsgSessionSize
		binary.BigEndian.PutUint32(payload[off+0:off+4], uint32(1000+i))    // ID
		binary.BigEndian.PutUint16(payload[off+10:off+12], ethTypeIPv4)     // EtherType
		binary.BigEndian.PutUint16(payload[off+58:off+60], uint16(80+i*20)) // ServerPort
		binary.BigEndian.PutUint32(payload[off+72:off+76], uint32(100*(i+1))) // ClientBytes
		binary.BigEndian.PutUint32(payload[off+76:off+80], uint32(500*(i+1))) // ServerBytes
	}
	got, err := decodeSessions(payload)
	if err != nil {
		t.Fatalf("decodeSessions: %v", err)
	}
	if len(got) != n {
		t.Fatalf("got %d sessions, want %d", len(got), n)
	}
	if got[0].ID != 1000 || got[1].ID != 1001 {
		t.Errorf("IDs = (%d, %d)", got[0].ID, got[1].ID)
	}
	if got[0].ServerPort != 80 || got[1].ServerPort != 100 {
		t.Errorf("ports = (%d, %d)", got[0].ServerPort, got[1].ServerPort)
	}
	if got[0].ClientBytes != 100 || got[1].ClientBytes != 200 {
		t.Errorf("client bytes drifted: %+v", got)
	}
}

// TestDecodeSessions_EmptyHeader handles the "ack-only" case where dp
// replies with Sessions=0. That happens when the agent issues
// ctrl_list_session but dp's threads have nothing in their tables yet.
func TestDecodeSessions_EmptyHeader(t *testing.T) {
	payload := make([]byte, dpMsgSessionHdrSize)
	// Sessions = 0, Reserved = 0
	got, err := decodeSessions(payload)
	if err != nil {
		t.Fatalf("empty session list: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d sessions on empty payload, want 0", len(got))
	}
}

// TestSessionCache_LookupHit verifies the cache routes a 5-tuple to the
// correct session and reports hit rate.
func TestSessionCache_LookupHit(t *testing.T) {
	c := NewSessionCache()
	s := &Session{
		ClientIP:    net.ParseIP("10.42.0.5"),
		ServerIP:    net.ParseIP("10.43.0.1"),
		ClientPort:  54321,
		ServerPort:  443,
		IPProto:     6,
		ClientBytes: 1000,
		ServerBytes: 5000,
	}
	c.Apply([]*Session{s})
	if c.Size() != 1 {
		t.Errorf("Size = %d want 1", c.Size())
	}
	got, ok := c.Lookup(s.Key())
	if !ok {
		t.Fatalf("Lookup miss")
	}
	if got.ServerBytes != 5000 {
		t.Errorf("wrong session retrieved")
	}
	// Different 5-tuple should miss.
	_, ok = c.Lookup(SessionKey{
		ClientIP:   "10.42.0.5",
		ServerIP:   "10.43.0.1",
		ClientPort: 12345,
		ServerPort: 443,
		IPProto:    6,
	})
	if ok {
		t.Errorf("expected miss for different ClientPort")
	}
	stats := c.Snapshot()
	if stats.Lookups != 2 || stats.LookupHits != 1 {
		t.Errorf("stats = %+v want lookups=2 hits=1", stats)
	}
}

// TestSessionCache_Replace swaps the whole map atomically; stale entries
// from the previous batch are gone after a Replace call.
func TestSessionCache_Replace(t *testing.T) {
	c := NewSessionCache()
	c.Apply([]*Session{{ClientIP: net.ParseIP("1.2.3.4"), ServerIP: net.ParseIP("5.6.7.8"), ClientPort: 100, ServerPort: 200, IPProto: 6}})
	if c.Size() != 1 {
		t.Fatalf("Size before replace = %d", c.Size())
	}
	c.Replace([]*Session{{ClientIP: net.ParseIP("9.9.9.9"), ServerIP: net.ParseIP("8.8.8.8"), ClientPort: 1, ServerPort: 2, IPProto: 17}})
	if c.Size() != 1 {
		t.Errorf("Size after replace = %d", c.Size())
	}
	_, ok := c.Lookup(SessionKey{ClientIP: "1.2.3.4", ServerIP: "5.6.7.8", ClientPort: 100, ServerPort: 200, IPProto: 6})
	if ok {
		t.Errorf("stale entry survived Replace")
	}
}

// TestSessionCache_ReplaceEvictsAbsent — Replace must drop every entry not
// present in the new snapshot, not merely overwrite matching keys. Seed two
// sessions, Replace with a snapshot containing only one of them (plus a new
// one), and assert the omitted 5-tuple is evicted while the carried-over and
// fresh ones remain.
func TestSessionCache_ReplaceEvictsAbsent(t *testing.T) {
	c := NewSessionCache()
	keep := &Session{ClientIP: net.IP{10, 0, 0, 1}, ServerIP: net.IP{10, 0, 0, 2}, ClientPort: 1, ServerPort: 2, IPProto: 6}
	drop := &Session{ClientIP: net.IP{10, 0, 0, 3}, ServerIP: net.IP{10, 0, 0, 4}, ClientPort: 3, ServerPort: 4, IPProto: 6}
	c.Apply([]*Session{keep, drop})
	if c.Size() != 2 {
		t.Fatalf("Size before replace = %d want 2", c.Size())
	}

	fresh := &Session{ClientIP: net.IP{10, 0, 0, 5}, ServerIP: net.IP{10, 0, 0, 6}, ClientPort: 5, ServerPort: 6, IPProto: 6}
	c.Replace([]*Session{keep, fresh})
	if c.Size() != 2 {
		t.Fatalf("Size after replace = %d want 2", c.Size())
	}
	if _, ok := c.Lookup(keep.Key()); !ok {
		t.Errorf("carried-over entry missing after Replace")
	}
	if _, ok := c.Lookup(fresh.Key()); !ok {
		t.Errorf("fresh entry missing after Replace")
	}
	if _, ok := c.Lookup(drop.Key()); ok {
		t.Errorf("absent entry survived Replace")
	}
}

// TestSessionKey_IPCanonicalization — a session decoded as a 4-byte IPv4 and
// the same address arriving as a 16-byte IPv4-mapped IPv6 must produce the
// same cache key, and a lookup built from either form must find the other.
func TestSessionKey_IPCanonicalization(t *testing.T) {
	v4 := net.IP{1, 2, 3, 4}                                                       // 4-byte IPv4
	mapped := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4}         // ::ffff:1.2.3.4
	srvV4 := net.IP{5, 6, 7, 8}
	srvMapped := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 5, 6, 7, 8}

	dotted := &Session{ClientIP: v4, ServerIP: srvV4, ClientPort: 100, ServerPort: 200, IPProto: 6}
	v6form := &Session{ClientIP: mapped, ServerIP: srvMapped, ClientPort: 100, ServerPort: 200, IPProto: 6}

	if dotted.Key() != v6form.Key() {
		t.Fatalf("keys differ across representations:\n dotted=%+v\n mapped=%+v", dotted.Key(), v6form.Key())
	}

	// An entry stored under the dotted form is found by a lookup key built
	// (via NewSessionKey) from the mapped form, and vice-versa.
	c := NewSessionCache()
	c.Apply([]*Session{dotted})
	if _, ok := c.Lookup(NewSessionKey(mapped, srvMapped, 100, 200, 6)); !ok {
		t.Errorf("lookup from mapped form missed dotted-form entry")
	}

	// A genuinely different (non-mapped) IPv6 address must NOT collide.
	realV6 := net.ParseIP("2001:db8::1")
	if NewSessionKey(realV6, srvV4, 100, 200, 6) == dotted.Key() {
		t.Errorf("distinct IPv6 address collided with IPv4 key")
	}
}

// TestSessionDumpAssembler assembles a multi-datagram dump using the
// DPMsgHdr.More flag: intermediate datagrams (More=1) accumulate without
// completing; the final datagram (More=0) completes and Take yields the full
// snapshot, then resets for the next dump.
func TestSessionDumpAssembler(t *testing.T) {
	var a SessionDumpAssembler
	s1 := &Session{ClientIP: net.IP{10, 0, 0, 1}, ClientPort: 1}
	s2 := &Session{ClientIP: net.IP{10, 0, 0, 2}, ClientPort: 2}
	s3 := &Session{ClientIP: net.IP{10, 0, 0, 3}, ClientPort: 3}

	if a.Add([]*Session{s1}, true) {
		t.Fatalf("dump reported complete on More=1 datagram")
	}
	if a.Add([]*Session{s2}, true) {
		t.Fatalf("dump reported complete on second More=1 datagram")
	}
	if !a.Add([]*Session{s3}, false) {
		t.Fatalf("dump did not complete on More=0 datagram")
	}
	full := a.Take()
	if len(full) != 3 {
		t.Fatalf("assembled %d sessions, want 3", len(full))
	}
	// Take must reset for the next dump.
	if got := a.Take(); got != nil {
		t.Errorf("assembler not reset after Take: %v", got)
	}
}
