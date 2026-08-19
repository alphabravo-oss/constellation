package dp

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestDecodeConnection_RoundTrip constructs a 96-byte DPMsgConnect by writing
// each field at the exact offset defs.h:425-448 specifies, then verifies that
// our decoder lifts every field back out correctly. Byte order is big-endian
// because dp htonl/htons-encodes everything before send (dp/ctrl.c:2811).
func TestDecodeConnection_RoundTrip(t *testing.T) {
	b := make([]byte, dpMsgConnectSize)
	// EPMAC[6]
	copy(b[0:6], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	// IPProto, Padding
	b[6] = 6 // TCP
	b[7] = 0
	// ServerPort, ClientPort
	binary.BigEndian.PutUint16(b[8:10], 8080)
	binary.BigEndian.PutUint16(b[10:12], 54321)
	// ClientIP[16] — first 4 bytes are the IPv4 (10.1.2.3); rest zero
	copy(b[12:16], net.ParseIP("10.1.2.3").To4())
	// ServerIP[16] — first 4 bytes are 10.4.5.6
	copy(b[28:32], net.ParseIP("10.4.5.6").To4())
	// EtherType = IPv4
	binary.BigEndian.PutUint16(b[44:46], ethTypeIPv4)
	// Flags — Ingress + ExternalPeer
	binary.BigEndian.PutUint16(b[46:48], ConnFlagIngress|ConnFlagExternal)
	// Bytes
	binary.BigEndian.PutUint32(b[48:52], 1_500_000)
	// Sessions
	binary.BigEndian.PutUint32(b[52:56], 42)
	// FirstSeenAt, LastSeenAt
	binary.BigEndian.PutUint32(b[56:60], 1_700_000_000)
	binary.BigEndian.PutUint32(b[60:64], 1_700_001_000)
	// Application
	binary.BigEndian.PutUint16(b[64:66], 1001) // arbitrary app id (HTTP=1001 in NeuVector apis.h)
	// PolicyAction, Severity
	b[66] = PolicyActionViolate
	b[67] = 5
	// PolicyId, Violates
	binary.BigEndian.PutUint32(b[68:72], 7)
	binary.BigEndian.PutUint32(b[72:76], 3)
	// ThreatID
	binary.BigEndian.PutUint32(b[76:80], 2022) // SQL_INJECTION
	// EpSessCurIn, EpSessIn12
	binary.BigEndian.PutUint32(b[80:84], 9)
	binary.BigEndian.PutUint32(b[84:88], 27)
	// EpByteIn12
	binary.BigEndian.PutUint64(b[88:96], 1_234_567_890)

	c, err := decodeConnection(b)
	if err != nil {
		t.Fatalf("decodeConnection: %v", err)
	}

	if got, want := c.EPMAC.String(), "aa:bb:cc:dd:ee:ff"; got != want {
		t.Errorf("EPMAC = %q want %q", got, want)
	}
	if c.IPProto != 6 {
		t.Errorf("IPProto = %d want 6", c.IPProto)
	}
	if c.ServerPort != 8080 || c.ClientPort != 54321 {
		t.Errorf("ports = (%d,%d) want (8080,54321)", c.ServerPort, c.ClientPort)
	}
	if got, want := c.ClientIP.String(), "10.1.2.3"; got != want {
		t.Errorf("ClientIP = %q want %q", got, want)
	}
	if got, want := c.ServerIP.String(), "10.4.5.6"; got != want {
		t.Errorf("ServerIP = %q want %q", got, want)
	}
	if c.EtherType != ethTypeIPv4 {
		t.Errorf("EtherType = 0x%x want 0x%x", c.EtherType, ethTypeIPv4)
	}
	if !c.Ingress || !c.ExternalPeer {
		t.Errorf("Ingress=%v ExternalPeer=%v want both true", c.Ingress, c.ExternalPeer)
	}
	if c.XFF || c.LinkLocal || c.NBE {
		t.Errorf("unexpected flag set: XFF=%v LinkLocal=%v NBE=%v", c.XFF, c.LinkLocal, c.NBE)
	}
	if c.Bytes != 1_500_000 {
		t.Errorf("Bytes = %d want 1500000", c.Bytes)
	}
	if c.Sessions != 42 {
		t.Errorf("Sessions = %d want 42", c.Sessions)
	}
	if c.FirstSeenAt != 1_700_000_000 || c.LastSeenAt != 1_700_001_000 {
		t.Errorf("SeenAt = (%d,%d)", c.FirstSeenAt, c.LastSeenAt)
	}
	if c.Application != 1001 {
		t.Errorf("Application = %d want 1001", c.Application)
	}
	if c.PolicyAction != PolicyActionViolate {
		t.Errorf("PolicyAction = %d want %d", c.PolicyAction, PolicyActionViolate)
	}
	if PolicyActionString(c.PolicyAction) != "alert" {
		t.Errorf("PolicyActionString = %q want alert", PolicyActionString(c.PolicyAction))
	}
	if c.Severity != 5 {
		t.Errorf("Severity = %d want 5", c.Severity)
	}
	if c.PolicyID != 7 || c.Violates != 3 {
		t.Errorf("Policy = (%d,%d)", c.PolicyID, c.Violates)
	}
	if c.ThreatID != 2022 {
		t.Errorf("ThreatID = %d want 2022", c.ThreatID)
	}
	if c.EpSessCurIn != 9 || c.EpSessIn12 != 27 {
		t.Errorf("EpSess = (%d,%d)", c.EpSessCurIn, c.EpSessIn12)
	}
	if c.EpByteIn12 != 1_234_567_890 {
		t.Errorf("EpByteIn12 = %d", c.EpByteIn12)
	}
}

// TestDecodeConnections_WithHeader builds the full DPMsgConnectHdr + N records
// envelope and verifies decodeConnections returns the right number of records
// with sane values.
func TestDecodeConnections_WithHeader(t *testing.T) {
	const n = 3
	payload := make([]byte, dpMsgConnectHdrSize+n*dpMsgConnectSize)
	binary.BigEndian.PutUint16(payload[0:2], n) // Connects
	binary.BigEndian.PutUint16(payload[2:4], 0) // Reserved
	for i := 0; i < n; i++ {
		off := dpMsgConnectHdrSize + i*dpMsgConnectSize
		binary.BigEndian.PutUint16(payload[off+44:off+46], ethTypeIPv4)
		binary.BigEndian.PutUint32(payload[off+48:off+52], uint32(1000*(i+1)))
	}
	got, err := decodeConnections(payload)
	if err != nil {
		t.Fatalf("decodeConnections: %v", err)
	}
	if len(got) != n {
		t.Fatalf("count = %d want %d", len(got), n)
	}
	for i, c := range got {
		want := uint32(1000 * (i + 1))
		if c.Bytes != want {
			t.Errorf("rec[%d].Bytes = %d want %d", i, c.Bytes, want)
		}
	}
}

// TestDecodeHdr_LengthMismatch ensures we reject a header that claims a length
// different from the buffer it arrived in.
func TestDecodeHdr_LengthMismatch(t *testing.T) {
	b := make([]byte, 10)
	b[0] = KindKeepAlive
	binary.BigEndian.PutUint16(b[2:4], 99) // header says 99 but buf is 10
	if _, _, err := decodeHdr(b); err == nil {
		t.Fatalf("expected length-mismatch error")
	}
}

// TestPolicyActionString covers the few buckets the REST API surfaces.
func TestPolicyActionString(t *testing.T) {
	cases := []struct {
		in  uint8
		out string
	}{
		{PolicyActionAllow, "allow"},
		{PolicyActionLearn, "allow"},
		{PolicyActionViolate, "alert"},
		{PolicyActionDeny, "deny"},
		{99, "unknown"},
	}
	for _, c := range cases {
		if got := PolicyActionString(c.in); got != c.out {
			t.Errorf("PolicyActionString(%d) = %q want %q", c.in, got, c.out)
		}
	}
}
