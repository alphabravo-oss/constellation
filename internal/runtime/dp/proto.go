package dp

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

// DPMsgSize is the maximum size of a single datagram exchanged with dp,
// matching the C #define DP_MSG_SIZE in third_party/neuvector/defs.h.
const DPMsgSize = 8192

// Message kinds, mirrored from defs.h DP_KIND_*. dp sends one of these in the
// header's Kind field for every notification it emits on /tmp/ctrl_listen.sock.
const (
	KindAppUpdate              = 1
	KindSessionList            = 2
	KindSessionCount           = 3
	KindDeviceCounter          = 4
	KindMeterList              = 5
	KindThreatLog              = 6
	KindConnection             = 7
	KindMacStats               = 8
	KindDeviceStats            = 9
	KindKeepAlive              = 10
	KindFqdnUpdate             = 11
	KindIPFqdnStorageUpdate    = 12
	KindIPFqdnStorageRelease   = 13
)

// kindName returns a human-readable label for a DP_KIND_* value. Falls back
// to a numeric form for kinds we don't expect to see.
func kindName(k uint8) string {
	switch k {
	case KindAppUpdate:
		return "app_update"
	case KindSessionList:
		return "session_list"
	case KindSessionCount:
		return "session_count"
	case KindDeviceCounter:
		return "device_counter"
	case KindMeterList:
		return "meter_list"
	case KindThreatLog:
		return "threat_log"
	case KindConnection:
		return "connection"
	case KindMacStats:
		return "mac_stats"
	case KindDeviceStats:
		return "device_stats"
	case KindKeepAlive:
		return "keep_alive"
	case KindFqdnUpdate:
		return "fqdn_update"
	case KindIPFqdnStorageUpdate:
		return "ip_fqdn_storage_update"
	case KindIPFqdnStorageRelease:
		return "ip_fqdn_storage_release"
	default:
		return fmt.Sprintf("kind_%d", k)
	}
}

// DPCONN_FLAG_* — bit flags on DPMsgConnect.Flags. Mirrored from defs.h.
const (
	ConnFlagIngress   = 0x0001
	ConnFlagExternal  = 0x0002
	ConnFlagXFF       = 0x0004
	ConnFlagSvcExtIP  = 0x0008
	ConnFlagMeshToSvr = 0x0010
	ConnFlagLinkLocal = 0x0020
	ConnFlagTmpOpen   = 0x0040
	ConnFlagUwlIP     = 0x0080
	ConnFlagCheckNbe  = 0x0100
	ConnFlagNbeSns    = 0x0200
)

// DPLOG_FLAG_* — bit flags on DPMsgThreatLog.Flags. Mirrored from defs.h.
const (
	ThreatFlagPktIngress  = 0x01
	ThreatFlagSessIngress = 0x02
	ThreatFlagTap         = 0x04
)

// DP_POLICY_ACTION_* — values of DPMsgConnect.PolicyAction, mirrored from defs.h.
const (
	PolicyActionOpen     = 0
	PolicyActionLearn    = 1
	PolicyActionAllow    = 2
	PolicyActionCheckVH  = 3
	PolicyActionCheckNbe = 4
	PolicyActionCheckApp = 5
	PolicyActionViolate  = 6
	PolicyActionDeny     = 7
)

// CFG_* — values of DPPolicyCfg.Cmd, mirrored from defs.h:222-224. The agent
// signals to dp how to interpret the incoming policy bundle: ADD inserts new
// rules, MODIFY swaps the rule set atomically, DELETE clears it.
const (
	CmdAdd    uint = 1
	CmdModify uint = 2
	CmdDelete uint = 3
)

// MSG_* — values of DPPolicyCfg.Flag, mirrored from defs.h:226-227. Used for
// multi-datagram policy pushes: MSG_START on the first message, MSG_END on
// the last, both bits set on a single-message push.
const (
	MsgStart uint = 0x1
	MsgEnd   uint = 0x2
)

// DP_POLICY_APPLY_* — values of DPPolicyCfg.ApplyDir, mirrored from defs.h.
// Tells dp whether the workload's rule set governs egress, ingress, or both.
const (
	ApplyDirEgress  int = 0x1
	ApplyDirIngress int = 0x2
	ApplyDirBoth    int = ApplyDirEgress | ApplyDirIngress
)

// PolicyActionString maps the numeric action to the same lowercase strings the
// REST API already serves so the same vocabulary flows kernel → UI.
func PolicyActionString(a uint8) string {
	switch a {
	case PolicyActionAllow, PolicyActionLearn, PolicyActionOpen,
		PolicyActionCheckVH, PolicyActionCheckNbe, PolicyActionCheckApp:
		return "allow"
	case PolicyActionViolate:
		return "alert"
	case PolicyActionDeny:
		return "deny"
	default:
		return "unknown"
	}
}

// EtherType constants used by DP wire messages (mirrored from <linux/if_ether.h>).
const (
	ethTypeIPv4 = 0x0800
	ethTypeIPv6 = 0x86DD
)

// DPMsgHdr matches the C struct in defs.h:
//
//	typedef struct {
//	    uint8_t  Kind;
//	    uint8_t  More;
//	    uint16_t Length;   // DPMsgHdr + Msg
//	} DPMsgHdr;
//
// Wire bytes are big-endian (dp htonl/htons-encodes every field before send).
type DPMsgHdr struct {
	Kind   uint8
	More   uint8
	Length uint16
}

const dpMsgHdrSize = 4

// decodeHdr parses the 4-byte header and verifies Length matches the buffer.
// Returns the header, the offset where payload starts, and any error.
func decodeHdr(buf []byte) (DPMsgHdr, int, error) {
	if len(buf) < dpMsgHdrSize {
		return DPMsgHdr{}, 0, fmt.Errorf("dp: short header (%d < %d)", len(buf), dpMsgHdrSize)
	}
	h := DPMsgHdr{
		Kind:   buf[0],
		More:   buf[1],
		Length: binary.BigEndian.Uint16(buf[2:4]),
	}
	if int(h.Length) != len(buf) {
		return h, 0, fmt.Errorf("dp: header length mismatch (hdr=%d actual=%d kind=%s)",
			h.Length, len(buf), kindName(h.Kind))
	}
	return h, dpMsgHdrSize, nil
}

// DPMsgConnectHdr — defs.h:
//
//	typedef struct {
//	    uint16_t Connects;
//	    uint16_t Reserved;
//	    // DPMsgConnect Connect[0];
//	} DPMsgConnectHdr;
const dpMsgConnectHdrSize = 4

// DPMsgConnect on the wire is 96 bytes; field offsets traced from defs.h:425-448.
// We do not declare a struct here — decodeConnection reads each field manually
// so we don't rely on Go struct-padding behavior matching the C layout.
const dpMsgConnectSize = 96

// DPMsgThreatLog — defs.h:391-412. Header is 68 bytes then Msg[64] + Packet[2048]
// + DlpNameHash:u32. Total 2184 bytes.
const (
	threatLogMsgLen    = 64
	threatLogPktLen    = 2048
	dpMsgThreatLogSize = 68 + threatLogMsgLen + threatLogPktLen + 4 // = 2184
)

// Connection is the Go-native form of one DPMsgConnect record. Field names
// mirror the C wire types so we can cross-reference defs.h:425-448.
type Connection struct {
	// Endpoint identity — dp uses the container's veth MAC as the workload key.
	// The agent (Wave 3) maps EPMAC → workload via the cgroup/pod resolver.
	EPMAC net.HardwareAddr

	// 5-tuple plus EtherType (IPv4 vs IPv6 — dictates ClientIP/ServerIP width).
	EtherType  uint16
	IPProto    uint8
	ClientIP   net.IP
	ServerIP   net.IP
	ClientPort uint16
	ServerPort uint16

	// Real metrics. Bytes is delta-since-last-report (dp resets after each emit
	// — see dp/ctrl.c:2853). Sessions is the count of distinct 5-tuples that
	// fell into this aggregate bucket.
	Bytes    uint32
	Sessions uint32

	// Epoch seconds (host clock). FirstSeenAt is the time the conversation
	// first appeared; LastSeenAt is when the bucket was emitted.
	FirstSeenAt uint32
	LastSeenAt  uint32

	// L7 application from DPI parsers (see dp/dpi/parsers/*). 0 = unknown.
	// dp's APP_* values are defined in dp/apis.h.
	Application uint16

	// Policy decision attached to the conversation by dp's policy engine.
	// Map via PolicyActionString() to the same "allow"/"alert"/"deny" vocabulary
	// the REST API serves.
	PolicyAction uint8
	PolicyID     uint32
	Violates     uint32

	// Threat / severity if the conversation tripped a signature.
	ThreatID uint32
	Severity uint8

	// Per-endpoint accumulators (in / over last 12 minutes) — used by NeuVector's
	// UI to surface endpoint pressure. We can plumb these to similar widgets.
	EpSessCurIn uint32
	EpSessIn12  uint32
	EpByteIn12  uint64

	// Connection-shape flags. Decoded from Flags into individual bools so
	// downstream consumers don't have to know the bit positions.
	Ingress      bool
	ExternalPeer bool
	XFF          bool
	SvcExtIP     bool
	MeshToSvr    bool
	LinkLocal    bool
	TmpOpen      bool
	UwlIP        bool
	NBE          bool
	NBESns       bool
}

// ThreatLog is the Go-native form of DPMsgThreatLog.
type ThreatLog struct {
	ThreatID    uint32
	ReportedAt  uint32 // epoch seconds
	Count       uint32
	Action      uint8
	Severity    uint8
	IPProto     uint8
	EPMAC       net.HardwareAddr
	EtherType   uint16
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16
	DstPort     uint16
	ICMPCode    uint8
	ICMPType    uint8
	Application uint16
	PktLen      uint16 // bytes copied into Packet
	CapLen      uint16 // bytes seen on the wire
	Msg         string
	Packet      []byte // up to threatLogPktLen bytes
	DlpNameHash uint32

	PktIngress  bool
	SessIngress bool
	Tap         bool
}

// decodeConnections decodes a DPMsgConnectHdr followed by `Connects` DPMsgConnect
// records. Returns a slice the caller owns. Wire layout: defs.h:425-454.
func decodeConnections(payload []byte) ([]*Connection, error) {
	if len(payload) < dpMsgConnectHdrSize {
		return nil, fmt.Errorf("dp: short connect-hdr (%d < %d)",
			len(payload), dpMsgConnectHdrSize)
	}
	count := int(binary.BigEndian.Uint16(payload[0:2]))
	// payload[2:4] = Reserved
	want := dpMsgConnectHdrSize + count*dpMsgConnectSize
	if len(payload) != want {
		return nil, fmt.Errorf("dp: connect payload length mismatch (count=%d expect=%d actual=%d)",
			count, want, len(payload))
	}

	out := make([]*Connection, count)
	off := dpMsgConnectHdrSize
	for i := 0; i < count; i++ {
		c, err := decodeConnection(payload[off : off+dpMsgConnectSize])
		if err != nil {
			return nil, fmt.Errorf("dp: connect record %d: %w", i, err)
		}
		out[i] = c
		off += dpMsgConnectSize
	}
	return out, nil
}

// decodeConnection parses one 96-byte DPMsgConnect. Offsets traced from
// defs.h:425-448. All multi-byte fields are big-endian (htonl-encoded by dp).
func decodeConnection(b []byte) (*Connection, error) {
	if len(b) != dpMsgConnectSize {
		return nil, fmt.Errorf("dp: connect record wrong size (%d != %d)",
			len(b), dpMsgConnectSize)
	}
	c := &Connection{
		EPMAC:        net.HardwareAddr(append([]byte(nil), b[0:6]...)),
		IPProto:      b[6],
		ServerPort:   binary.BigEndian.Uint16(b[8:10]),
		ClientPort:   binary.BigEndian.Uint16(b[10:12]),
		EtherType:    binary.BigEndian.Uint16(b[44:46]),
		Bytes:        binary.BigEndian.Uint32(b[48:52]),
		Sessions:     binary.BigEndian.Uint32(b[52:56]),
		FirstSeenAt:  binary.BigEndian.Uint32(b[56:60]),
		LastSeenAt:   binary.BigEndian.Uint32(b[60:64]),
		Application:  binary.BigEndian.Uint16(b[64:66]),
		PolicyAction: b[66],
		Severity:     b[67],
		PolicyID:     binary.BigEndian.Uint32(b[68:72]),
		Violates:     binary.BigEndian.Uint32(b[72:76]),
		ThreatID:     binary.BigEndian.Uint32(b[76:80]),
		EpSessCurIn:  binary.BigEndian.Uint32(b[80:84]),
		EpSessIn12:   binary.BigEndian.Uint32(b[84:88]),
		EpByteIn12:   binary.BigEndian.Uint64(b[88:96]),
	}
	// IP fields are 16-byte wide regardless of family; trim to the right
	// width for IPv4 so net.IP renders as 1.2.3.4 not ::ffff:1.2.3.4.
	switch c.EtherType {
	case ethTypeIPv4:
		c.ClientIP = net.IP(append([]byte(nil), b[12:16]...))
		c.ServerIP = net.IP(append([]byte(nil), b[28:32]...))
	case ethTypeIPv6:
		c.ClientIP = net.IP(append([]byte(nil), b[12:28]...))
		c.ServerIP = net.IP(append([]byte(nil), b[28:44]...))
	default:
		// Unknown EtherType — keep the raw 16-byte buffers so consumers can
		// still see the bits if it ever happens.
		c.ClientIP = net.IP(append([]byte(nil), b[12:28]...))
		c.ServerIP = net.IP(append([]byte(nil), b[28:44]...))
	}
	flags := binary.BigEndian.Uint16(b[46:48])
	c.Ingress = flags&ConnFlagIngress != 0
	c.ExternalPeer = flags&ConnFlagExternal != 0
	c.XFF = flags&ConnFlagXFF != 0
	c.SvcExtIP = flags&ConnFlagSvcExtIP != 0
	c.MeshToSvr = flags&ConnFlagMeshToSvr != 0
	c.LinkLocal = flags&ConnFlagLinkLocal != 0
	c.TmpOpen = flags&ConnFlagTmpOpen != 0
	c.UwlIP = flags&ConnFlagUwlIP != 0
	c.NBE = flags&ConnFlagCheckNbe != 0
	c.NBESns = flags&ConnFlagNbeSns != 0
	return c, nil
}

// DPMsgSessionHdr — 4 bytes prefix on every DP_KIND_SESSION_LIST notification.
//
//	typedef struct {
//	    uint16_t Sessions;
//	    uint16_t Reserved;
//	} DPMsgSessionHdr;
const dpMsgSessionHdrSize = 4

// DPMsgSession wire format from defs.h:233-269. Total 140 bytes per session.
// Carries the per-direction byte/packet counters dp tracks (ClientBytes vs
// ServerBytes) — the field DPMsgConnect lacks. We poll this periodically
// (Wave C1) and correlate against DPMsgConnect to fill in the wing split.
const dpMsgSessionSize = 140

// Session is the Go-native form of one DPMsgSession entry. Field names
// match defs.h exactly; not every dp field is plumbed up — we surface
// what the flow ingest + threat path actually need.
type Session struct {
	ID           uint32
	EPMAC        net.HardwareAddr
	EtherType    uint16
	ClientMAC    net.HardwareAddr
	ServerMAC    net.HardwareAddr
	ClientIP     net.IP
	ServerIP     net.IP
	ClientPort   uint16
	ServerPort   uint16
	ICMPCode     uint8
	ICMPType     uint8
	IPProto      uint8
	ClientPkts   uint32
	ServerPkts   uint32
	ClientBytes  uint32
	ServerBytes  uint32
	ClientAsmPkts  uint32
	ServerAsmPkts  uint32
	ClientAsmBytes uint32
	ServerAsmBytes uint32
	ClientState  uint8
	ServerState  uint8
	Idle         uint16
	Age          uint32
	Life         uint16
	Application  uint16
	ThreatID     uint32
	PolicyID     uint32
	PolicyAction uint8
	Severity     uint8
	Flags        uint16
	XffIP        net.IP
	XffApp       uint16
	XffPort      uint16
}

// decodeSessions parses one DPMsgSessionHdr + N DPMsgSession records.
// dp may emit zero sessions when the response is just an ack (the empty
// reply that confirms a ctrl_list_session was accepted) — that case
// returns an empty slice, not an error.
func decodeSessions(payload []byte) ([]*Session, error) {
	if len(payload) < dpMsgSessionHdrSize {
		return nil, fmt.Errorf("dp: short session-hdr (%d < %d)",
			len(payload), dpMsgSessionHdrSize)
	}
	count := int(binary.BigEndian.Uint16(payload[0:2]))
	// payload[2:4] = Reserved
	want := dpMsgSessionHdrSize + count*dpMsgSessionSize
	if len(payload) != want {
		return nil, fmt.Errorf("dp: session payload length mismatch (count=%d expect=%d actual=%d)",
			count, want, len(payload))
	}
	out := make([]*Session, 0, count)
	off := dpMsgSessionHdrSize
	for i := 0; i < count; i++ {
		s, err := decodeSession(payload[off : off+dpMsgSessionSize])
		if err != nil {
			return nil, fmt.Errorf("dp: session record %d: %w", i, err)
		}
		out = append(out, s)
		off += dpMsgSessionSize
	}
	return out, nil
}

// decodeSession parses one 140-byte DPMsgSession. Offsets traced from
// defs.h:233-269. Multi-byte fields are big-endian (dp htonl-encodes).
func decodeSession(b []byte) (*Session, error) {
	if len(b) != dpMsgSessionSize {
		return nil, fmt.Errorf("dp: session record wrong size (%d != %d)",
			len(b), dpMsgSessionSize)
	}
	s := &Session{
		ID:             binary.BigEndian.Uint32(b[0:4]),
		EPMAC:          net.HardwareAddr(append([]byte(nil), b[4:10]...)),
		EtherType:      binary.BigEndian.Uint16(b[10:12]),
		ClientMAC:      net.HardwareAddr(append([]byte(nil), b[12:18]...)),
		ServerMAC:      net.HardwareAddr(append([]byte(nil), b[18:24]...)),
		ClientPort:     binary.BigEndian.Uint16(b[56:58]),
		ServerPort:     binary.BigEndian.Uint16(b[58:60]),
		ICMPCode:       b[60],
		ICMPType:       b[61],
		IPProto:        b[62],
		ClientPkts:     binary.BigEndian.Uint32(b[64:68]),
		ServerPkts:     binary.BigEndian.Uint32(b[68:72]),
		ClientBytes:    binary.BigEndian.Uint32(b[72:76]),
		ServerBytes:    binary.BigEndian.Uint32(b[76:80]),
		ClientAsmPkts:  binary.BigEndian.Uint32(b[80:84]),
		ServerAsmPkts:  binary.BigEndian.Uint32(b[84:88]),
		ClientAsmBytes: binary.BigEndian.Uint32(b[88:92]),
		ServerAsmBytes: binary.BigEndian.Uint32(b[92:96]),
		ClientState:    b[96],
		ServerState:    b[97],
		Idle:           binary.BigEndian.Uint16(b[98:100]),
		Age:            binary.BigEndian.Uint32(b[100:104]),
		Life:           binary.BigEndian.Uint16(b[104:106]),
		Application:    binary.BigEndian.Uint16(b[106:108]),
		ThreatID:       binary.BigEndian.Uint32(b[108:112]),
		PolicyID:       binary.BigEndian.Uint32(b[112:116]),
		PolicyAction:   b[116],
		Severity:       b[117],
		Flags:          binary.BigEndian.Uint16(b[118:120]),
		XffApp:         binary.BigEndian.Uint16(b[136:138]),
		XffPort:        binary.BigEndian.Uint16(b[138:140]),
	}
	switch s.EtherType {
	case ethTypeIPv4:
		s.ClientIP = net.IP(append([]byte(nil), b[24:28]...))
		s.ServerIP = net.IP(append([]byte(nil), b[40:44]...))
	case ethTypeIPv6:
		s.ClientIP = net.IP(append([]byte(nil), b[24:40]...))
		s.ServerIP = net.IP(append([]byte(nil), b[40:56]...))
	default:
		s.ClientIP = net.IP(append([]byte(nil), b[24:40]...))
		s.ServerIP = net.IP(append([]byte(nil), b[40:56]...))
	}
	s.XffIP = net.IP(append([]byte(nil), b[120:136]...))
	return s, nil
}

// SessionKey identifies a session by 5-tuple. The cache uses this so the
// correlator in dp_flow.go can answer "for this DPMsgConnect, what does
// the most recent DPMsgSession tell me about per-direction bytes?".
type SessionKey struct {
	ClientIP   string
	ServerIP   string
	ClientPort uint16
	ServerPort uint16
	IPProto    uint8
}

// Key returns the cache key for a session. Two sessions with the same
// 5-tuple collapse — dp may emit the same session twice if it was active
// across two polls; the newer wins.
func (s *Session) Key() SessionKey {
	return NewSessionKey(s.ClientIP, s.ServerIP, s.ClientPort, s.ServerPort, s.IPProto)
}

// NewSessionKey builds a cache key from raw 5-tuple fields, applying the
// same IP canonicalization the cache uses internally. Lookup callers must
// route through this (rather than assembling a SessionKey by hand with
// ip.String()) so both sides agree on the key form — see ipKey.
func NewSessionKey(clientIP, serverIP net.IP, clientPort, serverPort uint16, ipProto uint8) SessionKey {
	return SessionKey{
		ClientIP:   ipKey(clientIP),
		ServerIP:   ipKey(serverIP),
		ClientPort: clientPort,
		ServerPort: serverPort,
		IPProto:    ipProto,
	}
}

// ipKey canonicalizes an IP into a stable cache-key string. dp hands us the
// same address in two stringifiable shapes depending on the wire path: a
// 4-byte IPv4 ("1.2.3.4") and a 16-byte IPv4-mapped IPv6 ("::ffff:1.2.3.4").
// net.IP.String() and netip disagree on which of those two they emit, so a
// naive ip.String() key can miss its own entry. We parse via net/netip and
// Unmap() so both representations collapse to the same canonical key.
func ipKey(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	if a, ok := netip.AddrFromSlice(ip); ok {
		return a.Unmap().String()
	}
	// Not a 4- or 16-byte slice — fall back to the raw form rather than
	// dropping the address entirely.
	return ip.String()
}

// decodeThreatLog parses one DPMsgThreatLog (2184 bytes). Offsets from
// defs.h:391-412. dp always sends exactly one threat per message — the
// DPMsgHdr.Length should equal dpMsgHdrSize + dpMsgThreatLogSize, but we
// tolerate longer trailing padding to be defensive.
func decodeThreatLog(b []byte) (*ThreatLog, error) {
	if len(b) < dpMsgThreatLogSize {
		return nil, fmt.Errorf("dp: short threat-log payload (%d < %d)",
			len(b), dpMsgThreatLogSize)
	}
	t := &ThreatLog{
		ThreatID:   binary.BigEndian.Uint32(b[0:4]),
		ReportedAt: binary.BigEndian.Uint32(b[4:8]),
		Count:      binary.BigEndian.Uint32(b[8:12]),
		Action:     b[12],
		Severity:   b[13],
		IPProto:    b[14],
	}
	flags := b[15]
	t.PktIngress = flags&ThreatFlagPktIngress != 0
	t.SessIngress = flags&ThreatFlagSessIngress != 0
	t.Tap = flags&ThreatFlagTap != 0
	t.EPMAC = net.HardwareAddr(append([]byte(nil), b[16:22]...))
	t.EtherType = binary.BigEndian.Uint16(b[22:24])
	switch t.EtherType {
	case ethTypeIPv4:
		t.SrcIP = net.IP(append([]byte(nil), b[24:28]...))
		t.DstIP = net.IP(append([]byte(nil), b[40:44]...))
	case ethTypeIPv6:
		t.SrcIP = net.IP(append([]byte(nil), b[24:40]...))
		t.DstIP = net.IP(append([]byte(nil), b[40:56]...))
	default:
		t.SrcIP = net.IP(append([]byte(nil), b[24:40]...))
		t.DstIP = net.IP(append([]byte(nil), b[40:56]...))
	}
	t.SrcPort = binary.BigEndian.Uint16(b[56:58])
	t.DstPort = binary.BigEndian.Uint16(b[58:60])
	t.ICMPCode = b[60]
	t.ICMPType = b[61]
	t.Application = binary.BigEndian.Uint16(b[62:64])
	t.PktLen = binary.BigEndian.Uint16(b[64:66])
	t.CapLen = binary.BigEndian.Uint16(b[66:68])

	t.Msg = cString(b[68 : 68+threatLogMsgLen])
	pktEnd := 68 + threatLogMsgLen + int(t.PktLen)
	if pktEnd > 68+threatLogMsgLen+threatLogPktLen {
		pktEnd = 68 + threatLogMsgLen + threatLogPktLen
	}
	t.Packet = append([]byte(nil), b[68+threatLogMsgLen:pktEnd]...)
	hashOff := 68 + threatLogMsgLen + threatLogPktLen
	if len(b) >= hashOff+4 {
		t.DlpNameHash = binary.BigEndian.Uint32(b[hashOff : hashOff+4])
	}
	return t, nil
}

// cString trims a C-style fixed-width char[] at the first NUL.
func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
