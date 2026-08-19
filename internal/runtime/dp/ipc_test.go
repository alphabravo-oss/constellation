package dp

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestIPCDispatchEmitsTypedEvents(t *testing.T) {
	tests := []struct {
		name  string
		msg   []byte
		check func(t *testing.T, ev Event)
	}{
		{
			name: "connection",
			msg:  dpDatagram(KindConnection, testConnectionPayload(1)),
			check: func(t *testing.T, ev Event) {
				t.Helper()
				if ev.Kind != EventConnection || ev.Conn == nil {
					t.Fatalf("event = %+v, want connection", ev)
				}
				if got, want := ev.Conn.ClientIP.String(), "10.1.2.3"; got != want {
					t.Fatalf("client IP = %q, want %q", got, want)
				}
				if ev.Conn.PolicyAction != PolicyActionViolate || ev.Conn.Application != 1001 {
					t.Fatalf("connection metadata = %+v", ev.Conn)
				}
			},
		},
		{
			name: "threat log",
			msg:  dpDatagram(KindThreatLog, testThreatPayload()),
			check: func(t *testing.T, ev Event) {
				t.Helper()
				if ev.Kind != EventThreat || ev.Threat == nil {
					t.Fatalf("event = %+v, want threat", ev)
				}
				if ev.Threat.ThreatID != 4242 || ev.Threat.Msg != "sql injection" {
					t.Fatalf("threat = %+v", ev.Threat)
				}
				if !ev.Threat.PktIngress || !ev.Threat.SessIngress || ev.Threat.Tap {
					t.Fatalf("threat flags = %+v", ev.Threat)
				}
				if string(ev.Threat.Packet) != "GET / HTTP/1.1" {
					t.Fatalf("packet = %q", string(ev.Threat.Packet))
				}
			},
		},
		{
			name: "session list",
			msg:  dpDatagram(KindSessionList, testSessionPayload(2)),
			check: func(t *testing.T, ev Event) {
				t.Helper()
				if ev.Kind != EventSession || len(ev.Sessions) != 2 {
					t.Fatalf("event = %+v, want two sessions", ev)
				}
				if got, want := ev.Sessions[1].ClientIP.String(), "10.0.0.2"; got != want {
					t.Fatalf("second client IP = %q, want %q", got, want)
				}
			},
		},
		{
			name: "keepalive",
			msg:  dpDatagram(KindKeepAlive, nil),
			check: func(t *testing.T, ev Event) {
				t.Helper()
				if ev.Kind != EventKeepAlive {
					t.Fatalf("event = %+v, want keepalive", ev)
				}
			},
		},
		{
			name: "parser metadata stays observable as raw kind",
			msg:  dpDatagram(KindAppUpdate, []byte("parser-app-update")),
			check: func(t *testing.T, ev Event) {
				t.Helper()
				if ev.Kind != EventOther || ev.RawKind != KindAppUpdate {
					t.Fatalf("event = %+v, want raw app-update metadata", ev)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := make(chan Event, 4)
			server := newIPCServer(t.TempDir()+"/listen.sock", newSilentLogger(), out)
			server.dispatch(tt.msg)
			if got := server.snapshot().RxTotal; got != 0 {
				t.Fatalf("dispatch should not mutate read-loop rx total directly, got %d", got)
			}
			select {
			case ev := <-out:
				if ev.At.IsZero() {
					t.Fatal("event timestamp is zero")
				}
				tt.check(t, ev)
			default:
				t.Fatal("no event emitted")
			}
		})
	}
}

func TestIPCDispatchCountsMalformedMessages(t *testing.T) {
	out := make(chan Event, 1)
	server := newIPCServer(t.TempDir()+"/listen.sock", newSilentLogger(), out)

	server.dispatch([]byte{KindKeepAlive, 0, 0, 99})
	if got := server.snapshot().RxBadHdr; got != 1 {
		t.Fatalf("bad header count = %d, want 1", got)
	}

	server.dispatch(dpDatagram(KindConnection, []byte{0, 1}))
	if got := server.snapshot().RxBadPL; got != 1 {
		t.Fatalf("bad payload count = %d, want 1", got)
	}
	if len(out) != 0 {
		t.Fatalf("unexpected event emitted for malformed messages: %+v", <-out)
	}
}

func TestIPCDispatchCountsBackPressureDrops(t *testing.T) {
	out := make(chan Event)
	server := newIPCServer(t.TempDir()+"/listen.sock", newSilentLogger(), out)

	server.dispatch(dpDatagram(KindKeepAlive, nil))
	if got := server.snapshot().RxDrop; got != 1 {
		t.Fatalf("drop count = %d, want 1", got)
	}
}

func dpDatagram(kind uint8, payload []byte) []byte {
	msg := make([]byte, dpMsgHdrSize+len(payload))
	msg[0] = kind
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(msg)))
	copy(msg[dpMsgHdrSize:], payload)
	return msg
}

func testConnectionPayload(count int) []byte {
	payload := make([]byte, dpMsgConnectHdrSize+count*dpMsgConnectSize)
	binary.BigEndian.PutUint16(payload[0:2], uint16(count))
	for i := 0; i < count; i++ {
		record := payload[dpMsgConnectHdrSize+i*dpMsgConnectSize : dpMsgConnectHdrSize+(i+1)*dpMsgConnectSize]
		copy(record[0:6], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(0xff - i)})
		record[6] = 6
		binary.BigEndian.PutUint16(record[8:10], 8080)
		binary.BigEndian.PutUint16(record[10:12], uint16(54000+i))
		copy(record[12:16], net.ParseIP("10.1.2.3").To4())
		copy(record[28:32], net.ParseIP("10.4.5.6").To4())
		binary.BigEndian.PutUint16(record[44:46], ethTypeIPv4)
		binary.BigEndian.PutUint16(record[46:48], ConnFlagIngress|ConnFlagExternal)
		binary.BigEndian.PutUint32(record[48:52], 2048)
		binary.BigEndian.PutUint32(record[52:56], 2)
		binary.BigEndian.PutUint16(record[64:66], 1001)
		record[66] = PolicyActionViolate
		record[67] = 5
		binary.BigEndian.PutUint32(record[68:72], 77)
		binary.BigEndian.PutUint32(record[76:80], 4242)
	}
	return payload
}

func testThreatPayload() []byte {
	payload := make([]byte, dpMsgThreatLogSize)
	binary.BigEndian.PutUint32(payload[0:4], 4242)
	binary.BigEndian.PutUint32(payload[4:8], 1_700_000_000)
	binary.BigEndian.PutUint32(payload[8:12], 3)
	payload[12] = PolicyActionDeny
	payload[13] = 5
	payload[14] = 6
	payload[15] = ThreatFlagPktIngress | ThreatFlagSessIngress
	copy(payload[16:22], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	binary.BigEndian.PutUint16(payload[22:24], ethTypeIPv4)
	copy(payload[24:28], net.ParseIP("10.1.2.3").To4())
	copy(payload[40:44], net.ParseIP("10.4.5.6").To4())
	binary.BigEndian.PutUint16(payload[56:58], 54321)
	binary.BigEndian.PutUint16(payload[58:60], 8080)
	binary.BigEndian.PutUint16(payload[62:64], 1001)
	packet := []byte("GET / HTTP/1.1")
	binary.BigEndian.PutUint16(payload[64:66], uint16(len(packet)))
	binary.BigEndian.PutUint16(payload[66:68], uint16(len(packet)))
	copy(payload[68:68+threatLogMsgLen], []byte("sql injection"))
	copy(payload[68+threatLogMsgLen:], packet)
	hashOff := 68 + threatLogMsgLen + threatLogPktLen
	binary.BigEndian.PutUint32(payload[hashOff:hashOff+4], 999)
	return payload
}

func testSessionPayload(count int) []byte {
	payload := make([]byte, dpMsgSessionHdrSize+count*dpMsgSessionSize)
	binary.BigEndian.PutUint16(payload[0:2], uint16(count))
	for i := 0; i < count; i++ {
		record := payload[dpMsgSessionHdrSize+i*dpMsgSessionSize : dpMsgSessionHdrSize+(i+1)*dpMsgSessionSize]
		binary.BigEndian.PutUint32(record[0:4], uint32(i+1))
		copy(record[4:10], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(0xff - i)})
		binary.BigEndian.PutUint16(record[10:12], ethTypeIPv4)
		copy(record[24:28], net.ParseIP("10.0.0."+string(rune('1'+i))).To4())
		copy(record[40:44], net.ParseIP("10.42.0.5").To4())
		binary.BigEndian.PutUint16(record[56:58], uint16(54000+i))
		binary.BigEndian.PutUint16(record[58:60], 8080)
		record[62] = 6
		binary.BigEndian.PutUint32(record[72:76], uint32(1000+i))
		binary.BigEndian.PutUint32(record[76:80], uint32(2000+i))
		binary.BigEndian.PutUint16(record[106:108], 1001)
		record[116] = PolicyActionAllow
	}
	return payload
}
