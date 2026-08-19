package dp

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// captureClient is a dpClient hooked up to a real unixgram socket that
// we own from the test, so PushPolicy's send path runs end-to-end
// (connect + write) without requiring an actual dp subprocess. Every
// datagram we receive is stored for inspection.
type captureServer struct {
	t    *testing.T
	addr string
	conn *net.UnixConn
}

func newCaptureServer(t *testing.T) *captureServer {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/dp_listen.sock"
	_ = os.Remove(path)
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = os.Remove(path) })
	return &captureServer{t: t, addr: path, conn: c}
}

// drain reads up to `n` datagrams with a short timeout each. Returns
// whatever it got — caller asserts on count.
func (s *captureServer) drain(n int) [][]byte {
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, DPMsgSize)
		_ = s.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		k, _, err := s.conn.ReadFromUnix(buf)
		if err != nil {
			break
		}
		out = append(out, append([]byte(nil), buf[:k]...))
	}
	return out
}

// newClientPointedAt returns a dpClient whose DialUnix raddr is the
// capture server's socket. We bypass dpClient.connect() (which assumes the
// hardcoded DP_SERVER_SOCK) by dialing manually.
func newClientPointedAt(t *testing.T, srv *captureServer) *dpClient {
	t.Helper()
	c := newDPClient(newSilentLogger())
	laddrPath := t.TempDir() + "/dp_client.sock"
	_ = os.Remove(laddrPath)
	conn, err := net.DialUnix("unixgram",
		&net.UnixAddr{Name: laddrPath, Net: "unixgram"},
		&net.UnixAddr{Name: srv.addr, Net: "unixgram"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(); _ = os.Remove(laddrPath) })
	c.conn = conn
	return c
}

// TestPushPolicy_SingleMessage verifies a small policy fits in one datagram
// with MSG_START|MSG_END both set, and that the wire shape parses as the
// expected JSON envelope.
func TestPushPolicy_SingleMessage(t *testing.T) {
	srv := newCaptureServer(t)
	c := newClientPointedAt(t, srv)

	policy := &WorkloadPolicy{
		WorkloadID: "default/api",
		Mode:       "monitor",
		DefAction:  PolicyActionAllow,
		ApplyDir:   ApplyDirBoth,
		MACs:       []string{"aa:bb:cc:dd:ee:ff"},
		Rules: []*PolicyRule{
			{ID: 1, Ingress: true, SrcIP: net.ParseIP("10.0.0.0"), DstIP: net.ParseIP("10.42.0.5"),
				Port: 80, IPProto: 6, Action: PolicyActionViolate},
			{ID: 2, Ingress: false, SrcIP: net.ParseIP("10.42.0.5"), DstIP: net.ParseIP("0.0.0.0"),
				Port: 443, IPProto: 6, Action: PolicyActionAllow},
		},
	}
	if err := c.pushPolicy(policy, CmdModify); err != nil {
		t.Fatalf("pushPolicy: %v", err)
	}
	datagrams := srv.drain(2)
	if len(datagrams) != 1 {
		t.Fatalf("got %d datagrams, want 1", len(datagrams))
	}
	var env policyCfgReq
	if err := json.Unmarshal(datagrams[0], &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Cfg == nil {
		t.Fatal("Cfg nil")
	}
	if env.Cfg.Cmd != CmdModify {
		t.Errorf("cmd=%d want %d", env.Cfg.Cmd, CmdModify)
	}
	if env.Cfg.Flag != (MsgStart | MsgEnd) {
		t.Errorf("flag=0x%x want 0x%x", env.Cfg.Flag, MsgStart|MsgEnd)
	}
	if len(env.Cfg.IPRules) != 2 {
		t.Errorf("rules=%d want 2", len(env.Cfg.IPRules))
	}
	if got := env.Cfg.WorkloadMac; len(got) != 1 || got[0] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac=%v want [aa:bb:cc:dd:ee:ff]", got)
	}
	if env.Cfg.DefAction != PolicyActionAllow {
		t.Errorf("defact=%d want %d", env.Cfg.DefAction, PolicyActionAllow)
	}
}

// TestPushPolicy_Fragmentation verifies that a policy bigger than one
// datagram fragments at ~40 rules per message, with MSG_START on the
// first datagram, MSG_END on the last, and neither bit on middles.
func TestPushPolicy_Fragmentation(t *testing.T) {
	srv := newCaptureServer(t)
	c := newClientPointedAt(t, srv)

	const n = 95
	rules := make([]*PolicyRule, n)
	for i := range rules {
		rules[i] = &PolicyRule{
			ID:      uint32(i + 1),
			Ingress: i%2 == 0,
			SrcIP:   net.ParseIP("10.0.0.1"),
			DstIP:   net.ParseIP("10.42.0.5"),
			Port:    uint16(8000 + i),
			IPProto: 6,
			Action:  PolicyActionAllow,
		}
	}
	policy := &WorkloadPolicy{
		WorkloadID: "default/api",
		ApplyDir:   ApplyDirBoth,
		MACs:       []string{"aa:bb:cc:dd:ee:ff"},
		Rules:      rules,
	}
	if err := c.pushPolicy(policy, CmdModify); err != nil {
		t.Fatalf("pushPolicy: %v", err)
	}
	// 95 rules @ ~40/msg → 3 datagrams.
	datagrams := srv.drain(8)
	if len(datagrams) < 2 {
		t.Fatalf("got %d datagrams, want at least 2 (fragmentation)", len(datagrams))
	}
	totalRules := 0
	for i, dg := range datagrams {
		var env policyCfgReq
		if err := json.Unmarshal(dg, &env); err != nil {
			t.Fatalf("datagram %d unmarshal: %v", i, err)
		}
		// Flag rules: first has MSG_START, last has MSG_END, middles have neither.
		isFirst := i == 0
		isLast := i == len(datagrams)-1
		hasStart := env.Cfg.Flag&MsgStart != 0
		hasEnd := env.Cfg.Flag&MsgEnd != 0
		if isFirst && !hasStart {
			t.Errorf("datagram %d: missing MSG_START", i)
		}
		if !isFirst && hasStart {
			t.Errorf("datagram %d: MSG_START on non-first fragment", i)
		}
		if isLast && !hasEnd {
			t.Errorf("datagram %d: missing MSG_END", i)
		}
		if !isLast && hasEnd {
			t.Errorf("datagram %d: MSG_END on non-last fragment", i)
		}
		if len(dg) > DPMsgSize {
			t.Errorf("datagram %d size %d > DP_MSG_SIZE %d", i, len(dg), DPMsgSize)
		}
		totalRules += len(env.Cfg.IPRules)
	}
	if totalRules != n {
		t.Errorf("total rules across fragments = %d, want %d", totalRules, n)
	}
}

// TestPushPolicy_DeleteClearsTable verifies that CmdDelete with no rules
// still sends one datagram (so dp clears its table for the workload).
func TestPushPolicy_DeleteClearsTable(t *testing.T) {
	srv := newCaptureServer(t)
	c := newClientPointedAt(t, srv)

	policy := &WorkloadPolicy{
		WorkloadID: "default/api",
		ApplyDir:   ApplyDirBoth,
		MACs:       []string{"aa:bb:cc:dd:ee:ff"},
	}
	if err := c.pushPolicy(policy, CmdDelete); err != nil {
		t.Fatalf("pushPolicy: %v", err)
	}
	dgs := srv.drain(2)
	if len(dgs) != 1 {
		t.Fatalf("got %d datagrams, want 1", len(dgs))
	}
	var env policyCfgReq
	if err := json.Unmarshal(dgs[0], &env); err != nil {
		t.Fatal(err)
	}
	if env.Cfg.Cmd != CmdDelete {
		t.Errorf("cmd=%d want %d", env.Cfg.Cmd, CmdDelete)
	}
	if env.Cfg.Flag != (MsgStart | MsgEnd) {
		t.Errorf("flag=0x%x want both START|END set on single-msg delete", env.Cfg.Flag)
	}
	if len(env.Cfg.IPRules) != 0 {
		t.Errorf("rules=%d want 0 on delete", len(env.Cfg.IPRules))
	}
}

// TestBuildDLPRules verifies the ctrl_bld_dlp envelope round-trips with
// the pattern list dp expects.
func TestBuildDLPRules(t *testing.T) {
	srv := newCaptureServer(t)
	c := newClientPointedAt(t, srv)

	rules := []*DLPRule{
		{Name: "aws-keys", ID: 9001, Patterns: []string{`AKIA[0-9A-Z]{16}`}},
		{Name: "credit-cards", ID: 9002, Patterns: []string{
			`\b4[0-9]{12}(?:[0-9]{3})?\b`,
			`\b5[1-5][0-9]{14}\b`,
		}},
	}
	if err := c.sendOneway(&dlpBuildReq{Build: &dlpBuildPayload{
		Flag: MsgStart | MsgEnd, ApplyDir: ApplyDirEgress,
		DlpRules: rules, WorkloadMac: []string{"aa:bb:cc:dd:ee:ff"},
	}}); err != nil {
		t.Fatalf("sendOneway: %v", err)
	}
	dgs := srv.drain(1)
	if len(dgs) != 1 {
		t.Fatalf("got %d datagrams, want 1", len(dgs))
	}
	// Just sanity-check the envelope key + pattern presence; full
	// re-decode is overkill for a build_dlp invocation.
	body := string(dgs[0])
	if !strings.Contains(body, `"ctrl_bld_dlp"`) {
		t.Errorf("envelope missing ctrl_bld_dlp: %s", body)
	}
	if !strings.Contains(body, "AKIA") {
		t.Errorf("AKIA pattern missing")
	}
	if !strings.Contains(body, `"id":9001`) {
		t.Errorf("rule id missing")
	}
}

// TestPushPolicy_NilPolicyReturnsError covers the defensive nil check.
func TestPushPolicy_NilPolicy(t *testing.T) {
	c := newDPClient(newSilentLogger())
	if err := c.pushPolicy(nil, CmdModify); err == nil {
		t.Error("expected error for nil policy")
	}
}

// Ensure ApplyDir constants line up with dp's defs.h values. Hard-coded
// from third_party/neuvector/defs.h:220-221.
func TestApplyDirConstants(t *testing.T) {
	if ApplyDirEgress != 0x1 || ApplyDirIngress != 0x2 || ApplyDirBoth != 0x3 {
		t.Errorf("ApplyDir constants drifted from defs.h: %d %d %d",
			ApplyDirEgress, ApplyDirIngress, ApplyDirBoth)
	}
	if CmdAdd != 1 || CmdModify != 2 || CmdDelete != 3 {
		t.Errorf("Cmd constants drifted from defs.h: %d %d %d",
			CmdAdd, CmdModify, CmdDelete)
	}
	if MsgStart != 0x1 || MsgEnd != 0x2 {
		t.Errorf("Msg constants drifted from defs.h: %x %x", MsgStart, MsgEnd)
	}
}
