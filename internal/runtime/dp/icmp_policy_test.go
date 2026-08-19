package dp

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
)

// TestICMPPolicy is the G2.4 self-check: an IPProtoICMP rule must serialise
// with proto 1 in the built dp policy entry, and SetICMPPolicy must emit the
// ctrl_enable_icmp_policy gate that dp reads. Reuses captureServer /
// newClientPointedAt from policy_test.go (same package).
func TestICMPPolicy(t *testing.T) {
	srv := newCaptureServer(t)
	c := newClientPointedAt(t, srv)

	policy := &WorkloadPolicy{
		WorkloadID: "default/api",
		ApplyDir:   ApplyDirBoth,
		MACs:       []string{"aa:bb:cc:dd:ee:ff"},
		Rules: []*PolicyRule{
			{ID: 1, Ingress: true, SrcIP: net.ParseIP("10.0.0.0"), DstIP: net.ParseIP("10.42.0.5"),
				IPProto: IPProtoICMP, Action: PolicyActionDeny},
		},
	}
	if err := c.pushPolicy(policy, CmdModify); err != nil {
		t.Fatalf("pushPolicy: %v", err)
	}
	dgs := srv.drain(1)
	if len(dgs) != 1 {
		t.Fatalf("got %d datagrams, want 1", len(dgs))
	}
	var env policyCfgReq
	if err := json.Unmarshal(dgs[0], &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(env.Cfg.IPRules) != 1 {
		t.Fatalf("rules=%d want 1", len(env.Cfg.IPRules))
	}
	if got := env.Cfg.IPRules[0].IPProto; got != IPProtoICMP {
		t.Errorf("built rule proto=%d want IPProtoICMP(%d)", got, IPProtoICMP)
	}
	if IPProtoICMP != 1 {
		t.Errorf("IPProtoICMP=%d want 1 (drifted from IPPROTO_ICMP)", IPProtoICMP)
	}

	// The gate is additive: sending it emits ctrl_enable_icmp_policy=true so
	// dp actually enforces the ICMP rule instead of blanket-allowing ICMP.
	if err := (&Supervisor{client: c}).SetICMPPolicy(true); err != nil {
		t.Fatalf("SetICMPPolicy: %v", err)
	}
	g := srv.drain(1)
	if len(g) != 1 {
		t.Fatalf("gate: got %d datagrams, want 1", len(g))
	}
	if body := string(g[0]); !strings.Contains(body, `"ctrl_enable_icmp_policy"`) ||
		!strings.Contains(body, `"enable_icmp_policy":true`) {
		t.Errorf("gate envelope wrong: %s", body)
	}
}
