package dp

import (
	"strings"
	"testing"
)

// TestConfigureDLPRules_ActionBinding verifies the ctrl_cfg_dlp envelope
// carries the per-rule action derived from mode: enforce → DROP (2),
// monitor → ALLOW (1). This is the P0-1 binding that makes an enforce rule
// actually block instead of alert-only.
func TestConfigureDLPRules_ActionBinding(t *testing.T) {
	srv := newCaptureServer(t)
	c := newClientPointedAt(t, srv)

	rules := []*DLPRule{
		{Name: "secrets", ID: 9001, Patterns: []string{"AKIA"}, Mode: "enforce"},
		{Name: "pii", ID: 9002, Patterns: []string{"ssn"}, Mode: "monitor"},
	}
	// Exercise the same wire builder ConfigureDLPRules uses.
	bindings := make([]*dlpRidSetting, 0, len(rules))
	ids := make([]uint32, 0, len(rules))
	for _, r := range rules {
		bindings = append(bindings, &dlpRidSetting{ID: r.ID, Action: DLPModeAction(r.Mode)})
		ids = append(ids, r.ID)
	}
	if err := c.sendOneway(&dlpCfgReq{Cfg: &dlpCfgPayload{
		Flag: MsgStart | MsgEnd, WorkloadMac: []string{"aa:bb:cc:dd:ee:ff"},
		DlpRuleNames: bindings, RuleIds: ids, RuleType: "dlp",
	}}); err != nil {
		t.Fatalf("sendOneway: %v", err)
	}
	body := string(srv.drain(1)[0])
	if !strings.Contains(body, `"ctrl_cfg_dlp"`) {
		t.Errorf("missing ctrl_cfg_dlp envelope: %s", body)
	}
	// enforce rule 9001 must bind action 2 (DROP).
	if !strings.Contains(body, `{"id":9001,"action":2}`) {
		t.Errorf("enforce rule missing DROP action: %s", body)
	}
	// monitor rule 9002 must bind action 1 (ALLOW / alert-only).
	if !strings.Contains(body, `{"id":9002,"action":1}`) {
		t.Errorf("monitor rule missing ALLOW action: %s", body)
	}
}

func TestDLPModeAction(t *testing.T) {
	if DLPModeAction("enforce") != DPIActionDrop {
		t.Errorf("enforce must map to DROP (%d)", DPIActionDrop)
	}
	for _, m := range []string{"monitor", "disabled", "", "bogus"} {
		if DLPModeAction(m) != DPIActionAllow {
			t.Errorf("mode %q must map to ALLOW (%d) — SAFETY default", m, DPIActionAllow)
		}
	}
}
