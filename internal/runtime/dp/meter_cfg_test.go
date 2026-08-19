package dp

import (
	"encoding/json"
	"testing"
)

// TestMeterConfigEncode asserts the config-push encoder emits the expected wire
// kind (`ctrl_cfg_detect`) and per-meter fields, and that env overrides overlay
// onto the NV baseline with LowerLimit clamped to UpperLimit.
func TestMeterConfigEncode(t *testing.T) {
	// Baseline (env unset) must equal NV's compiled defaults.
	t.Setenv(envMeterSynFlood, "")
	t.Setenv(envMeterICMPFlood, "")
	t.Setenv(envMeterSession, "")
	base := meterConfigFromEnv()
	want := []meterThreshold{
		{MeterID: synFloodMeterID, Span: 5, UpperLimit: 800, LowerLimit: 600},
		{MeterID: icmpFloodMeterID, Span: 1, UpperLimit: 100, LowerLimit: 100},
		{MeterID: ipSrcSessionMeterID, Span: 1, UpperLimit: 2000, LowerLimit: 2000},
	}
	for i := range want {
		if base[i] != want[i] {
			t.Fatalf("baseline meter %d = %+v, want %+v", i, base[i], want[i])
		}
	}

	// Override SYN flood below its baseline LowerLimit → LowerLimit clamps down.
	t.Setenv(envMeterSynFlood, "500")
	// Garbage override is ignored, baseline kept.
	t.Setenv(envMeterICMPFlood, "not-a-number")
	got := meterConfigFromEnv()
	if got[0].UpperLimit != 500 || got[0].LowerLimit != 500 {
		t.Fatalf("SYN override = upper %d/lower %d, want 500/500", got[0].UpperLimit, got[0].LowerLimit)
	}
	if got[1].UpperLimit != 100 {
		t.Fatalf("ICMP garbage override changed upper to %d, want 100", got[1].UpperLimit)
	}

	// Encoder must wrap the set under the ctrl_cfg_detect key with snake_case fields.
	b, err := json.Marshal(&dpMeterCfgReq{Cfg: &dpMeterCfg{Meters: got}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var probe map[string]dpMeterCfg
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cfg, ok := probe["ctrl_cfg_detect"]
	if !ok {
		t.Fatalf("wire kind missing ctrl_cfg_detect: %s", b)
	}
	if len(cfg.Meters) != 3 || cfg.Meters[0].MeterID != synFloodMeterID || cfg.Meters[0].UpperLimit != 500 {
		t.Fatalf("decoded meters wrong: %+v", cfg.Meters)
	}
}
