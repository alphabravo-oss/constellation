package dp

import (
	"encoding/json"
	"testing"
)

// TestBuildDetector_CombinesDLPAndWAF is the regression guard for the
// shared-detector clobber: BuildDetector must emit ONE ctrl_bld_dlp whose single
// dlp_rules array carries BOTH a DLP-range sig id (20000-29999) and a WAF-range
// sig id (40000-49999), each with string patterns dp can read with
// json_string_value. Two separate builds used to clobber each other's ep
// detector; one combined build keeps every pattern in a single detector.
func TestBuildDetector_CombinesDLPAndWAF(t *testing.T) {
	srv := newCaptureServer(t)
	c := newClientPointedAt(t, srv)

	dlpRules := []*DLPRule{{
		Name: "aws-secret", ID: DLPSigID(9001), Mode: "monitor",
		Patterns: []string{`AKIA[0-9A-Z]{16}`},
	}}
	wafRules := []*WAFRule{{
		Name: "sqli", ID: WAFSigID(0), Mode: "enforce",
		Patterns: []WAFPattern{{Context: WAFCtxHead, Value: `(?i)union.+select`}},
	}}

	sup := &Supervisor{client: c}
	if err := sup.BuildDetector(dlpRules, wafRules, []string{"aa:bb:cc:dd:ee:ff"}, nil, ApplyDirBoth); err != nil {
		t.Fatalf("BuildDetector: %v", err)
	}

	msgs := srv.drain(1)
	if len(msgs) != 1 {
		t.Fatalf("want 1 ctrl_bld_dlp datagram, got %d", len(msgs))
	}

	var env struct {
		Build struct {
			Flag     uint `json:"flag"`
			Dir      int  `json:"dir"`
			DlpRules []struct {
				Name     string            `json:"name"`
				ID       uint32            `json:"id"`
				Patterns []json.RawMessage `json:"patterns"`
			} `json:"dlp_rules"`
		} `json:"ctrl_bld_dlp"`
	}
	if err := json.Unmarshal(msgs[0], &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if env.Build.Flag != (MsgStart | MsgEnd) {
		t.Fatalf("flag = %d, want MSG_START|MSG_END (%d)", env.Build.Flag, MsgStart|MsgEnd)
	}
	if env.Build.Dir != ApplyDirBoth {
		t.Fatalf("dir = %d, want ApplyDirBoth (%d)", env.Build.Dir, ApplyDirBoth)
	}
	if len(env.Build.DlpRules) != 2 {
		t.Fatalf("want 2 rules in one dlp_rules array, got %d", len(env.Build.DlpRules))
	}

	var sawDLP, sawWAF bool
	for _, r := range env.Build.DlpRules {
		switch {
		case r.ID >= dpMinUserSigID && r.ID < dpMinUserSigID+dpUserSigSpan:
			sawDLP = true
		case r.ID >= dpMinWAFSigID && r.ID < dpMinWAFSigID+dpWAFSigSpan:
			sawWAF = true
		default:
			t.Fatalf("rule id %d outside dp's DLP/WAF sig ranges", r.ID)
		}
		if len(r.Patterns) == 0 {
			t.Fatalf("rule %q has no patterns", r.Name)
		}
		// dp reads each pattern with json_string_value → must be a JSON string,
		// not an object (a struct pattern would segfault dp).
		for _, p := range r.Patterns {
			if len(p) == 0 || p[0] != '"' {
				t.Fatalf("rule %q pattern serialized as non-string %s", r.Name, p)
			}
		}
	}
	if !sawDLP {
		t.Fatal("no DLP-range (20000-29999) sig id in the combined build")
	}
	if !sawWAF {
		t.Fatal("no WAF-range (40000-49999) sig id in the combined build")
	}
}

// TestConfigureDetector_BindsBothTables verifies the combined ctrl_cfg_dlp
// carries both the DLP keys (dlp_rule_names/rule_ids/ruletype) and the WAF keys
// (waf_rule_names/waf_rule_ids/wafruletype) in one message, with both ruletype
// strings present so dp's unconditional strcmp never NULL-derefs.
func TestConfigureDetector_BindsBothTables(t *testing.T) {
	srv := newCaptureServer(t)
	c := newClientPointedAt(t, srv)

	dlpRules := []*DLPRule{{Name: "aws", ID: DLPSigID(9001), Mode: "enforce"}}
	wafRules := []*WAFRule{{Name: "sqli", ID: WAFSigID(0), Mode: "enforce"}}

	sup := &Supervisor{client: c}
	if err := sup.ConfigureDetector([]string{"aa:bb:cc:dd:ee:ff"}, dlpRules, wafRules); err != nil {
		t.Fatalf("ConfigureDetector: %v", err)
	}

	msgs := srv.drain(1)
	if len(msgs) != 1 {
		t.Fatalf("want 1 ctrl_cfg_dlp datagram, got %d", len(msgs))
	}

	var env struct {
		Cfg struct {
			DlpRuleNames []struct {
				ID     uint32 `json:"id"`
				Action uint8  `json:"action"`
			} `json:"dlp_rule_names"`
			WafRuleNames []struct {
				ID     uint32 `json:"id"`
				Action uint8  `json:"action"`
			} `json:"waf_rule_names"`
			RuleIds     []uint32 `json:"rule_ids"`
			WafRuleIds  []uint32 `json:"waf_rule_ids"`
			RuleType    string   `json:"ruletype"`
			WafRuleType string   `json:"wafruletype"`
		} `json:"ctrl_cfg_dlp"`
	}
	if err := json.Unmarshal(msgs[0], &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// OUTSIDE mode: the rid arrays gate on the session's policy id (0), which is the
	// only branch that scans default east-west sessions (dpi_search.c). Both keys
	// still present (dp strcmp's both unconditionally).
	if env.Cfg.RuleType != DLPRuleTypeOutside || env.Cfg.WafRuleType != WAFRuleTypeOutside {
		t.Fatalf("ruletype=%q wafruletype=%q, want outside/wafoutside", env.Cfg.RuleType, env.Cfg.WafRuleType)
	}
	if len(env.Cfg.DlpRuleNames) != 1 || env.Cfg.DlpRuleNames[0].Action != DPIActionDrop {
		t.Fatalf("dlp binding = %+v, want 1 rule with DROP", env.Cfg.DlpRuleNames)
	}
	if len(env.Cfg.WafRuleNames) != 1 || env.Cfg.WafRuleNames[0].Action != DPIActionReset {
		t.Fatalf("waf binding = %+v, want 1 rule with RESET", env.Cfg.WafRuleNames)
	}
	if len(env.Cfg.RuleIds) != 1 || env.Cfg.RuleIds[0] != 0 || len(env.Cfg.WafRuleIds) != 1 || env.Cfg.WafRuleIds[0] != 0 {
		t.Fatalf("rule_ids=%v waf_rule_ids=%v, want [0] each (bind default policy id, not sigids)", env.Cfg.RuleIds, env.Cfg.WafRuleIds)
	}
}
