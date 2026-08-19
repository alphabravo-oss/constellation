package dp

import (
	"strings"
	"testing"
)

// Self-check for the OUTSIDE-mode detection gate (FIX 1). dp gates DLP/WAF on the
// SESSION's network-policy id (key.rid = sess->policy_desc.id), not on the sigid.
// The cfg must therefore run ruletype/wafruletype = OUTSIDE and bind rid {0} (the
// default east-west session id) into ep->{dlp,waf}_rid_map, while the sigids stay
// only in the *_rule_names bindings. Sending sigids as rule_ids (the old INSIDE
// path) never matched a session id, so dpi_process_detector never fired.
func TestConfigureDetector_OutsideGateBindsPolicyID(t *testing.T) {
	if defaultSessionRID != 0 {
		t.Fatalf("defaultSessionRID = %d, want 0 (dp's default/unmatched policy id)", defaultSessionRID)
	}
	srv := newCaptureServer(t)
	c := newClientPointedAt(t, srv)
	sup := &Supervisor{client: c}

	dlp := []*DLPRule{{Name: "secrets", ID: 20001, Patterns: []string{"AKIA"}, Mode: "enforce"}}
	waf := []*WAFRule{{Name: "xss", ID: 40001, Patterns: []WAFPattern{{Context: WAFCtxURL, Value: "<script"}}, Mode: "monitor"}}
	if err := sup.ConfigureDetector([]string{"aa:bb:cc:dd:ee:ff"}, dlp, waf); err != nil {
		t.Fatalf("ConfigureDetector: %v", err)
	}
	body := string(srv.drain(1)[0])

	// OUTSIDE ruletypes both present (dp strcmp's both unconditionally).
	if !strings.Contains(body, `"ruletype":"outside"`) {
		t.Errorf("ruletype not outside: %s", body)
	}
	if !strings.Contains(body, `"wafruletype":"wafoutside"`) {
		t.Errorf("wafruletype not wafoutside: %s", body)
	}
	// rid maps gate on policy id 0, NOT the sigids.
	if !strings.Contains(body, `"rule_ids":[0]`) {
		t.Errorf("rule_ids must bind policy id [0], got: %s", body)
	}
	if !strings.Contains(body, `"waf_rule_ids":[0]`) {
		t.Errorf("waf_rule_ids must bind policy id [0], got: %s", body)
	}
	// sigids still carried in the *_rule_names bindings (dlp_cfg_map / waf_cfg_map).
	if !strings.Contains(body, `"id":20001`) || !strings.Contains(body, `"id":40001`) {
		t.Errorf("sigids missing from rule_names bindings: %s", body)
	}
	// sigids must NOT leak into the rid arrays.
	if strings.Contains(body, `"rule_ids":[20001`) || strings.Contains(body, `"waf_rule_ids":[40001`) {
		t.Errorf("sigids leaked into rid arrays (the original bug): %s", body)
	}
}
