package dp

import (
	"strings"
	"testing"
)

// Self-check for ITEM #3 FIX 1: ConfigureDetector must bind the pushed
// network-policy rule ids into ep->dlp_rid_map ALONGSIDE the default id 0, so
// positive-policy sessions get DLP-scanned (dp gates on sess->policy_desc.id in
// the OUTSIDE branch). WAF stays {0}-ONLY on purpose: the OUTSIDE branch has no
// apply_dir gate, so binding policy ids to waf_rid_map would scan those sessions
// in BOTH directions and re-open the DB-egress false positive on a WAF-opted web
// workload — WAF coverage widens only once dp's INSIDE + apply_dir model lands.
func TestConfigureDetector_BindsPushedPolicyRIDs(t *testing.T) {
	srv := newCaptureServer(t)
	c := newClientPointedAt(t, srv)
	sup := &Supervisor{client: c}

	dlp := []*DLPRule{{Name: "secrets", ID: 20001, Patterns: []string{"AKIA"}, Mode: "monitor"}}
	waf := []*WAFRule{{Name: "xss", ID: 40001, Patterns: []WAFPattern{{Context: WAFCtxURL, Value: "<script"}}, Mode: "monitor"}}
	if err := sup.ConfigureDetector([]string{"aa:bb:cc:dd:ee:ff"}, dlp, waf, 42, 43); err != nil {
		t.Fatalf("ConfigureDetector: %v", err)
	}
	body := string(srv.drain(1)[0])

	// DLP: {0} + pushed policy ids (full coverage). WAF: {0} only (FP-safe).
	if !strings.Contains(body, `"rule_ids":[0,42,43]`) {
		t.Errorf("dlp rule_ids must bind {0} + pushed policy ids, got: %s", body)
	}
	if !strings.Contains(body, `"waf_rule_ids":[0]`) {
		t.Errorf("waf_rule_ids must stay {0}-only (FP-safe), got: %s", body)
	}
}
