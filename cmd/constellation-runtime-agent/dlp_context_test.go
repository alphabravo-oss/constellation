package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// TestDLPRuleWireParsesPatternForms verifies NET-40 bundle decoding: a rule's
// `patterns` array may mix legacy bare strings and {pattern, op, context}
// objects, and both populate the index-aligned Patterns/Ops/Contexts slices.
func TestDLPRuleWireParsesPatternForms(t *testing.T) {
	raw := `{"dp_rule_id":9001,"name":"r","mode":"monitor",
	  "patterns":[
	    "legacy-str",
	    {"pattern":"cc","context":"body"},
	    {"pattern":"tok","op":"not_regex","context":"header"}
	  ]}`
	var r dlpRuleWire
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	wantPats := []string{"legacy-str", "cc", "tok"}
	wantOps := []string{"", "", "not_regex"}
	wantCtx := []string{"", "body", "header"}
	if strings.Join(r.Patterns, "|") != strings.Join(wantPats, "|") {
		t.Errorf("patterns = %v, want %v", r.Patterns, wantPats)
	}
	if strings.Join(r.Ops, "|") != strings.Join(wantOps, "|") {
		t.Errorf("ops = %v, want %v", r.Ops, wantOps)
	}
	if strings.Join(r.Contexts, "|") != strings.Join(wantCtx, "|") {
		t.Errorf("contexts = %v, want %v", r.Contexts, wantCtx)
	}
}

// TestApplyDLPOps checks op negation: not_regex prepends "!" (which dp's
// NormalizePCREPattern understands), regex/"" pass through, and an already-"!"
// pattern is not double-negated.
func TestApplyDLPOps(t *testing.T) {
	got := applyDLPOps(
		[]string{"a", "b", "c", "!d"},
		[]string{"regex", "not_regex", "", "not"},
	)
	want := []string{"a", "!b", "c", "!d"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("applyDLPOps = %v, want %v", got, want)
	}
}

// TestPlanDLPPushesThreadsContext is the end-to-end NET-40 assertion: a bundle
// rule with per-pattern contexts (+ a not_regex op) flows through planDLPPushes
// into a dp.DLPRule whose Contexts/Patterns, once normalized to the dp wire form,
// carry the right "; context <ctx>" per pattern.
func TestPlanDLPPushesThreadsContext(t *testing.T) {
	raw := `{"dp_rule_id":9001,"name":"pii","mode":"monitor",
	  "patterns":[
	    {"pattern":"AKIA[0-9A-Z]{16}","context":"uri"},
	    {"pattern":"secret","op":"not_regex","context":"header"}
	  ]}`
	var r dlpRuleWire
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	pushes := planDLPPushes([]dlpRuleWire{r}, []string{"aa:bb:cc:dd:ee:ff"}, false)
	if len(pushes) != 1 || len(pushes[0].rules) != 1 {
		t.Fatalf("want 1 push/1 rule, got %+v", pushes)
	}
	dr := pushes[0].rules[0]
	// Contexts are threaded index-aligned into the dp.DLPRule; dp folds them
	// into the "; context <ctx>" wire suffix (asserted in the dp package test).
	if strings.Join(dr.Contexts, "|") != "uri|header" {
		t.Errorf("dp.DLPRule.Contexts = %v, want [uri header]", dr.Contexts)
	}
	// not_regex must have negated the second pattern (dp's NormalizePCREPattern
	// then turns the leading "!" into a dp negated match).
	if dr.Patterns[1] != "!secret" {
		t.Errorf("op not applied: %q", dr.Patterns[1])
	}
}

// TestSuppressDLPFalsePositive is the NET-41 gate: for a registered built-in PII
// sig id, a hit whose packet has no Luhn-valid card is dropped, while a valid PAN
// (or an unregistered sig, or an empty packet) is kept.
func TestSuppressDLPFalsePositive(t *testing.T) {
	rules := []dlpRuleWire{{DPRuleID: 7001, Name: "builtin-dlp-federal-pii", Mode: "monitor"}}
	setValidatedThreatIDs(rules)
	sig := dp.DLPSigID(7001)

	// Invalid PAN under the registered sig ⇒ suppress.
	if !suppressDLPFalsePositive(threatIngestRow{ThreatID: sig, Packet: []byte("order=4111111111111112")}) {
		t.Errorf("invalid-PAN false positive not suppressed")
	}
	// Valid PAN ⇒ keep.
	if suppressDLPFalsePositive(threatIngestRow{ThreatID: sig, Packet: []byte("card=4111111111111111")}) {
		t.Errorf("valid PAN wrongly suppressed")
	}
	// Empty packet ⇒ keep (fail-open).
	if suppressDLPFalsePositive(threatIngestRow{ThreatID: sig}) {
		t.Errorf("empty packet wrongly suppressed")
	}
	// Unregistered sig id ⇒ keep (never touch non-PII threats).
	if suppressDLPFalsePositive(threatIngestRow{ThreatID: sig + 12345, Packet: []byte("order=4111111111111112")}) {
		t.Errorf("unregistered sig wrongly suppressed")
	}
}
