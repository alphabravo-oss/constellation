package handler

import "testing"

func TestSanitizeGrantableVerbs(t *testing.T) {
	// user-grantable verbs pass + dedup
	got, err := sanitizeGrantableVerbs([]string{"read-findings", "read-findings", "manage-policies"})
	if err != nil {
		t.Fatalf("valid verbs rejected: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected dedup to 2, got %v", got)
	}
	// service-only verb rejected (the security boundary)
	if _, err := sanitizeGrantableVerbs([]string{"runtime-ingest"}); err == nil {
		t.Fatal("runtime-ingest must be rejected from a custom role")
	}
	// unknown verb rejected
	if _, err := sanitizeGrantableVerbs([]string{"make-coffee"}); err == nil {
		t.Fatal("unknown verb must be rejected")
	}
}
