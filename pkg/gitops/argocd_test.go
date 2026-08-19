package gitops

import "testing"

func TestDetectDrift_FindsModifiedAndOrphanedResources(t *testing.T) {
	declared := []Resource{
		{Kind: "RoleBinding", Name: "rb-1", Namespace: "default", Spec: map[string]any{"subjects": []any{"alice"}}},
		{Kind: "NetworkPolicy", Name: "np-1", Namespace: "default", Spec: map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"app": "x"}}}},
	}
	live := []Resource{
		{Kind: "RoleBinding", Name: "rb-1", Namespace: "default", Spec: map[string]any{"subjects": []any{"alice", "EVIL"}}}, // tampered
		{Kind: "RoleBinding", Name: "rb-2", Namespace: "default", Spec: map[string]any{"subjects": []any{"bob"}}},          // out-of-band addition
		// np-1 missing → declared-but-not-in-cluster
	}
	drift := DetectDrift("argocd", "demo-app", declared, live)
	if len(drift) != 3 {
		t.Fatalf("expected 3 drift findings, got %d: %+v", len(drift), drift)
	}
	got := map[string]string{}
	for _, d := range drift {
		got[d.Name] = d.DiffSummary
	}
	if !contains(got["rb-1"], "declared sha") {
		t.Fatalf("rb-1 should be modified-drift: %s", got["rb-1"])
	}
	if !contains(got["rb-2"], "not declared") {
		t.Fatalf("rb-2 should be out-of-band: %s", got["rb-2"])
	}
	if !contains(got["np-1"], "missing from cluster") {
		t.Fatalf("np-1 should be declared-only: %s", got["np-1"])
	}
}

func TestIsSensitive(t *testing.T) {
	for _, k := range []string{"RoleBinding", "NetworkPolicy", "Secret"} {
		if !IsSensitive(k) {
			t.Fatalf("%s should be sensitive", k)
		}
	}
	if IsSensitive("ConfigMap") {
		t.Fatal("ConfigMap is not in the sensitive set")
	}
}

func contains(s, needle string) bool {
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
