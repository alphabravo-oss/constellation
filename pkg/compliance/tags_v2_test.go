package compliance

import "testing"

func TestBuildTagsV2_KnownInternal(t *testing.T) {
	got := BuildTagsV2("k8s.api.audit-logging")
	if len(got) == 0 {
		t.Fatal("expected non-empty tags for known check")
	}
	if got[FrameworkCISK8s].References[0] != "1.2.22" {
		t.Errorf("CIS K8s ref: want 1.2.22, got %s", got[FrameworkCISK8s].References[0])
	}
	if got[FrameworkPCIDSS4].Profile != FrameworkPCIDSS4 {
		t.Errorf("PCI profile mismatch")
	}
}

func TestBuildTagsV2_UnknownInternal(t *testing.T) {
	if got := BuildTagsV2("nonexistent.check"); len(got) != 0 {
		t.Fatalf("expected empty, got %+v", got)
	}
}

func TestFilterByProfile(t *testing.T) {
	tags := TagsV2{FrameworkPCIDSS4: ProfileTag{Profile: FrameworkPCIDSS4}}
	if !FilterByProfile(tags, "") {
		t.Fatal("empty profile must match")
	}
	if !FilterByProfile(tags, FrameworkPCIDSS4) {
		t.Fatal("matching profile must pass")
	}
	if FilterByProfile(tags, FrameworkSOC2) {
		t.Fatal("non-matching profile must reject")
	}
}

func TestSortedProfiles(t *testing.T) {
	tags := TagsV2{FrameworkSOC2: ProfileTag{}, FrameworkCISK8s: ProfileTag{}}
	got := SortedProfiles(tags)
	if got[0] != FrameworkCISK8s {
		t.Fatalf("expected cis-k8s first, got %v", got)
	}
}
