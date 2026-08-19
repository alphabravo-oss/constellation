package handler

import "testing"

// TestFedProfileKind covers the P2-3 revision-kind classifier: the two runtime-
// profile kinds that expose a runtime-agent pull bundle (and their `_delete`
// tombstones) route to the generic fed_runtime_profiles table, while the legacy
// kinds, the dropped network_policy kind, and unknown strings do not.
func TestFedProfileKind(t *testing.T) {
	profile := []string{
		"file_profile", "file_profile_delete",
		"host_process_profile", "host_process_profile_delete",
	}
	for _, k := range profile {
		if !fedProfileKind(k) {
			t.Errorf("fedProfileKind(%q) = false, want true", k)
		}
	}

	notProfile := []string{
		"policy", "policy_delete", "group", "group_delete",
		"admission_policy", "response_rule", "",
		"network_policy", "network_policy_delete",
		"file_profile_delete_x", "networkpolicy",
	}
	for _, k := range notProfile {
		if fedProfileKind(k) {
			t.Errorf("fedProfileKind(%q) = true, want false", k)
		}
	}

	// The exported author-side constants must stay aligned with the kinds the
	// joint-side apply switch recognizes.
	for _, k := range []string{FedKindFileProfile, FedKindHostProcessProfile} {
		if !fedProfileKind(k) {
			t.Errorf("exported kind %q not recognized by fedProfileKind", k)
		}
	}
}
