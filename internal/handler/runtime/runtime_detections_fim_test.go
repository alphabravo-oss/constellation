package runtime

import "testing"

// TestMatchDefaultFIM_SharedLibraries asserts the default FIM watch-set covers
// shared-library directories (NeuVector share/fsmon/monitor.go watches /lib and
// /lib64). Tamper of libc / ld.so / a preload implant must be classified even
// with no operator-authored file profile.
func TestMatchDefaultFIM_SharedLibraries(t *testing.T) {
	cases := []struct {
		path  string
		label string
	}{
		{"/lib/x86_64-linux-gnu/libc.so.6", "shared library directory"},
		{"/lib/x86_64-linux-gnu/libpthread.so.0", "shared library directory"},
		{"/lib64/ld-linux-x86-64.so.2", "shared library directory"},
	}
	for _, tc := range cases {
		w := matchDefaultFIM(tc.path)
		if w == nil {
			t.Fatalf("matchDefaultFIM(%q) = nil, want a shared-library watch", tc.path)
		}
		if w.label != tc.label {
			t.Errorf("matchDefaultFIM(%q) label = %q, want %q", tc.path, w.label, tc.label)
		}
		if w.fimSeverity() != "high" {
			t.Errorf("matchDefaultFIM(%q) severity = %q, want high", tc.path, w.fimSeverity())
		}
	}

	// The apk package DB lives under /lib/apk/db/installed; the exact-match
	// rule must still win over the new /lib/ directory rule.
	if w := matchDefaultFIM("/lib/apk/db/installed"); w == nil || w.label != "apk package database" {
		t.Errorf("matchDefaultFIM(/lib/apk/db/installed) = %+v, want apk package database", w)
	}
}
