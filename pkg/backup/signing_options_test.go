package backup

import "testing"

func TestResolveSignModePreservesExplicitDefaultsAndRejectsUnknown(t *testing.T) {
	for _, fallback := range []SignMode{SignModeNone, SignModeStaticKey} {
		for _, raw := range []string{"", "none", "static-key", "keyless"} {
			want := SignMode(raw)
			if raw == "" {
				want = fallback
			}
			got, err := ResolveSignMode(raw, fallback)
			if err != nil || got != want {
				t.Fatalf("raw=%q fallback=%q got=%q err=%v", raw, fallback, got, err)
			}
		}
	}
	for _, raw := range []string{"static_key", "STATIC-KEY", " none", "none ", "\x00none", "sentinel-private-input"} {
		if got, err := ResolveSignMode(raw, SignModeNone); err == nil || got != "" || err.Error() != "sign_mode must be none, static-key, or keyless" {
			t.Fatalf("invalid mode did not fail closed: got=%q err=%v", got, err)
		}
	}
	if _, err := ResolveSignMode("", SignMode("invalid-default")); err == nil {
		t.Fatal("invalid default accepted")
	}
}
