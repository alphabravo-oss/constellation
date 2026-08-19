package netpolicy

import "testing"

func TestEvaluateNBE(t *testing.T) {
	cases := []struct {
		name             string
		src, dst         string
		mode             NBEMode
		wantCross        bool
		wantFlag, wantDeny bool
	}{
		{"same namespace, protect", "app", "app", NBEProtect, false, false, false},
		{"cross ns, off", "app", "db", NBEOff, true, false, false},
		{"cross ns, observe flags only", "app", "db", NBEObserve, true, true, false},
		{"cross ns, protect denies", "app", "db", NBEProtect, true, true, true},
		{"kube-system dst exempt", "app", "kube-system", NBEProtect, false, false, false},
		{"kube-system src exempt", "kube-system", "app", NBEProtect, false, false, false},
		{"external dst not a namespace", "app", "external", NBEProtect, false, false, false},
		{"empty src not a namespace", "", "db", NBEProtect, false, false, false},
		{"unknown mode is inert", "app", "db", NBEMode("bogus"), true, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := EvaluateNBE(c.src, c.dst, c.mode)
			if got.CrossNamespace != c.wantCross {
				t.Errorf("CrossNamespace = %v, want %v", got.CrossNamespace, c.wantCross)
			}
			if got.Flagged != c.wantFlag {
				t.Errorf("Flagged = %v, want %v", got.Flagged, c.wantFlag)
			}
			if got.Deny != c.wantDeny {
				t.Errorf("Deny = %v, want %v", got.Deny, c.wantDeny)
			}
		})
	}
}

func TestEvaluateNBE_DenyOnlyUnderProtect(t *testing.T) {
	// Safety invariant: Deny must never be true unless mode==protect AND the
	// flow is a genuine cross-namespace crossing.
	for _, m := range []NBEMode{NBEOff, NBEObserve, NBEMode(""), NBEMode("weird")} {
		if EvaluateNBE("a", "b", m).Deny {
			t.Errorf("mode %q must not deny", m)
		}
	}
	if !EvaluateNBE("a", "b", NBEProtect).Deny {
		t.Error("protect on a cross-ns flow must deny")
	}
}

func TestNBEModeValid(t *testing.T) {
	for _, m := range []NBEMode{NBEOff, NBEObserve, NBEProtect} {
		if !m.Valid() {
			t.Errorf("%q should be valid", m)
		}
	}
	if NBEMode("nope").Valid() {
		t.Error("unknown mode should be invalid")
	}
}
