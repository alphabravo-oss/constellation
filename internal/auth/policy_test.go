package auth

import (
	"errors"
	"testing"
	"time"
)

// A1: DefaultSecurityPolicy must reproduce the legacy hardcoded behaviour exactly, so an org
// with no auth_policy row behaves identically to before the feature landed.
func TestDefaultSecurityPolicyMatchesLegacy(t *testing.T) {
	pol := DefaultSecurityPolicy()
	prof := pol.PasswordProfile()
	legacy := DefaultPasswordProfile()
	if prof != legacy {
		t.Fatalf("PasswordProfile() = %+v, want legacy %+v", prof, legacy)
	}
	// Session/idle default to "use deploy-time value": the fallback is returned unchanged.
	if got := pol.SessionTTL(time.Hour); got != time.Hour {
		t.Fatalf("SessionTTL fallback = %v, want 1h", got)
	}
	if got := pol.IdleTimeout(30 * time.Minute); got != 30*time.Minute {
		t.Fatalf("IdleTimeout fallback = %v, want 30m", got)
	}
}

// A1: configured session/idle minutes override the deploy-time fallback.
func TestSecurityPolicyTimeoutOverrides(t *testing.T) {
	pol := SecurityPolicy{SessionTimeoutMinutes: 120, IdleTimeoutMinutes: 15}
	if got := pol.SessionTTL(time.Hour); got != 2*time.Hour {
		t.Fatalf("SessionTTL = %v, want 2h", got)
	}
	if got := pol.IdleTimeout(30 * time.Minute); got != 15*time.Minute {
		t.Fatalf("IdleTimeout = %v, want 15m", got)
	}
}

// A1: PasswordProfile projection converts MaxAgeDays -> Duration.
func TestSecurityPolicyPasswordProfileProjection(t *testing.T) {
	pol := SecurityPolicy{MinLength: 16, MinClasses: 4, MaxAgeDays: 30, HistoryDepth: 8}
	prof := pol.PasswordProfile()
	if prof.MinLength != 16 || prof.MinClasses != 4 || prof.HistoryDepth != 8 {
		t.Fatalf("projection lost fields: %+v", prof)
	}
	if prof.MaxAge != 30*24*time.Hour {
		t.Fatalf("MaxAge = %v, want 30d", prof.MaxAge)
	}
}

func TestSecurityPolicyValidate(t *testing.T) {
	valid := DefaultSecurityPolicy()
	cases := []struct {
		name    string
		mut     func(*SecurityPolicy)
		wantErr bool
	}{
		{"default ok", func(*SecurityPolicy) {}, false},
		{"min length zero", func(p *SecurityPolicy) { p.MinLength = 0 }, true},
		{"min length too big", func(p *SecurityPolicy) { p.MinLength = 9999 }, true},
		{"classes over 4", func(p *SecurityPolicy) { p.MinClasses = 5 }, true},
		{"classes zero ok", func(p *SecurityPolicy) { p.MinClasses = 0 }, false},
		{"negative age", func(p *SecurityPolicy) { p.MaxAgeDays = -1 }, true},
		{"zero age ok (no expiry)", func(p *SecurityPolicy) { p.MaxAgeDays = 0 }, false},
		{"history over ceil", func(p *SecurityPolicy) { p.HistoryDepth = 33 }, true},
		{"session below min", func(p *SecurityPolicy) { p.SessionTimeoutMinutes = 1 }, true},
		{"session zero ok", func(p *SecurityPolicy) { p.SessionTimeoutMinutes = 0 }, false},
		{"idle above max", func(p *SecurityPolicy) { p.IdleTimeoutMinutes = 10000 }, true},
		{"idle in range ok", func(p *SecurityPolicy) { p.IdleTimeoutMinutes = 20 }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := valid
			tc.mut(&p)
			err := p.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate() = nil, want error")
				}
				if !errors.Is(err, ErrInvalidPolicy) {
					t.Fatalf("Validate() err = %v, want ErrInvalidPolicy", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}
