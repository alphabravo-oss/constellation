package identity

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

const AccessCookie = "__Host-constellation-session"
const BindingCookie = "__Host-constellation-oidc"
const BrowserHeader = "X-Constellation-Client"

func respond(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}
func cookie(w http.ResponseWriter, name, value string, expires time.Time) {
	age := int(time.Until(expires).Seconds())
	if value == "" {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires, MaxAge: age})
}
func fail(w http.ResponseWriter, r *http.Request, status int, message string) {
	apiutil.WriteStatus(r.Context(), w, status, message)
}

func (s *Service) Providers(w http.ResponseWriter, r *http.Request) {
	respond(w, map[string]bool{"oidc": s.oidc != nil, "break_glass": s.emergency.Enabled})
}
func (s *Service) Settings(w http.ResponseWriter, r *http.Request) {
	respond(w, map[string]any{"oidc": s.oidc, "ready": s.rp.Load() != nil, "break_glass": map[string]any{"enabled": s.emergency.Enabled, "totp_required": true, "session_seconds": int(s.emergency.SessionTTL.Seconds())}})
}
func (s *Service) OIDCStart(w http.ResponseWriter, r *http.Request) {
	rp := s.rp.Load()
	if rp == nil {
		fail(w, r, http.StatusServiceUnavailable, "single sign-on provider unavailable")
		return
	}
	state, binding, verifier, nonce := randomToken(), randomToken(), randomToken(), randomToken()
	if err := s.store.saveAttempt(r.Context(), state, binding, verifier, nonce); err != nil {
		fail(w, r, 500, "start sign-in")
		return
	}
	cookie(w, BindingCookie, binding, time.Now().Add(5*time.Minute))
	respond(w, map[string]string{"authorize_url": rp.Start(state, verifier, nonce)})
}
func (s *Service) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	rp := s.rp.Load()
	if rp == nil {
		fail(w, r, 503, "single sign-on provider unavailable")
		return
	}
	binding, err := r.Cookie(BindingCookie)
	if err != nil || r.URL.Query().Get("code") == "" || r.URL.Query().Get("state") == "" {
		fail(w, r, 400, "invalid sign-in callback")
		return
	}
	verifier, nonce, err := s.store.consumeAttempt(r.Context(), r.URL.Query().Get("state"), binding.Value)
	cookie(w, BindingCookie, "", time.Now())
	if err != nil {
		fail(w, r, 400, "expired or invalid sign-in attempt")
		return
	}
	p, err := rp.Exchange(r.Context(), r.URL.Query().Get("code"), verifier, nonce)
	if err != nil {
		s.failedLogin(w, r, "oidc")
		return
	}
	if len(p.Roles) == 0 {
		fail(w, r, 403, "no mapped roles; contact your administrator")
		return
	}
	subj, epoch, err := s.store.resolve(r.Context(), s.oidc.OrgName, s.oidc.IssuerURL, p)
	if err != nil {
		fail(w, r, 403, "identity unavailable; contact your administrator")
		return
	}
	raw, err := s.store.startSession(r.Context(), subj, epoch, p.Roles, "oidc", p.Expires, s.audit)
	if err != nil {
		fail(w, r, 500, "create session")
		return
	}
	cookie(w, AccessCookie, raw, p.Expires)
	http.Redirect(w, r, "/clusters", http.StatusSeeOther)
}
func (s *Service) failedLogin(w http.ResponseWriter, r *http.Request, kind string) {
	_, _, err := s.audit.Log(r.Context(), audit.Event{Action: "auth.login." + kind + ".failed", TargetKind: "identity", After: map[string]any{"severity": "critical"}})
	if err != nil {
		fail(w, r, 500, "record authentication event")
		return
	}
	fail(w, r, 401, "authentication failed")
}
func (s *Service) BreakGlass(w http.ResponseWriter, r *http.Request) {
	if !s.emergency.Enabled {
		fail(w, r, 404, "break-glass disabled")
		return
	}
	allowed, err := s.store.reserveBreakGlass(r.Context())
	if err != nil {
		fail(w, r, 500, "check login rate")
		return
	}
	if !allowed {
		s.counter.WithLabelValues("rate_limited").Inc()
		_, _, _ = s.audit.Log(r.Context(), audit.Event{Action: "auth.login.break-glass.rate_limited", TargetKind: "identity", After: map[string]any{"severity": "critical"}})
		w.Header().Set("Retry-After", "300")
		fail(w, r, 429, "too many emergency login attempts")
		return
	}
	var body struct {
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		s.counter.WithLabelValues("failure").Inc()
		s.failedLogin(w, r, "break-glass")
		return
	}
	step := totpStep(s.emergency.TOTPSecret, body.TOTP, time.Now())
	if VerifyPassword(s.emergency.PasswordHash, body.Password) != nil || step < 0 {
		s.counter.WithLabelValues("failure").Inc()
		s.failedLogin(w, r, "break-glass")
		return
	}
	used, err := s.store.consumeTOTP(r.Context(), step)
	if err != nil {
		fail(w, r, 500, "verify emergency code")
		return
	}
	if !used {
		s.counter.WithLabelValues("failure").Inc()
		s.failedLogin(w, r, "break-glass")
		return
	}
	p := &Principal{Subject: "admin", Email: "break-glass@constellation.local", Name: "Emergency administrator", Roles: []string{"GlobalAdmin"}, Expires: time.Now().Add(s.emergency.SessionTTL)}
	subj, epoch, err := s.store.resolve(r.Context(), s.emergency.OrgName, "break-glass", p)
	if err != nil {
		fail(w, r, 500, "resolve emergency administrator")
		return
	}
	raw, err := s.store.startSession(r.Context(), subj, epoch, p.Roles, "break-glass", p.Expires, s.audit)
	if err != nil {
		fail(w, r, 500, "create emergency session")
		return
	}
	s.counter.WithLabelValues("success").Inc()
	cookie(w, AccessCookie, raw, p.Expires)
	respond(w, map[string]any{"expires_at": p.Expires})
}
func (s *Service) Me(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	roles := []string{}
	for _, a := range subj.Assignments {
		roles = append(roles, a.Role)
	}
	respond(w, map[string]any{"user_id": subj.UserID, "org_id": subj.OrgID, "email": subj.Email, "roles": roles})
}
func (s *Service) Logout(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	if err := s.store.logout(r.Context(), subj.UserID); err != nil {
		fail(w, r, 500, "end session")
		return
	}
	cookie(w, AccessCookie, "", time.Now())
	respond(w, map[string]string{"status": "ok"})
}
