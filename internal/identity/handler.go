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

func (s *Service) OIDCStart(w http.ResponseWriter, r *http.Request) {
	cfg := s.current.Load()
	rp := cfg.RP
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
	cfg := s.current.Load()
	rp := cfg.RP
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
	cookie(w, AccessCookie, "", time.Now())
	if len(p.Roles) == 0 {
		fail(w, r, 403, "no mapped roles; contact your administrator")
		return
	}
	subj, epoch, err := s.store.resolve(r.Context(), cfg.OIDC.OrgName, cfg.OIDC.IssuerURL, p)
	if err != nil {
		fail(w, r, 403, "identity unavailable; contact your administrator")
		return
	}
	raw, err := s.store.startSession(r.Context(), subj, epoch, p.Roles, "oidc", p.Expires, s.audit)
	if err != nil {
		fail(w, r, 500, "create session")
		return
	}
	if err = s.RefreshSessions(r.Context()); err != nil {
		fail(w, r, 503, "refresh session state")
		return
	}
	cookie(w, AccessCookie, raw, p.Expires)
	http.Redirect(w, r, "/clusters", http.StatusSeeOther)
}
func (s *Service) failedLogin(w http.ResponseWriter, r *http.Request, kind string) {
	severity := "warning"
	if kind == "break-glass" {
		severity = "critical"
	}
	_, _, err := s.audit.Log(r.Context(), audit.Event{Action: "auth.login." + kind + ".failed", TargetKind: "identity", After: map[string]any{"severity": severity}})
	if err != nil {
		fail(w, r, 500, "record authentication event")
		return
	}
	fail(w, r, 401, "authentication failed")
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
	if err := s.RefreshSessions(r.Context()); err != nil {
		fail(w, r, 503, "refresh session state")
		return
	}
	cookie(w, AccessCookie, "", time.Now())
	respond(w, map[string]string{"status": "ok"})
}
