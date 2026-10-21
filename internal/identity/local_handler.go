package identity

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func decodeBody(w http.ResponseWriter, r *http.Request, out any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	d.DisallowUnknownFields()
	return d.Decode(out)
}
func (s *Service) Providers(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.readSettings(r.Context(), s.enc)
	if err != nil {
		fail(w, r, 503, "sign-in methods unavailable")
		return
	}
	respond(w, map[string]any{"local": cfg.Local.Enabled && (cfg.Local.Display != "sso" || cfg.OIDC == nil), "oidc": cfg.OIDC != nil && (cfg.Local.Display != "local" || !cfg.Local.Enabled), "break_glass": s.hasRecovery(r), "totp_policy": cfg.Local.TOTPPolicy})
}
func (s *Service) Settings(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.readSettings(r.Context(), s.enc)
	if err != nil {
		fail(w, r, 503, "sign-in settings unavailable")
		return
	}
	respond(w, map[string]any{"local": cfg.Local, "oidc": cfg.OIDC, "bundled_oidc": s.bundled, "revision": cfg.Revision, "ready": s.current.Load().RP != nil, "break_glass": map[string]any{"enabled": s.hasRecovery(r), "totp_required": true, "session_seconds": int(s.emergency.SessionTTL.Seconds())}})
}
func (s *Service) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Local        LocalConfig `json:"local"`
		OIDC         *OIDCConfig `json:"oidc"`
		ClientSecret *string     `json:"client_secret"`
		Revision     int64       `json:"revision"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		fail(w, r, 400, "invalid sign-in settings")
		return
	}
	if err := body.Local.validate(); err != nil {
		fail(w, r, 400, err.Error())
		return
	}
	// A presentation setting must leave at least one normal sign-in choice.
	if body.Local.Enabled && body.Local.Display == "sso" && body.OIDC == nil {
		fail(w, r, 400, "configure single sign-on before hiding local sign-in")
		return
	}
	previous, err := s.store.readSettings(r.Context(), s.enc)
	if err != nil {
		fail(w, r, 500, "read settings")
		return
	}
	if body.OIDC != nil {
		body.OIDC.defaults()
		if err := body.OIDC.validate(); err != nil {
			fail(w, r, 400, err.Error())
			return
		}
		switch {
		case s.bundled != nil && body.OIDC.IssuerURL == s.bundled.IssuerURL && body.OIDC.ClientID == s.bundled.ClientID:
			body.OIDC.ClientSecret = s.bundled.ClientSecret
		case body.ClientSecret != nil:
			body.OIDC.ClientSecret = *body.ClientSecret
		case previous.OIDC != nil && previous.OIDC.IssuerURL == body.OIDC.IssuerURL && previous.OIDC.ClientID == body.OIDC.ClientID:
			body.OIDC.ClientSecret = previous.OIDC.ClientSecret
		}
	}
	sealed, err := s.sealClientSecret(body.OIDC)
	if err != nil {
		fail(w, r, 500, "encrypt provider credentials")
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	err = s.store.writeSettings(r.Context(), settingsRecord{Local: body.Local, OIDC: body.OIDC, Revision: body.Revision}, sealed, &subj, s.audit)
	if err != nil {
		fail(w, r, 409, "settings changed; reload before saving")
		return
	}
	if err = s.RefreshSessions(r.Context()); err != nil {
		fail(w, r, 503, "refresh session state")
		return
	}
	// Background discovery is bounded and never blocks the settings response.
	// Other replicas observe the same revision on their next two-second tick.
	respond(w, map[string]any{"status": "ok", "revision": body.Revision + 1})
}
func (s *Service) LocalLogin(w http.ResponseWriter, r *http.Request) { s.localLogin(w, r, false) }
func (s *Service) BreakGlass(w http.ResponseWriter, r *http.Request) { s.localLogin(w, r, true) }
func (s *Service) localLogin(w http.ResponseWriter, r *http.Request, emergency bool) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		fail(w, r, 400, "invalid sign-in request")
		return
	}
	if emergency {
		body.Email, _ = s.store.recoveryEmail(r.Context(), s.org)
	}
	cfg, err := s.store.readSettings(r.Context(), s.enc)
	if err != nil {
		fail(w, r, 503, "sign-in unavailable")
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	allowed, err := s.store.reserveIP(r.Context(), ip, cfg.Local.IPRate)
	if err != nil {
		fail(w, r, 503, "check login rate")
		return
	}
	if !allowed {
		if emergency {
			s.counter.WithLabelValues("rate_limited").Inc()
		}
		w.Header().Set("Retry-After", "60")
		fail(w, r, 429, "too many sign-in attempts from this address")
		return
	}
	raw, expires, kind, err := s.loginLocal(r.Context(), body.Email, body.Password, body.TOTP, emergency)
	if err != nil {
		s.localLoginError(w, r, kind, err)
		return
	}

	if kind == "break-glass" {
		s.counter.WithLabelValues("success").Inc()
	}
	cookie(w, AccessCookie, raw, expires)
	respond(w, map[string]any{"expires_at": expires})
}
func (s *Service) localLoginError(w http.ResponseWriter, r *http.Request, kind string, err error) {

	if errors.Is(err, errPasswordBusy) {
		w.Header().Set("Retry-After", "1")
		fail(w, r, 429, "sign-in busy; try again shortly")
		return
	}
	if errors.Is(err, errLoginBlocked) {
		if kind == "break-glass" {
			s.counter.WithLabelValues("rate_limited").Inc()
		}
		_, _, _ = s.audit.Log(r.Context(), audit.Event{Action: "auth.login." + kind + ".rate_limited", TargetKind: "identity", After: map[string]any{"severity": "critical"}})
		var backoff accountBackoff
		seconds := 1
		if errors.As(err, &backoff) {
			seconds = backoff.Seconds
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		fail(w, r, 429, "account temporarily blocked; try again later")
		return
	}
	if kind == "break-glass" {
		s.counter.WithLabelValues("failure").Inc()
	}
	s.failedLogin(w, r, kind)
}
func (s *Service) ListUsers(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	users, err := s.store.listLocal(r.Context(), subj.OrgID)
	if err != nil {
		fail(w, r, 500, "list local users")
		return
	}
	respond(w, map[string]any{"users": users})
}
func (s *Service) CreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		Role        string `json:"role"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		fail(w, r, 400, "invalid user")
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	out, err := s.createUser(r.Context(), subj, body.Email, body.DisplayName, body.Password, body.Role)
	if err != nil {
		fail(w, r, 400, err.Error())
		return
	}
	respond(w, out)
}
func (s *Service) MutateUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		fail(w, r, 400, "invalid user ID")
		return
	}
	var body struct {
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err = decodeBody(w, r, &body); err != nil {
		fail(w, r, 400, "invalid user change")
		return
	}
	action := chi.URLParam(r, "action")
	value := body.Password
	if action == "role" {
		value = body.Role
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	out, err := s.mutateUser(r.Context(), subj, id, action, value)
	if err != nil {
		fail(w, r, 400, err.Error())
		return
	}
	respond(w, out)
}

func (s *Service) hasRecovery(r *http.Request) bool {
	_, err := s.store.recoveryEmail(r.Context(), s.org)
	return err == nil
}
