package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// AuthSecurityPolicy serves the A1 admin-configurable security policy CRUD:
//
//	GET /api/v1/auth/security-policy — the org's password policy + session/idle timeouts
//	PUT /api/v1/auth/security-policy — replace the whole policy (optimistic-concurrency by revision)
//
// The policy supersedes the hardcoded auth.DefaultPasswordProfile (12ch/3-class/90d/5-history)
// and the deploy-time-only session/idle env knobs. An org with no row resolves to the built-in
// default (the fallback), so this endpoint is purely additive: not configuring it preserves the
// legacy behaviour. Both routes are gated by rbac.VerbManageSystemConfig in the router.
//
// This is the storage + REST half of A1. The login/validation consumption
// (auth.LoadPasswordProfile in place of the DefaultPasswordProfile constant, and
// SecurityPolicy.SessionTTL/IdleTimeout feeding the JWT signer + idle middleware) is the
// remaining integration seam — see the package-level notes in internal/auth/policy.go.
type AuthSecurityPolicy struct {
	db    *db.DB
	audit *audit.Logger
}

// NewAuthSecurityPolicy constructs the handler.
func NewAuthSecurityPolicy(d *db.DB, a *audit.Logger) *AuthSecurityPolicy {
	return &AuthSecurityPolicy{db: d, audit: a}
}

// securityPolicyBody is the GET/PUT wire shape. It carries the revision so a PUT can be
// checked against the version the client edited (optimistic concurrency; 409 on conflict).
type securityPolicyBody struct {
	MinLength             int   `json:"min_length"`
	MinClasses            int   `json:"min_classes"`
	MaxAgeDays            int   `json:"max_age_days"`
	HistoryDepth          int   `json:"history_depth"`
	SessionTimeoutMinutes int   `json:"session_timeout_minutes"`
	IdleTimeoutMinutes    int   `json:"idle_timeout_minutes"`
	LockoutThreshold      int   `json:"lockout_threshold"`
	LockoutWindowMinutes  int   `json:"lockout_window_minutes"`
	Revision              int64 `json:"revision"`
}

func toPolicyBody(p auth.SecurityPolicy, rev int64) securityPolicyBody {
	return securityPolicyBody{
		MinLength:             p.MinLength,
		MinClasses:            p.MinClasses,
		MaxAgeDays:            p.MaxAgeDays,
		HistoryDepth:          p.HistoryDepth,
		SessionTimeoutMinutes: p.SessionTimeoutMinutes,
		IdleTimeoutMinutes:    p.IdleTimeoutMinutes,
		LockoutThreshold:      p.LockoutThreshold,
		LockoutWindowMinutes:  p.LockoutWindowMinutes,
		Revision:              rev,
	}
}

func (b securityPolicyBody) toModel() auth.SecurityPolicy {
	return auth.SecurityPolicy{
		MinLength:             b.MinLength,
		MinClasses:            b.MinClasses,
		MaxAgeDays:            b.MaxAgeDays,
		HistoryDepth:          b.HistoryDepth,
		SessionTimeoutMinutes: b.SessionTimeoutMinutes,
		IdleTimeoutMinutes:    b.IdleTimeoutMinutes,
		LockoutThreshold:      b.LockoutThreshold,
		LockoutWindowMinutes:  b.LockoutWindowMinutes,
	}
}

// Get returns the org's current security policy (the built-in default when unconfigured).
func (h *AuthSecurityPolicy) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	pol, rev, err := auth.LoadSecurityPolicy(r.Context(), h.db.Pool(), subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "load policy")
		return
	}
	writeJSON(w, http.StatusOK, toPolicyBody(pol, rev))
}

// Put replaces the org's security policy. The body's revision must match the stored revision
// (0 when no row exists yet); a mismatch is a 409 so a concurrent edit cannot be silently lost.
func (h *AuthSecurityPolicy) Put(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var body securityPolicyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	pol := body.toModel()
	if err := pol.Validate(); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Capture the prior value for the audit Before/After trail.
	before, _, _ := auth.LoadSecurityPolicy(r.Context(), h.db.Pool(), subj.OrgID)

	updatedBy := subj.UserID
	rev, err := auth.SaveSecurityPolicy(r.Context(), h.db.Pool(), subj.OrgID, pol, body.Revision, &updatedBy)
	if errors.Is(err, auth.ErrPolicyRevisionConflict) {
		jsonError(w, http.StatusConflict, "policy changed concurrently; reload and retry")
		return
	}
	if err != nil {
		if errors.Is(err, auth.ErrInvalidPolicy) {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		jsonError(w, http.StatusInternalServerError, "save policy")
		return
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "auth.security_policy.update",
		TargetKind: "org",
		TargetID:   subj.OrgID.String(),
		Before:     before,
		After:      pol,
	})
	writeJSON(w, http.StatusOK, toPolicyBody(pol, rev))
}
