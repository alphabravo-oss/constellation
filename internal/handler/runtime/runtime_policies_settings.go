// P1-2: cluster-wide enforcement master switch + default action.
//
// Backed by the netpolicy_settings row (migration 120). Two knobs, both
// defaulting to a passthrough value so an untouched cluster behaves exactly as
// before:
//
//	EnforcementOverride  none|observe|enforce   — wins over each policy's mode
//	DefaultAction        unset|allow|deny        — wins over each policy's def_action
//
// The override is honoured in the agent policy bundle (see runtime_policies_
// bundle.go): "observe" is the emergency / staged-rollout "stop blocking" toggle
// (force monitor), "enforce" flips the whole cluster on. An env var
// (CONSTELLATION_NETPOLICY_OVERRIDE) is consulted as a break-glass fallback so
// the observe override works even if the DB is unreachable.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// EnforcementOverride is the cluster-wide mode override.
type EnforcementOverride string

const (
	OverrideNone    EnforcementOverride = "none"    // passthrough
	OverrideObserve EnforcementOverride = "observe" // force monitor everywhere
	OverrideEnforce EnforcementOverride = "enforce" // force enforce everywhere
)

// DefaultActionOverride is the cluster-wide matched-no-rule fallback override.
type DefaultActionOverride string

const (
	DefaultActionUnset DefaultActionOverride = "unset" // passthrough
	DefaultActionAllow DefaultActionOverride = "allow"
	DefaultActionDeny  DefaultActionOverride = "deny"
)

// NetpolicySettings is one netpolicy_settings row.
type NetpolicySettings struct {
	EnforcementOverride EnforcementOverride   `json:"enforcement_override"`
	DefaultAction       DefaultActionOverride `json:"default_action"`
}

// DefaultNetpolicySettings is the all-passthrough baseline used when no row
// exists — nothing forced, behaviour unchanged.
func DefaultNetpolicySettings() NetpolicySettings {
	return NetpolicySettings{EnforcementOverride: OverrideNone, DefaultAction: DefaultActionUnset}
}

func (o EnforcementOverride) valid() bool {
	switch o {
	case OverrideNone, OverrideObserve, OverrideEnforce:
		return true
	}
	return false
}

func (d DefaultActionOverride) valid() bool {
	switch d {
	case DefaultActionUnset, DefaultActionAllow, DefaultActionDeny:
		return true
	}
	return false
}

// GetSettings loads the cluster's settings, or the passthrough default when no
// row exists. The env break-glass override (CONSTELLATION_NETPOLICY_OVERRIDE)
// takes precedence over the stored value only when it forces "observe" — the
// emergency stop must work even when nobody can reach the DB, but env must never
// be able to silently turn ENFORCE on.
func (s *RuntimePolicyStore) GetSettings(ctx context.Context, orgID, clusterID uuid.UUID) (NetpolicySettings, error) {
	out := DefaultNetpolicySettings()
	var over, def string
	err := s.db.Pool().QueryRow(ctx,
		`SELECT enforcement_override, default_action FROM netpolicy_settings
		  WHERE org_id = $1 AND cluster_id = $2`, orgID, clusterID).Scan(&over, &def)
	if err == nil {
		out.EnforcementOverride = EnforcementOverride(over)
		out.DefaultAction = DefaultActionOverride(def)
	} else if !strings.Contains(err.Error(), "no rows") {
		return out, err
	}
	if envNetpolicyObserveOverride() {
		out.EnforcementOverride = OverrideObserve
	}
	return out, nil
}

// PutSettings upserts the cluster's settings after validating the two knobs.
func (s *RuntimePolicyStore) PutSettings(ctx context.Context, orgID, clusterID uuid.UUID, in NetpolicySettings, by *uuid.UUID) error {
	if in.EnforcementOverride == "" {
		in.EnforcementOverride = OverrideNone
	}
	if in.DefaultAction == "" {
		in.DefaultAction = DefaultActionUnset
	}
	if !in.EnforcementOverride.valid() {
		return errors.New("invalid enforcement_override")
	}
	if !in.DefaultAction.valid() {
		return errors.New("invalid default_action")
	}
	_, err := s.db.Pool().Exec(ctx, `
INSERT INTO netpolicy_settings (org_id, cluster_id, enforcement_override, default_action, updated_by, updated_at)
VALUES ($1,$2,$3,$4,$5,NOW())
ON CONFLICT (org_id, cluster_id) DO UPDATE
   SET enforcement_override = EXCLUDED.enforcement_override,
       default_action       = EXCLUDED.default_action,
       updated_by           = EXCLUDED.updated_by,
       updated_at           = NOW()`,
		orgID, clusterID, string(in.EnforcementOverride), string(in.DefaultAction), by)
	return err
}

// ApplyMode returns the effective policy mode after the cluster override wins
// over the per-policy mode. A disabled policy stays disabled (the override is
// about blocking-vs-observing, not about resurrecting a switched-off policy).
func (o EnforcementOverride) ApplyMode(mode PolicyMode) PolicyMode {
	if mode == PolicyModeDisabled {
		return mode
	}
	switch o {
	case OverrideObserve:
		return PolicyModeMonitor
	case OverrideEnforce:
		return PolicyModeEnforce
	default:
		return mode
	}
}

// ApplyDefAction returns the effective def_action after the cluster override
// wins over the per-policy def_action. Unset is passthrough.
func (d DefaultActionOverride) ApplyDefAction(def uint8) uint8 {
	switch d {
	case DefaultActionAllow:
		return uint8(dp.PolicyActionAllow)
	case DefaultActionDeny:
		return uint8(dp.PolicyActionDeny)
	default:
		return def
	}
}

func envNetpolicyObserveOverride() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("CONSTELLATION_NETPOLICY_OVERRIDE")), "observe")
}

// ---------------------------------- HTTP ------------------------------------
//
// ponytail: route registration lives in internal/server/server.go (out of this
// subsystem's assigned paths). Wire these two under /runtime-policies:settings
// (GET read-findings, PUT manage-policies) when adding the routes there.

// GetSettingsHTTP handles GET /api/v1/runtime-policies:settings?cluster_id=...
func (h *RuntimePoliciesHTTP) GetSettingsHTTP(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	clusterID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	settings, err := h.store.GetSettings(r.Context(), sub.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, settings)
}

// SetSettingsHTTP handles PUT /api/v1/runtime-policies:settings?cluster_id=...
func (h *RuntimePoliciesHTTP) SetSettingsHTTP(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	clusterID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	var req NetpolicySettings
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if err := h.store.PutSettings(r.Context(), sub.OrgID, clusterID, req, &sub.UserID); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.store.GetSettings(r.Context(), sub.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
