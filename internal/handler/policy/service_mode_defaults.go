package policy

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// The default mode newly-discovered/created service groups adopt (NV's NewServiceMode /
// NewServiceProfileMode). Discover = learn only, Monitor = alert, Protect = block.
type serviceModeDefaultsDTO struct {
	ClusterID   string `json:"cluster_id"`
	PolicyMode  string `json:"policy_mode"`
	ProfileMode string `json:"profile_mode"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

func validServiceMode(m string) bool {
	return m == "discover" || m == "monitor" || m == "protect"
}

// ServiceModeDefaults returns the cluster's new-service default modes, defaulting to
// monitor/monitor when unset. GET /policies/service-mode-defaults
func (p *Policies) ServiceModeDefaults(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	clusterID, ok := p.resolveAdmissionCluster(r, subj.OrgID)
	if !ok {
		jsonError(w, http.StatusBadRequest, "cluster_id required")
		return
	}
	dto := serviceModeDefaultsDTO{ClusterID: clusterID.String(), PolicyMode: "monitor", ProfileMode: "monitor"}
	var updated *time.Time
	if err := p.db.Pool().QueryRow(r.Context(), `
SELECT policy_mode, profile_mode, updated_at
  FROM service_mode_defaults WHERE org_id = $1 AND cluster_id = $2`, subj.OrgID, clusterID).
		Scan(&dto.PolicyMode, &dto.ProfileMode, &updated); err == nil && updated != nil {
		dto.UpdatedAt = updated.UTC().Format(time.RFC3339)
	}
	httpx.WriteJSON(w, http.StatusOK, dto)
}

// UpdateServiceModeDefaults upserts the cluster's new-service default modes.
// PATCH /policies/service-mode-defaults
func (p *Policies) UpdateServiceModeDefaults(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	clusterID, ok := p.resolveAdmissionCluster(r, subj.OrgID)
	if !ok {
		jsonError(w, http.StatusBadRequest, "cluster_id required")
		return
	}
	var body struct {
		PolicyMode  string `json:"policy_mode"`
		ProfileMode string `json:"profile_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	cur := serviceModeDefaultsDTO{PolicyMode: "monitor", ProfileMode: "monitor"}
	_ = p.db.Pool().QueryRow(r.Context(), `
SELECT policy_mode, profile_mode FROM service_mode_defaults WHERE org_id = $1 AND cluster_id = $2`,
		subj.OrgID, clusterID).Scan(&cur.PolicyMode, &cur.ProfileMode)
	if m := strings.TrimSpace(body.PolicyMode); m != "" {
		if !validServiceMode(m) {
			jsonError(w, http.StatusBadRequest, "policy_mode must be discover, monitor, or protect")
			return
		}
		cur.PolicyMode = m
	}
	if m := strings.TrimSpace(body.ProfileMode); m != "" {
		if !validServiceMode(m) {
			jsonError(w, http.StatusBadRequest, "profile_mode must be discover, monitor, or protect")
			return
		}
		cur.ProfileMode = m
	}
	if _, err := p.db.Pool().Exec(r.Context(), `
INSERT INTO service_mode_defaults (org_id, cluster_id, policy_mode, profile_mode, updated_by, updated_at)
VALUES ($1,$2,$3,$4,$5,NOW())
ON CONFLICT (org_id, cluster_id) DO UPDATE SET
  policy_mode = EXCLUDED.policy_mode, profile_mode = EXCLUDED.profile_mode,
  updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		subj.OrgID, clusterID, cur.PolicyMode, cur.ProfileMode, subj.UserID); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if p.auditLog != nil {
		orgID, userID := subj.OrgID, subj.UserID
		actorIP := net.ParseIP(r.RemoteAddr)
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			actorIP = net.ParseIP(host)
		}
		_, _, _ = p.auditLog.Log(r.Context(), audit.Event{
			OrgID: &orgID, ActorID: &userID, ActorIP: actorIP,
			Action: "service_mode_defaults.update", TargetKind: "service-mode-defaults", TargetID: clusterID.String(),
			After: map[string]any{"policy_mode": cur.PolicyMode, "profile_mode": cur.ProfileMode}, RequestID: chimw.GetReqID(r.Context()),
		})
	}
	cur.ClusterID = clusterID.String()
	cur.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	httpx.WriteJSON(w, http.StatusOK, cur)
}
