package policy

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// admissionStateDTO mirrors NeuVector's RESTAdmissionState so the Admission Control page
// is a drop-in match: a global enable flag, monitor/protect mode, default action, and
// webhook failure policy — the state panel NV users flip first.
type admissionStateDTO struct {
	ClusterID     string `json:"cluster_id"`
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode"`           // monitor | protect
	DefaultAction string `json:"default_action"` // allow | deny
	FailurePolicy string `json:"failure_policy"` // ignore | fail
	UpdatedAt     string `json:"updated_at,omitempty"`
}

func (p *Policies) resolveAdmissionCluster(r *http.Request, orgID uuid.UUID) (uuid.UUID, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if raw != "" {
		if id, err := uuid.Parse(raw); err == nil {
			return id, true
		}
		return uuid.Nil, false
	}
	// Default to the most-recently-active cluster, matching the network page behavior.
	var id uuid.UUID
	if err := p.db.Pool().QueryRow(r.Context(), `
SELECT id FROM clusters WHERE org_id = $1
 ORDER BY CASE WHEN state = 'connected' THEN 0 ELSE 1 END, last_heartbeat_at DESC NULLS LAST, created_at ASC
 LIMIT 1`, orgID).Scan(&id); err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// AdmissionState returns the cluster's global admission-control state, defaulting to a
// safe disabled/monitor posture if never configured. GET /policies/admission/state
func (p *Policies) AdmissionState(w http.ResponseWriter, r *http.Request) {
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
	dto := admissionStateDTO{ClusterID: clusterID.String(), Enabled: false, Mode: "monitor", DefaultAction: "allow", FailurePolicy: "ignore"}
	var updated *time.Time
	err := p.db.Pool().QueryRow(r.Context(), `
SELECT enabled, mode, default_action, failure_policy, updated_at
  FROM admission_state WHERE org_id = $1 AND cluster_id = $2`, subj.OrgID, clusterID).
		Scan(&dto.Enabled, &dto.Mode, &dto.DefaultAction, &dto.FailurePolicy, &updated)
	if err == nil && updated != nil {
		dto.UpdatedAt = updated.UTC().Format(time.RFC3339)
	}
	// pgx returns ErrNoRows when unconfigured → keep the safe defaults above.
	httpx.WriteJSON(w, http.StatusOK, dto)
}

type admissionStateBody struct {
	Enabled       *bool  `json:"enabled"`
	Mode          string `json:"mode"`
	DefaultAction string `json:"default_action"`
	FailurePolicy string `json:"failure_policy"`
}

// UpdateAdmissionState upserts the cluster's admission-control state. Audit-logged.
// PATCH /policies/admission/state
func (p *Policies) UpdateAdmissionState(w http.ResponseWriter, r *http.Request) {
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
	var body admissionStateBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	// Start from current (or defaults) so PATCH semantics apply — only sent fields change.
	cur := admissionStateDTO{Enabled: false, Mode: "monitor", DefaultAction: "allow", FailurePolicy: "ignore"}
	_ = p.db.Pool().QueryRow(r.Context(), `
SELECT enabled, mode, default_action, failure_policy
  FROM admission_state WHERE org_id = $1 AND cluster_id = $2`, subj.OrgID, clusterID).
		Scan(&cur.Enabled, &cur.Mode, &cur.DefaultAction, &cur.FailurePolicy)
	if body.Enabled != nil {
		cur.Enabled = *body.Enabled
	}
	if m := strings.TrimSpace(body.Mode); m == "monitor" || m == "protect" {
		cur.Mode = m
	}
	if a := strings.TrimSpace(body.DefaultAction); a == "allow" || a == "deny" {
		cur.DefaultAction = a
	}
	if f := strings.TrimSpace(body.FailurePolicy); f == "ignore" || f == "fail" {
		cur.FailurePolicy = f
	}
	if _, err := p.db.Pool().Exec(r.Context(), `
INSERT INTO admission_state (org_id, cluster_id, enabled, mode, default_action, failure_policy, updated_by, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
ON CONFLICT (org_id, cluster_id) DO UPDATE SET
  enabled = EXCLUDED.enabled, mode = EXCLUDED.mode, default_action = EXCLUDED.default_action,
  failure_policy = EXCLUDED.failure_policy, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		subj.OrgID, clusterID, cur.Enabled, cur.Mode, cur.DefaultAction, cur.FailurePolicy, subj.UserID); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	p.auditAdmissionState(r, subj, clusterID, cur)
	cur.ClusterID = clusterID.String()
	cur.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	httpx.WriteJSON(w, http.StatusOK, cur)
}

func (p *Policies) auditAdmissionState(r *http.Request, subj authctx.Subject, clusterID uuid.UUID, s admissionStateDTO) {
	if p.auditLog == nil {
		return
	}
	orgID := subj.OrgID
	userID := subj.UserID
	actorIP := net.ParseIP(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		actorIP = net.ParseIP(host)
	}
	_, _, _ = p.auditLog.Log(r.Context(), audit.Event{
		OrgID:      &orgID,
		ActorID:    &userID,
		ActorIP:    actorIP,
		Action:     "admission.state.update",
		TargetKind: "admission-state",
		TargetID:   clusterID.String(),
		After:      map[string]any{"enabled": s.Enabled, "mode": s.Mode, "default_action": s.DefaultAction, "failure_policy": s.FailurePolicy},
		RequestID:  chimw.GetReqID(r.Context()),
	})
}
