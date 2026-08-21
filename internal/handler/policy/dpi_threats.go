package policy

import (
	"encoding/json"
	"net"
	"net/http"

	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// DPI signature toggles a cluster operator can flip from the console. Currently just the
// weak-TLS version detections (SSLv3/TLS1.0/1.1), which default OFF because dp reads the
// legacy TLS record version in tap mode and false-positives on ordinary HTTPS. The
// runtime-agent picks this up on its session-upload cycle and applies it live via dp.
type dpiThreatSettingsDTO struct {
	ClusterID      string `json:"cluster_id"`
	WeakTLSEnabled bool   `json:"weak_tls_enabled"`
}

// DPIThreatSettings returns the cluster's DPI toggle state. GET /policies/dpi-threats
func (p *Policies) DPIThreatSettings(w http.ResponseWriter, r *http.Request) {
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
	dto := dpiThreatSettingsDTO{ClusterID: clusterID.String()}
	_ = p.db.Pool().QueryRow(r.Context(),
		`SELECT weak_tls_enabled FROM dpi_threat_settings WHERE org_id = $1 AND cluster_id = $2`,
		subj.OrgID, clusterID).Scan(&dto.WeakTLSEnabled)
	httpx.WriteJSON(w, http.StatusOK, dto)
}

// UpdateDPIThreatSettings upserts the cluster's DPI toggle. PATCH /policies/dpi-threats
func (p *Policies) UpdateDPIThreatSettings(w http.ResponseWriter, r *http.Request) {
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
		WeakTLSEnabled bool `json:"weak_tls_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if _, err := p.db.Pool().Exec(r.Context(), `
INSERT INTO dpi_threat_settings (org_id, cluster_id, weak_tls_enabled, updated_by, updated_at)
VALUES ($1,$2,$3,$4,NOW())
ON CONFLICT (org_id, cluster_id) DO UPDATE SET
  weak_tls_enabled = EXCLUDED.weak_tls_enabled, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		subj.OrgID, clusterID, body.WeakTLSEnabled, subj.UserID); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// When disabling weak-TLS detection, purge the weak-TLS threat rows AND clear the
	// lingering references on flow rollups/raw flows — otherwise a bucket keeps
	// max_threat_id for its lifetime and the map keeps painting a stale "threat" edge for
	// a signature that's now off. IDs: 2011 SSLv3, 2012 TLS1.0, 2027 TLS1.1.
	if !body.WeakTLSEnabled {
		ctx := r.Context()
		_, _ = p.db.Pool().Exec(ctx, `DELETE FROM runtime_threats WHERE org_id=$1 AND cluster_id=$2 AND threat_id IN (2011,2012,2027)`, subj.OrgID, clusterID)
		_, _ = p.db.Pool().Exec(ctx, `UPDATE network_flow_rollups SET max_threat_id=0, max_severity=0 WHERE org_id=$1 AND cluster_id=$2 AND max_threat_id IN (2011,2012,2027)`, subj.OrgID, clusterID)
		_, _ = p.db.Pool().Exec(ctx, `UPDATE network_flows SET threat_id=NULL, severity=NULL WHERE org_id=$1 AND cluster_id=$2 AND threat_id IN (2011,2012,2027)`, subj.OrgID, clusterID)
	}
	if p.auditLog != nil {
		orgID, userID := subj.OrgID, subj.UserID
		actorIP := net.ParseIP(r.RemoteAddr)
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			actorIP = net.ParseIP(host)
		}
		_, _, _ = p.auditLog.Log(r.Context(), audit.Event{
			OrgID: &orgID, ActorID: &userID, ActorIP: actorIP,
			Action: "dpi_threat_settings.update", TargetKind: "dpi-threat-settings", TargetID: clusterID.String(),
			After: map[string]any{"weak_tls_enabled": body.WeakTLSEnabled}, RequestID: chimw.GetReqID(r.Context()),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, dpiThreatSettingsDTO{ClusterID: clusterID.String(), WeakTLSEnabled: body.WeakTLSEnabled})
}
