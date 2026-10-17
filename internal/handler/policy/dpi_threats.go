package policy

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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
	if !p.dpiClusterOwned(w, r, subj.OrgID, clusterID) {
		return
	}
	dto := dpiThreatSettingsDTO{ClusterID: clusterID.String()}
	err := p.db.Pool().QueryRow(r.Context(),
		`SELECT weak_tls_enabled FROM dpi_threat_settings WHERE org_id = $1 AND cluster_id = $2`,
		subj.OrgID, clusterID).Scan(&dto.WeakTLSEnabled)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusInternalServerError, "could not load DPI threat settings")
		return
	}
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
	if !p.dpiClusterOwned(w, r, subj.OrgID, clusterID) {
		return
	}
	var body struct {
		WeakTLSEnabled         *bool `json:"weak_tls_enabled"`
		ExpectedWeakTLSEnabled *bool `json:"expected_weak_tls_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.WeakTLSEnabled == nil {
		jsonError(w, http.StatusBadRequest, "weak_tls_enabled must be an explicit boolean")
		return
	}
	enabled := *body.WeakTLSEnabled
	ctx := r.Context()
	tx, err := p.db.Pool().Begin(ctx)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "could not update DPI threat settings")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The owned cluster row serializes both existing and absent-default settings.
	var owned uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM clusters WHERE id=$1 AND org_id=$2 FOR UPDATE`, clusterID, subj.OrgID).Scan(&owned); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "cluster not found")
		} else {
			jsonError(w, http.StatusInternalServerError, "could not lock DPI settings cluster")
		}
		return
	}
	var current bool
	if err := tx.QueryRow(ctx, `SELECT weak_tls_enabled FROM dpi_threat_settings WHERE org_id=$1 AND cluster_id=$2`, subj.OrgID, clusterID).Scan(&current); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusInternalServerError, "could not load current DPI threat settings")
		return
	}
	if body.ExpectedWeakTLSEnabled != nil && *body.ExpectedWeakTLSEnabled != current {
		jsonError(w, http.StatusConflict, "configured weak-TLS setting changed; refresh and review before saving")
		return
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO dpi_threat_settings (org_id, cluster_id, weak_tls_enabled, updated_by, updated_at)
VALUES ($1,$2,$3,$4,NOW())
ON CONFLICT (org_id, cluster_id) DO UPDATE SET
  weak_tls_enabled = EXCLUDED.weak_tls_enabled, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		subj.OrgID, clusterID, enabled, subj.UserID); err != nil {
		jsonError(w, http.StatusInternalServerError, "could not update DPI threat settings")
		return
	}
	// Disabling and evidence cleanup commit together, or every change rolls back.
	if !enabled {
		for _, sql := range []string{
			`DELETE FROM runtime_threats WHERE org_id=$1 AND cluster_id=$2 AND threat_id IN (2011,2012,2027)`,
			`UPDATE network_flow_rollups SET max_threat_id=0, max_severity=0 WHERE org_id=$1 AND cluster_id=$2 AND max_threat_id IN (2011,2012,2027)`,
			`UPDATE network_flows SET threat_id=NULL, severity=NULL WHERE org_id=$1 AND cluster_id=$2 AND threat_id IN (2011,2012,2027)`,
		} {
			if _, err := tx.Exec(ctx, sql, subj.OrgID, clusterID); err != nil {
				jsonError(w, http.StatusInternalServerError, "could not remove weak-TLS evidence; settings change rolled back")
				return
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		jsonError(w, http.StatusInternalServerError, "could not commit DPI threat settings")
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
			Action: "dpi_threat_settings.update", TargetKind: "dpi-threat-settings", TargetID: clusterID.String(),
			After: map[string]any{"cluster_id": clusterID.String(), "weak_tls_enabled": enabled}, RequestID: chimw.GetReqID(r.Context()),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, dpiThreatSettingsDTO{ClusterID: clusterID.String(), WeakTLSEnabled: enabled})
}

func (p *Policies) dpiClusterOwned(w http.ResponseWriter, r *http.Request, orgID, clusterID uuid.UUID) bool {
	var owned bool
	if err := p.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE org_id=$1 AND id=$2)`, orgID, clusterID).Scan(&owned); err != nil {
		jsonError(w, http.StatusInternalServerError, "could not resolve DPI settings cluster")
		return false
	}
	if !owned {
		jsonError(w, http.StatusNotFound, "cluster not found")
		return false
	}
	return true
}
