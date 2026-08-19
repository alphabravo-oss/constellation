package runtime

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// Forensics serves captured forensic snapshots (compressed envelopes of K8s state +
// recent logs + flows captured at quarantine or critical-alert time).
type Forensics struct {
	db *db.DB
}

// NewForensics constructs a Forensics handler.
func NewForensics(d *db.DB) *Forensics { return &Forensics{db: d} }

type forensicsSnapshotDTO struct {
	ID            string `json:"id"`
	ClusterID     string `json:"cluster_id,omitempty"`
	DeploymentID  string `json:"deployment_id,omitempty"`
	PodName       string `json:"pod_name,omitempty"`
	Namespace     string `json:"namespace,omitempty"`
	Trigger       string `json:"trigger"`
	PayloadSHA256 string `json:"payload_sha256"`
	SizeBytes     int64  `json:"size_bytes"`
	CapturedAt    string `json:"captured_at"`
}

// Get returns a single snapshot's metadata. The payload is downloaded via a separate
// signed-URL or admin tool; this endpoint never returns raw payload bytes.
func (h *Forensics) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "snapshot_id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad snapshot id")
		return
	}
	var (
		clusterID    *uuid.UUID
		deploymentID *uuid.UUID
		podName      *string
		namespace    *string
		trigger      string
		sha          string
		size         int64
		capturedAt   time.Time
	)
	err = h.db.Pool().QueryRow(r.Context(), `
SELECT cluster_id, deployment_id, pod_name, namespace, trigger, payload_sha256, size_bytes, captured_at
  FROM forensics_snapshots
 WHERE id = $1 AND org_id = $2`,
		id, subj.OrgID).
		Scan(&clusterID, &deploymentID, &podName, &namespace, &trigger, &sha, &size, &capturedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "snapshot not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	dto := forensicsSnapshotDTO{
		ID:            id.String(),
		Trigger:       trigger,
		PayloadSHA256: sha,
		SizeBytes:     size,
		CapturedAt:    capturedAt.UTC().Format(time.RFC3339),
	}
	if clusterID != nil {
		dto.ClusterID = clusterID.String()
	}
	if deploymentID != nil {
		dto.DeploymentID = deploymentID.String()
	}
	if podName != nil {
		dto.PodName = *podName
	}
	if namespace != nil {
		dto.Namespace = *namespace
	}
	httpx.WriteJSON(w, http.StatusOK, dto)
}
