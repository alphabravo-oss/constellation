package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

// CrossScan triggers a fan-out scan across the named cluster. The scan is realized by
// creating image scan targets for each distinct discovered workload image and queueing
// one scan job per target. Jobs already pending for the same cluster target are not
// re-enqueued.
func (h *Clusters) CrossScan(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	clusterID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad cluster id")
		return
	}
	var body struct {
		Platform string `json:"platform,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	// Verify cluster belongs to caller's org.
	var orgID uuid.UUID
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT org_id FROM clusters WHERE id = $1`, clusterID).Scan(&orgID); err != nil {
		jsonError(w, http.StatusNotFound, "cluster not found")
		return
	}
	if orgID != subj.OrgID {
		jsonError(w, http.StatusForbidden, "cluster not in org")
		return
	}

	// Collect distinct images from the live workload inventory populated by the
	// discoverer. Fresh clusters should not require pre-existing image assets before
	// their first cluster scan can be queued.
	// Pull each distinct running image ref together with the digest the
	// discoverer resolved for it (from pod containerStatuses[].imageID, persisted
	// onto image_workload_links.image_digest). Carrying the digest onto the image
	// scan target lets it connect to package-evidence the runtime-agent keyed by
	// digest, so node-local images become scannable without a registry pull
	// (WS-F1). The LEFT JOIN keeps refs that have no resolved digest yet.
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT img.ref, COALESCE(MAX(l.image_digest), '') AS image_digest
  FROM deployments d
 CROSS JOIN LATERAL unnest(d.image_refs) AS img(ref)
  LEFT JOIN image_workload_links l
    ON l.org_id = d.org_id
   AND l.cluster_id = d.cluster_id
   AND l.image_ref = img.ref
   AND l.image_digest IS NOT NULL
 WHERE d.org_id = $1
   AND d.cluster_id = $2
   AND img.ref <> ''
 GROUP BY img.ref
 ORDER BY img.ref`, subj.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "collect images: "+err.Error())
		return
	}
	defer rows.Close()

	type discoveredImage struct {
		ref    string
		digest string
	}
	images := []discoveredImage{}
	for rows.Next() {
		var img discoveredImage
		if err := rows.Scan(&img.ref, &img.digest); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		images = append(images, img)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	enqueued := 0
	jobIDs := make([]string, 0, len(images))
	for _, img := range images {
		target, err := upsertScanTarget(r.Context(), h.db.Pool(), nil, subj.OrgID, scanTargetUpsert{
			TargetType:      "image",
			TargetRef:       img.ref,
			TargetClusterID: &clusterID,
			SourceType:      "discoverer",
			SourceRef:       clusterID.String(),
			ImageRef:        img.ref,
			ImageDigest:     img.digest,
			Platform:        body.Platform,
		})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "scan target: "+err.Error())
			return
		}

		// Skip if a pending job for the same cluster target already exists.
		var exists bool
		if err := h.db.Pool().QueryRow(r.Context(),
			`SELECT EXISTS(
				SELECT 1 FROM scan_jobs
				 WHERE org_id = $1
				   AND target_id = $2
				   AND status IN ('pending','running','paused')
			)`,
			subj.OrgID, target.ID).Scan(&exists); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if exists {
			continue
		}
		id := uuid.New()
		if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO scan_jobs (id, org_id, target_id, status, requested_by)
VALUES ($1, $2, $3, 'pending', $4)`,
			id, subj.OrgID, target.ID, subj.UserID); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		enqueued++
		jobIDs = append(jobIDs, id.String())
	}

	uid, oid := subj.UserID, subj.OrgID
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "cluster.cross-scan",
			TargetKind: "cluster", TargetID: clusterID.String(),
			After: map[string]any{"images_seen": len(images), "jobs_enqueued": enqueued},
		})
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"images_seen":   len(images),
		"jobs_enqueued": enqueued,
		"job_ids":       jobIDs,
	})
}
