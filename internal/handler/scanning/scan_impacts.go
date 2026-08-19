package scanning

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/imageid"
)

func (h *ScanJobs) ImpactedWorkloads(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad target id")
		return
	}

	target, err := h.loadScanTarget(r.Context(), nil, targetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "scan target not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, "scan target: "+err.Error())
		return
	}
	if target.OrgID != subj.OrgID {
		jsonError(w, http.StatusNotFound, "scan target not found")
		return
	}

	targetRefIdentity := imageid.Parse(target.Ref)
	imageRefIdentity := imageid.Parse(target.ImageRef)
	imageDigest := firstNonEmptyString(target.ImageDigest, imageRefIdentity.Digest, targetRefIdentity.Digest)

	out := []handler.ImpactedWorkload{}
	if target.Type == "image" {
		rows, err := h.db.Pool().Query(r.Context(), `
SELECT l.cluster_id,
       l.deployment_id,
       l.workload_id,
       l.namespace,
       l.name,
       l.kind,
       l.image_ref,
       l.image_ref_normalized,
       COALESCE(l.image_repository, ''),
       COALESCE(l.image_tag, ''),
       COALESCE(l.image_digest, ''),
       COALESCE(d.risk_score, 0),
       COALESCE(d.finding_count, 0),
       COALESCE(d.critical_count, 0),
       COALESCE(d.high_count, 0),
       l.last_seen_at
  FROM image_workload_links l
  LEFT JOIN deployments d ON d.id = l.deployment_id
 WHERE l.org_id = $1
   AND ($2::uuid IS NULL OR l.cluster_id = $2)
   AND (
        ($3 <> '' AND l.image_ref = $3)
     OR ($4 <> '' AND l.image_ref = $4)
     OR ($5 <> '' AND l.image_ref_normalized = $5)
     OR ($6 <> '' AND l.image_ref_normalized = $6)
     OR ($7 <> '' AND l.image_digest = $7)
   )
 ORDER BY COALESCE(d.risk_score, 0) DESC,
          COALESCE(d.critical_count, 0) DESC,
          COALESCE(d.high_count, 0) DESC,
          l.namespace,
          l.name
 LIMIT 1000`, subj.OrgID, target.ClusterID,
			target.Ref, target.ImageRef,
			targetRefIdentity.Normalized, imageRefIdentity.Normalized,
			imageDigest)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "impacted workloads: "+err.Error())
			return
		}
		defer rows.Close()
		for rows.Next() {
			var item handler.ImpactedWorkload
			if err := rows.Scan(
				&item.ClusterID,
				&item.DeploymentID,
				&item.WorkloadID,
				&item.Namespace,
				&item.Name,
				&item.Kind,
				&item.ImageRef,
				&item.ImageRefNormalized,
				&item.ImageRepository,
				&item.ImageTag,
				&item.ImageDigest,
				&item.RiskScore,
				&item.FindingCount,
				&item.CriticalCount,
				&item.HighCount,
				&item.LastSeenAt,
			); err != nil {
				jsonError(w, http.StatusInternalServerError, "scan impacted workload: "+err.Error())
				return
			}
			out = append(out, item)
		}
		if err := rows.Err(); err != nil {
			jsonError(w, http.StatusInternalServerError, "impacted workload rows: "+err.Error())
			return
		}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"target_id":          target.ID,
		"target_type":        target.Type,
		"target_ref":         target.Ref,
		"target_cluster_id":  target.ClusterID,
		"image_ref":          target.ImageRef,
		"image_digest":       imageDigest,
		"impacted_count":     len(out),
		"impacted_workloads": out,
	})
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
