package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	searchdsl "github.com/alphabravocompany/constellation/pkg/search/dsl"
)

type Assets struct {
	db *db.DB
}

func NewAssets(database *db.DB) *Assets { return &Assets{db: database} }

type assetDTO struct {
	ID               uuid.UUID       `json:"id"`
	Kind             string          `json:"kind"`
	Name             string          `json:"name"`
	Digest           *string         `json:"digest,omitempty"`
	Labels           json.RawMessage `json:"labels"`
	AIWorkload       bool            `json:"ai_workload"`
	Criticality      string          `json:"criticality"`
	FindingCount     int             `json:"finding_count"`
	CriticalFindings int             `json:"critical_findings"`
	HighFindings     int             `json:"high_findings"`
	OpenFindings     int             `json:"open_findings"`
	SBOMCount        int             `json:"sbom_count"`
	ImageSigned      *bool           `json:"image_signed,omitempty"`
	Registry         string          `json:"registry,omitempty"`
	Repository       string          `json:"repository,omitempty"`
	Tag              string          `json:"tag,omitempty"`
	SizeBytes        *int64          `json:"size_bytes,omitempty"`
	FirstSeenAt      time.Time       `json:"first_seen_at"`
	LastSeenAt       time.Time       `json:"last_seen_at"`
}

func (a *Assets) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	qstr := r.URL.Query().Get("q")
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	compiled, err := searchdsl.Compile(qstr, assetsSearchSchema)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "search: " + err.Error()})
		return
	}
	args := []any{subj.OrgID, clusterArg}
	extraWhere := ""
	if !compiled.Empty() {
		extraWhere = " AND " + shiftPlaceholders(compiled.Where, len(args))
		args = append(args, compiled.Args...)
	}
	args = append(args, limit, offset)
	rows, err := a.db.Pool().Query(r.Context(),
		`WITH generic_finding_rollup AS (
             SELECT asset_id,
                    count(*)::int AS finding_count,
                    count(*) FILTER (WHERE severity = 'critical')::int AS critical_findings,
                    count(*) FILTER (WHERE severity = 'high')::int AS high_findings,
                    count(*) FILTER (WHERE lifecycle NOT IN ('resolved', 'suppressed'))::int AS open_findings
               FROM findings
              WHERE org_id = $1
                AND ($2::uuid IS NULL OR cluster_id = $2)
              GROUP BY asset_id
           ), latest_image_results AS (
             SELECT DISTINCT ON (asset_id, image_digest, platform, scanner_profile)
                    id, org_id, asset_id
               FROM image_scan_results
              WHERE org_id = $1 AND asset_id IS NOT NULL
              ORDER BY asset_id, image_digest, platform, scanner_profile, last_scanned_at DESC
           ), image_finding_rollup AS (
             SELECT lir.asset_id,
                    count(*)::int AS finding_count,
                    count(*) FILTER (WHERE f.severity = 'critical')::int AS critical_findings,
                    count(*) FILTER (WHERE f.severity = 'high')::int AS high_findings,
                    count(*)::int AS open_findings
               FROM latest_image_results lir
               JOIN image_scan_findings f ON f.image_scan_result_id = lir.id
              GROUP BY lir.asset_id
           ), sbom_rollup AS (
             SELECT asset_id, count(DISTINCT format)::int AS sbom_count
               FROM (
                 SELECT lir.asset_id, a.format
                   FROM latest_image_results lir
                   JOIN image_scan_artifacts a
                     ON a.org_id = lir.org_id
                    AND a.image_scan_result_id = lir.id
                    AND a.artifact_type = 'sbom'
                 UNION ALL
                 SELECT d.asset_id, d.format
                   FROM sbom_documents d
                   JOIN assets da ON da.id = d.asset_id
                  WHERE da.org_id = $1
                    AND ($2::uuid IS NULL OR da.cluster_id = $2)
               ) sb
              GROUP BY asset_id
           )
           SELECT a.id, a.kind, a.name, a.digest, a.labels, a.ai_workload, a.criticality,
                  COALESCE(fr.finding_count, 0), COALESCE(fr.critical_findings, 0),
                  COALESCE(fr.high_findings, 0), COALESCE(fr.open_findings, 0),
                  COALESCE(sr.sbom_count, 0), i.signed, COALESCE(i.registry, ''),
                  COALESCE(i.repository, ''), COALESCE(i.tag, ''), i.size_bytes,
                  a.first_seen_at, a.last_seen_at
             FROM assets a
             LEFT JOIN generic_finding_rollup gfr ON gfr.asset_id = a.id
             LEFT JOIN image_finding_rollup ifr ON ifr.asset_id = a.id
             LEFT JOIN LATERAL (
                 SELECT CASE WHEN a.kind = 'image'
                             THEN COALESCE(ifr.finding_count, 0)
                             ELSE COALESCE(gfr.finding_count, 0)
                        END AS finding_count,
                        CASE WHEN a.kind = 'image'
                             THEN COALESCE(ifr.critical_findings, 0)
                             ELSE COALESCE(gfr.critical_findings, 0)
                        END AS critical_findings,
                        CASE WHEN a.kind = 'image'
                             THEN COALESCE(ifr.high_findings, 0)
                             ELSE COALESCE(gfr.high_findings, 0)
                        END AS high_findings,
                        CASE WHEN a.kind = 'image'
                             THEN COALESCE(ifr.open_findings, 0)
                             ELSE COALESCE(gfr.open_findings, 0)
                        END AS open_findings
             ) fr ON true
             LEFT JOIN sbom_rollup sr ON sr.asset_id = a.id
             LEFT JOIN images i ON i.asset_id = a.id
            WHERE a.org_id = $1
              AND ($2::uuid IS NULL OR a.cluster_id = $2)`+extraWhere+`
            ORDER BY COALESCE(fr.critical_findings, 0) DESC,
                     COALESCE(fr.high_findings, 0) DESC,
                     COALESCE(fr.finding_count, 0) DESC,
                     a.last_seen_at DESC
            LIMIT $`+itoa(len(args)-1)+` OFFSET $`+itoa(len(args)), args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := make([]assetDTO, 0, limit)
	for rows.Next() {
		var d assetDTO
		var labels []byte
		if err := rows.Scan(&d.ID, &d.Kind, &d.Name, &d.Digest, &labels, &d.AIWorkload,
			&d.Criticality, &d.FindingCount, &d.CriticalFindings, &d.HighFindings,
			&d.OpenFindings, &d.SBOMCount, &d.ImageSigned, &d.Registry, &d.Repository,
			&d.Tag, &d.SizeBytes, &d.FirstSeenAt, &d.LastSeenAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		d.Labels = labels
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets": out, "limit": limit, "offset": offset})
}

func (a *Assets) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	subj, _ := SubjectFrom(r.Context())
	var d assetDTO
	var labels []byte
	err = a.db.Pool().QueryRow(r.Context(),
		`SELECT id, kind, name, digest, labels, ai_workload, criticality, first_seen_at, last_seen_at
           FROM assets WHERE id = $1 AND org_id = $2`, id, subj.OrgID).
		Scan(&d.ID, &d.Kind, &d.Name, &d.Digest, &labels, &d.AIWorkload,
			&d.Criticality, &d.FirstSeenAt, &d.LastSeenAt)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	d.Labels = labels

	findings := []map[string]any{}
	var imageScanResult any
	if d.Kind == "image" {
		var imageDigest string
		if d.Digest != nil {
			imageDigest = *d.Digest
		}
		resultHandler := NewImageScanResults(a.db)
		var resultID uuid.UUID
		if err := a.db.Pool().QueryRow(r.Context(), `
SELECT id
  FROM image_scan_results
 WHERE org_id = $1
   AND (asset_id = $2 OR ($3 <> '' AND image_digest = $3))
 ORDER BY last_scanned_at DESC
 LIMIT 1`, subj.OrgID, id, imageDigest).Scan(&resultID); err == nil {
			result, err := resultHandler.getResult(r, subj.OrgID, resultID)
			if err == nil {
				imageScanResult = result
				if canonicalFindings, err := resultHandler.getFindings(r, subj.OrgID, resultID); err == nil {
					for _, f := range canonicalFindings {
						findings = append(findings, map[string]any{
							"id":                   f.ID.String(),
							"kind":                 "vulnerability",
							"external_id":          f.ExternalID,
							"title":                f.Title,
							"severity":             f.Severity,
							"risk_score":           f.RiskScore,
							"lifecycle":            "open",
							"last_seen_at":         f.LastSeenAt.UTC().Format(time.RFC3339),
							"image_scan_result_id": f.ImageScanResultID.String(),
							"finding_key":          f.FindingKey,
						})
					}
				}
			}
		}
	}
	rows, err := a.db.Pool().Query(r.Context(), `
SELECT id, kind, external_id, title, severity, risk_score, lifecycle, last_seen_at
  FROM findings
 WHERE org_id = $1 AND asset_id = $2
 ORDER BY risk_score DESC, last_seen_at DESC
 LIMIT 100`, subj.OrgID, id)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var (
				fid, kind, externalID, title, severity, lifecycle string
				risk                                              int
				lastSeen                                          time.Time
			)
			if err := rows.Scan(&fid, &kind, &externalID, &title, &severity, &risk, &lifecycle, &lastSeen); err == nil {
				findings = append(findings, map[string]any{
					"id": fid, "kind": kind, "external_id": externalID, "title": title,
					"severity": severity, "risk_score": risk, "lifecycle": lifecycle,
					"last_seen_at": lastSeen.UTC().Format(time.RFC3339),
				})
			}
		}
	}

	var image map[string]any
	var registry, repository, tag, digest string
	var layers, architectures, sigInfo []byte
	var size *int64
	var signed bool
	var pulled time.Time
	if err := a.db.Pool().QueryRow(r.Context(), `
SELECT registry, repository, COALESCE(tag,''), digest, layers, architectures, size_bytes,
       signed, signature_info, pulled_at
  FROM images WHERE asset_id = $1`, id).
		Scan(&registry, &repository, &tag, &digest, &layers, &architectures, &size, &signed, &sigInfo, &pulled); err == nil {
		image = map[string]any{
			"registry": registry, "repository": repository, "tag": tag, "digest": digest,
			"layers": json.RawMessage(layers), "architectures": json.RawMessage(architectures),
			"size_bytes": size, "signed": signed, "signature_info": json.RawMessage(sigInfo),
			"pulled_at": pulled.UTC().Format(time.RFC3339),
		}
	}

	sboms := []map[string]any{}
	sbomRows, err := a.db.Pool().Query(r.Context(), `
SELECT id, format, sha256, created_at
  FROM (
        SELECT DISTINCT ON (format)
               id, format, sha256, created_at, source_priority
          FROM (
                SELECT a.id::text AS id, a.format, a.sha256, a.created_at, 0 AS source_priority
                  FROM image_scan_results r
                  JOIN image_scan_artifacts a
                    ON a.org_id = r.org_id
                   AND a.image_scan_result_id = r.id
                 WHERE r.org_id = $1
                   AND r.asset_id = $2
                   AND a.artifact_type = 'sbom'
                UNION ALL
                SELECT d.id::text AS id, d.format, d.sha256, d.created_at, 1 AS source_priority
                  FROM sbom_documents d
                  JOIN assets da ON da.id = d.asset_id
                 WHERE da.org_id = $1
                   AND d.asset_id = $2
               ) sb
         ORDER BY format, source_priority, created_at DESC
       ) latest_by_format
 ORDER BY created_at DESC`, subj.OrgID, id)
	if err == nil {
		defer sbomRows.Close()
		for sbomRows.Next() {
			var sid, format, sha string
			var created time.Time
			if err := sbomRows.Scan(&sid, &format, &sha, &created); err == nil {
				sboms = append(sboms, map[string]any{
					"id": sid, "format": format, "sha256": sha, "created_at": created.UTC().Format(time.RFC3339),
				})
			}
		}
	}

	imageAcceptances, err := NewImageAcceptances(a.db, nil).listForAsset(r, subj.OrgID, id)
	if err != nil {
		imageAcceptances = []imageAcceptanceDTO{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"asset": d, "image": image, "findings": findings, "sboms": sboms,
		"image_acceptances": imageAcceptances,
		"image_scan_result": imageScanResult,
	})
}
