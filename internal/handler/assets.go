package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler/platformrole"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
)

type Assets struct {
	db *db.DB
}

func NewAssets(database *db.DB) *Assets { return &Assets{db: database} }

type assetDTO struct {
	PlatformRole     string          `json:"platform_role"`
	ID               uuid.UUID       `json:"id"`
	ClusterID        *uuid.UUID      `json:"cluster_id,omitempty"`
	Kind             string          `json:"kind"`
	Name             string          `json:"name"`
	DisplayName      string          `json:"display_name"`
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

func (a *Assets) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	fail := func() {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "asset evidence unavailable"})
	}
	var d assetDTO
	var labels []byte
	err = a.db.Pool().QueryRow(r.Context(),
		`SELECT a.id, a.cluster_id, a.kind, a.name, `+assetDisplayNameSQL+`, a.digest, a.labels, a.ai_workload, a.criticality, a.first_seen_at, a.last_seen_at, `+platformrole.AssetPlatformRoleSQL("a")+`
           FROM assets a LEFT JOIN images i ON i.asset_id=a.id WHERE a.id = $1 AND a.org_id = $2`, id, subj.OrgID).
		Scan(&d.ID, &d.ClusterID, &d.Kind, &d.Name, &d.DisplayName, &d.Digest, &labels, &d.AIWorkload,
			&d.Criticality, &d.FirstSeenAt, &d.LastSeenAt, &d.PlatformRole)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		fail()
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
		err := a.db.Pool().QueryRow(r.Context(), `
SELECT id FROM image_scan_results
 WHERE org_id=$1 AND (($3<>'' AND image_digest=$3) OR ($3='' AND asset_id=$2))
 ORDER BY last_scanned_at DESC NULLS LAST, id DESC LIMIT 1`, subj.OrgID, id, imageDigest).Scan(&resultID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			fail()
			return
		}
		if err == nil {
			result, e := resultHandler.getResult(r, subj.OrgID, resultID)
			if e != nil {
				fail()
				return
			}
			imageScanResult = result
			canonicalFindings, e := resultHandler.getFindings(r, subj.OrgID, resultID)
			if e != nil {
				fail()
				return
			}
			for _, f := range canonicalFindings {
				findings = append(findings, map[string]any{
					"id": f.ID.String(), "kind": "vulnerability", "external_id": f.ExternalID, "title": f.Title, "severity": f.Severity, "risk_score": f.RiskScore, "lifecycle": "open", "last_seen_at": f.LastSeenAt.UTC().Format(time.RFC3339), "image_scan_result_id": f.ImageScanResultID.String(), "finding_key": f.FindingKey, "platform_role": "",
				})
			}
		}
	}
	rows, err := a.db.Pool().Query(r.Context(), `
SELECT id, kind, COALESCE(external_id,''), title, severity, risk_score, lifecycle, last_seen_at, `+platformrole.FindingPlatformRoleSQL("findings")+`,first_seen_at,revision::text,cluster_id,target_cluster_id,id::text||':'||extract(epoch FROM first_seen_at)::text
  FROM findings
 WHERE org_id = $1 AND asset_id = $2 AND cluster_id IS NOT DISTINCT FROM $3::uuid
 ORDER BY risk_score DESC, last_seen_at DESC, id, first_seen_at
 LIMIT 100`, subj.OrgID, id, d.ClusterID)
	if err != nil {
		fail()
		return
	}
	defer rows.Close()
	for rows.Next() {
		var (
			fid, kind, externalID, title, severity, lifecycle, role string
			risk                                                    int
			lastSeen                                                time.Time
			firstSeen                                               time.Time
			revision, rowID                                         string
			sourceCluster, targetCluster                            *uuid.UUID
		)
		if err := rows.Scan(&fid, &kind, &externalID, &title, &severity, &risk, &lifecycle, &lastSeen, &role, &firstSeen, &revision, &sourceCluster, &targetCluster, &rowID); err != nil {
			fail()
			return
		}
		findings = append(findings, map[string]any{
			"id": fid, "kind": kind, "external_id": externalID, "title": title,
			"severity": severity, "risk_score": risk, "lifecycle": lifecycle,
			"last_seen_at": lastSeen.UTC().Format(time.RFC3339), "platform_role": role,
			"first_seen_at": firstSeen.UTC().Format(time.RFC3339Nano), "revision": revision, "row_id": rowID,
			"source_cluster_id": sourceCluster, "target_cluster_id": targetCluster,
		})
	}

	if rows.Err() != nil {
		fail()
		return
	}
	rows.Close()
	var image map[string]any
	var registry, repository, tag, digest string
	var layers, architectures, sigInfo []byte
	var size *int64
	var signed bool
	var pulled time.Time
	err = a.db.Pool().QueryRow(r.Context(), `
SELECT registry, repository, COALESCE(tag,''), digest, layers, architectures, size_bytes,
       signed, signature_info, pulled_at
  FROM images WHERE asset_id = $1`, id).
		Scan(&registry, &repository, &tag, &digest, &layers, &architectures, &size, &signed, &sigInfo, &pulled)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		fail()
		return
	}
	if err == nil {
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
	if err != nil {
		fail()
		return
	}
	defer sbomRows.Close()
	for sbomRows.Next() {
		var sid, format, sha string
		var created time.Time
		if err := sbomRows.Scan(&sid, &format, &sha, &created); err != nil {
			fail()
			return
		}
		sboms = append(sboms, map[string]any{
			"id": sid, "format": format, "sha256": sha, "created_at": created.UTC().Format(time.RFC3339),
		})
	}

	if sbomRows.Err() != nil {
		fail()
		return
	}
	sbomRows.Close()
	imageAcceptances, err := NewImageAcceptances(a.db, nil).listForAsset(r, subj.OrgID, id)
	if err != nil {
		fail()
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"asset": d, "image": image, "findings": findings, "sboms": sboms,
		"image_acceptances": imageAcceptances,
		"image_scan_result": imageScanResult,
	})
}
