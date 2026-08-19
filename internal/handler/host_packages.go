// Host-package snapshot ingest + read endpoints (Slice D.1).
//
//	POST /api/v1/host-packages:report   — runtime-agent upsert
//	GET  /api/v1/host-packages          — list latest per node
//	GET  /api/v1/host-packages/{node}   — single snapshot lookup
//
// CVE matching is performed by scanner workers. The API stores host package
// evidence, updates a host scan target, and enqueues target-backed work.
package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/scanner"
)

type HostPackagesPayload struct {
	Node          string            `json:"node"`
	ObservedAt    time.Time         `json:"observed_at"`
	Distro        string            `json:"distro,omitempty"`
	DistroVersion string            `json:"distro_version,omitempty"`
	Source        string            `json:"source,omitempty"` // dpkg | rpm | apk
	Count         int               `json:"count"`
	Items         []HostPackageItem `json:"items"`
}

type HostPackageItem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Source  string `json:"source,omitempty"`
}

type HostPackagesHandler struct {
	db *db.DB
}

func NewHostPackages(d *db.DB) *HostPackagesHandler {
	return &HostPackagesHandler{db: d}
}

func (h *HostPackagesHandler) Report(w http.ResponseWriter, r *http.Request) {
	tok, ok := runtimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	// 8 MiB cap: ~5000 packages × ~150 bytes JSON each ≈ 750 KiB, headroom × 10.
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)

	var body HostPackagesPayload
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if strings.TrimSpace(body.Node) == "" {
		jsonError(w, http.StatusBadRequest, "node is required")
		return
	}
	if body.ObservedAt.IsZero() {
		body.ObservedAt = time.Now().UTC()
	}
	raw, err := json.Marshal(&body)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "re-encode: "+err.Error())
		return
	}

	// Attribute to the cluster the agent token was minted for (init-bundle),
	// not the org's oldest cluster. clusterID is nil only for a token with no
	// bundle mapping; the upsert stays NULL-safe (dedups on (org_id, node)).
	// clusterID is also threaded into the scan-target upsert below.
	clusterID, err := ResolveAgentClusterID(r.Context(), h.db, tok)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "resolve cluster: "+err.Error())
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "begin: "+err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if _, err := tx.Exec(r.Context(), `
INSERT INTO host_packages (
    org_id, cluster_id, node, package_count, source, distro,
    payload, observed_at, updated_at
) VALUES ($1, $2, $3, $4, NULLIF($5,''), NULLIF($6,''), $7, $8, NOW())
ON CONFLICT (org_id, COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid), node) DO UPDATE SET
    package_count = EXCLUDED.package_count,
    source        = EXCLUDED.source,
    distro        = EXCLUDED.distro,
    payload       = EXCLUDED.payload,
    observed_at   = EXCLUDED.observed_at,
    updated_at    = NOW()
`,
		tok.OrgID, clusterID, body.Node, body.Count,
		body.Source, body.Distro, raw, body.ObservedAt,
	); err != nil {
		jsonError(w, http.StatusInternalServerError, "insert: "+err.Error())
		return
	}

	evidencePayload := scanEvidencePackagePayload{
		Packages:      scannerPackagesFromHostPackages(body),
		Distro:        body.Distro,
		DistroVersion: body.DistroVersion,
		Source:        body.Source,
		Node:          body.Node,
	}
	inventoryHash, err := packageEvidenceHash(evidencePayload)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "evidence hash: "+err.Error())
		return
	}
	metadata, _ := json.Marshal(map[string]any{
		"node":           body.Node,
		"distro":         body.Distro,
		"distro_version": body.DistroVersion,
		"source":         body.Source,
		"package_count":  len(evidencePayload.Packages),
	})
	target, err := upsertScanTarget(r.Context(), nil, tx, tok.OrgID, scanTargetUpsert{
		TargetType:      "host",
		TargetRef:       body.Node,
		TargetClusterID: clusterID,
		SourceType:      "host",
		SourceRef:       body.Node,
		InventoryHash:   inventoryHash,
		Metadata:        metadata,
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "scan target: "+err.Error())
		return
	}
	evidenceID, err := upsertPackageScanEvidence(r.Context(), tx, tok.OrgID, target, inventoryHash, evidencePayload, body.ObservedAt)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "scan evidence: "+err.Error())
		return
	}

	var exists bool
	if err := tx.QueryRow(r.Context(), `
SELECT EXISTS(
    SELECT 1
      FROM scan_jobs
     WHERE org_id = $1
       AND target_id = $2
       AND status IN ('pending', 'running', 'paused')
)`, tok.OrgID, target.ID).Scan(&exists); err != nil {
		jsonError(w, http.StatusInternalServerError, "scan job check: "+err.Error())
		return
	}
	var jobID *uuid.UUID
	if !exists {
		id := uuid.New()
		if _, err := tx.Exec(r.Context(), `
INSERT INTO scan_jobs (id, org_id, target_id, status)
VALUES ($1, $2, $3, 'pending')`, id, tok.OrgID, target.ID); err != nil {
			jsonError(w, http.StatusInternalServerError, "enqueue scan job: "+err.Error())
			return
		}
		jobID = &id
	}

	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"scan_target_id":     target.ID,
		"scan_evidence_id":   evidenceID,
		"inventory_hash":     inventoryHash,
		"package_count":      len(evidencePayload.Packages),
		"scan_job_enqueued":  jobID != nil,
		"scan_job_id":        jobID,
		"scanner_source":     "scan_evidence",
		"scanner_target_ref": target.Ref,
	})
}

func scannerPackagesFromHostPackages(body HostPackagesPayload) []scanner.Package {
	namespace := hostPackageNamespace(body.Distro)
	if namespace == "" {
		namespace = strings.ToLower(strings.TrimSpace(body.Distro))
	}
	out := make([]scanner.Package, 0, len(body.Items))
	for _, item := range body.Items {
		name := strings.TrimSpace(item.Name)
		version := strings.TrimSpace(item.Version)
		if name == "" || version == "" {
			continue
		}
		source := strings.TrimSpace(item.Source)
		if source == "" {
			source = strings.TrimSpace(body.Source)
		}
		source = hostPackageEcosystem(source)
		out = append(out, scanner.Package{
			Ecosystem:        source,
			Name:             name,
			Version:          version,
			Arch:             strings.TrimSpace(item.Arch),
			NamespaceKind:    "os",
			NamespaceName:    namespace,
			NamespaceVersion: strings.TrimSpace(body.DistroVersion),
		})
	}
	return out
}

// HostPackageEcosystem / HostPackageNamespace are exported seams over the
// package-internal helpers, consumed by the handler/scanning sub-package
// (workload package ingest).
func HostPackageEcosystem(source string) string { return hostPackageEcosystem(source) }

func hostPackageEcosystem(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "dpkg":
		return "deb"
	case "rpm":
		return "rpm"
	case "apk":
		return "apk"
	default:
		return strings.ToLower(strings.TrimSpace(source))
	}
}

// PackageEvidenceHash is the exported seam over packageEvidenceHash, consumed by
// the handler/scanning sub-package (workload/serverless package ingest).
func PackageEvidenceHash(payload ScanEvidencePackagePayload) (string, error) {
	return packageEvidenceHash(payload)
}

func packageEvidenceHash(payload scanEvidencePackagePayload) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// HostPackageNamespace is the exported seam over hostPackageNamespace.
func HostPackageNamespace(distroID string) string { return hostPackageNamespace(distroID) }

func hostPackageNamespace(distroID string) string {
	switch strings.ToLower(strings.TrimSpace(distroID)) {
	case "ubuntu":
		return "ubuntu"
	case "debian":
		return "debian"
	case "alpine":
		return "alpine"
	case "rhel", "redhat", "redhatenterpriseserver":
		return "rhel"
	case "centos":
		return "centos"
	case "rocky":
		return "rocky"
	case "almalinux":
		return "almalinux"
	case "ol", "oracle", "oraclelinux":
		return "oracle"
	case "amzn", "amazon", "amazonlinux":
		return "amazon"
	case "sles", "suse", "opensuse", "opensuse-leap", "opensuse-tumbleweed":
		return "suse"
	case "photon":
		return "photon"
	case "azurelinux", "mariner", "cbl-mariner":
		return "azurelinux"
	case "wolfi":
		return "wolfi"
	}
	return ""
}

type HostPackagesRow struct {
	Node         string          `json:"node"`
	ClusterID    *uuid.UUID      `json:"cluster_id,omitempty"`
	PackageCount int             `json:"package_count"`
	Source       string          `json:"source,omitempty"`
	Distro       string          `json:"distro,omitempty"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	ObservedAt   time.Time       `json:"observed_at"`
}

func (h *HostPackagesHandler) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT node, cluster_id, package_count, COALESCE(source,''),
       COALESCE(distro,''), payload, observed_at
  FROM host_packages
 WHERE org_id = $1
 ORDER BY observed_at DESC
 LIMIT 500`, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()
	out := make([]HostPackagesRow, 0)
	for rows.Next() {
		var rrow HostPackagesRow
		if err := rows.Scan(&rrow.Node, &rrow.ClusterID, &rrow.PackageCount,
			&rrow.Source, &rrow.Distro, &rrow.Payload, &rrow.ObservedAt,
		); err != nil {
			jsonError(w, http.StatusInternalServerError, "scan: "+err.Error())
			return
		}
		out = append(out, rrow)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *HostPackagesHandler) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	node := chi.URLParam(r, "node")
	if node == "" {
		jsonError(w, http.StatusBadRequest, "node required")
		return
	}
	var rrow HostPackagesRow
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT node, cluster_id, package_count, COALESCE(source,''),
       COALESCE(distro,''), payload, observed_at
  FROM host_packages
 WHERE org_id = $1 AND node = $2
 ORDER BY observed_at DESC
 LIMIT 1`, subj.OrgID, node).Scan(
		&rrow.Node, &rrow.ClusterID, &rrow.PackageCount,
		&rrow.Source, &rrow.Distro, &rrow.Payload, &rrow.ObservedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "no host-packages for node")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rrow)
}
