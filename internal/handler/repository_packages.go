package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/scanner"
)

type RepositoryPackagesHandler struct {
	db *db.DB
}

func NewRepositoryPackages(d *db.DB) *RepositoryPackagesHandler {
	return &RepositoryPackagesHandler{db: d}
}

type RepositoryPackagesPayload struct {
	RepositoryRef string            `json:"repository_ref"`
	RepositoryURL string            `json:"repository_url,omitempty"`
	SourceType    string            `json:"source_type,omitempty"`
	SourceRef     string            `json:"source_ref,omitempty"`
	CommitSHA     string            `json:"commit_sha,omitempty"`
	Branch        string            `json:"branch,omitempty"`
	Path          string            `json:"path,omitempty"`
	Workflow      string            `json:"workflow,omitempty"`
	RunID         string            `json:"run_id,omitempty"`
	ObservedAt    time.Time         `json:"observed_at,omitempty"`
	PackageSource string            `json:"package_source,omitempty"`
	Packages      []scanner.Package `json:"packages,omitempty"`
}

func (h *RepositoryPackagesHandler) Report(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)

	var body RepositoryPackagesPayload
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	body.RepositoryRef = strings.TrimSpace(body.RepositoryRef)
	body.RepositoryURL = strings.TrimSpace(body.RepositoryURL)
	body.SourceType = normalizeRepositorySourceType(body.SourceType)
	body.SourceRef = strings.TrimSpace(body.SourceRef)
	body.CommitSHA = strings.TrimSpace(body.CommitSHA)
	body.Branch = strings.TrimSpace(body.Branch)
	body.Path = strings.TrimSpace(body.Path)
	body.Workflow = strings.TrimSpace(body.Workflow)
	body.RunID = strings.TrimSpace(body.RunID)
	body.PackageSource = strings.TrimSpace(body.PackageSource)
	if body.RepositoryRef == "" {
		jsonError(w, http.StatusBadRequest, "repository_ref is required")
		return
	}
	if !validScanSourceType(body.SourceType) {
		jsonError(w, http.StatusBadRequest, "unsupported source_type")
		return
	}
	if body.ObservedAt.IsZero() {
		body.ObservedAt = time.Now().UTC()
	}
	if body.SourceRef == "" {
		body.SourceRef = defaultRepositorySourceRef(body)
	}
	packages := scannerPackagesFromRepositoryPackages(body)
	if len(packages) == 0 {
		jsonError(w, http.StatusBadRequest, "no packages in repository evidence")
		return
	}

	targetRef := repositoryTargetRef(body.RepositoryRef, body.SourceRef)
	evidencePayload := scanEvidencePackagePayload{
		Packages:      packages,
		Source:        firstNonEmpty(body.PackageSource, "syft"),
		RepositoryRef: body.RepositoryRef,
		RepositoryURL: body.RepositoryURL,
		CommitSHA:     body.CommitSHA,
		Branch:        body.Branch,
		Path:          body.Path,
		Workflow:      body.Workflow,
		RunID:         body.RunID,
	}
	inventoryHash, err := packageEvidenceHash(evidencePayload)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "evidence hash: "+err.Error())
		return
	}
	metadata, _ := json.Marshal(map[string]any{
		"repository_ref": body.RepositoryRef,
		"repository_url": body.RepositoryURL,
		"source_ref":     body.SourceRef,
		"commit_sha":     body.CommitSHA,
		"branch":         body.Branch,
		"path":           body.Path,
		"workflow":       body.Workflow,
		"run_id":         body.RunID,
		"package_count":  len(packages),
	})

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "begin: "+err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	target, err := upsertScanTarget(r.Context(), nil, tx, subj.OrgID, scanTargetUpsert{
		TargetType:    "repository",
		TargetRef:     targetRef,
		SourceType:    body.SourceType,
		SourceRef:     body.SourceRef,
		InventoryHash: inventoryHash,
		Metadata:      metadata,
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "scan target: "+err.Error())
		return
	}
	evidenceID, err := upsertPackageScanEvidence(r.Context(), tx, subj.OrgID, target, inventoryHash, evidencePayload, body.ObservedAt)
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
)`, subj.OrgID, target.ID).Scan(&exists); err != nil {
		jsonError(w, http.StatusInternalServerError, "scan job check: "+err.Error())
		return
	}
	var jobID *uuid.UUID
	if !exists {
		id := uuid.New()
		if _, err := tx.Exec(r.Context(), `
INSERT INTO scan_jobs (id, org_id, target_id, status, requested_by)
VALUES ($1, $2, $3, 'pending', $4)`, id, subj.OrgID, target.ID, subj.UserID); err != nil {
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
		"package_count":      len(packages),
		"scan_job_enqueued":  jobID != nil,
		"scan_job_id":        jobID,
		"scanner_source":     "scan_evidence",
		"scanner_target_ref": target.Ref,
	})
}

func scannerPackagesFromRepositoryPackages(body RepositoryPackagesPayload) []scanner.Package {
	out := make([]scanner.Package, 0, len(body.Packages))
	for _, pkg := range body.Packages {
		pkg.Name = strings.TrimSpace(pkg.Name)
		pkg.Version = strings.TrimSpace(pkg.Version)
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		pkg.Ecosystem = strings.TrimSpace(pkg.Ecosystem)
		pkg.Purl = strings.TrimSpace(pkg.Purl)
		if pkg.NamespaceKind == "" && pkg.Ecosystem != "" {
			pkg.NamespaceKind = "language"
		}
		if pkg.NamespaceName == "" && pkg.Ecosystem != "" {
			pkg.NamespaceName = pkg.Ecosystem
		}
		out = append(out, pkg)
	}
	return out
}

func normalizeRepositorySourceType(sourceType string) string {
	sourceType = strings.TrimSpace(sourceType)
	if sourceType == "" {
		return "repository"
	}
	return normalizeScanSourceType(sourceType, "repository")
}

func defaultRepositorySourceRef(body RepositoryPackagesPayload) string {
	for _, value := range []string{body.CommitSHA, body.Branch, body.RepositoryURL, body.RepositoryRef} {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return "repository"
}

func repositoryTargetRef(repositoryRef, sourceRef string) string {
	repositoryRef = strings.TrimSpace(repositoryRef)
	sourceRef = strings.TrimSpace(sourceRef)
	if sourceRef == "" || sourceRef == repositoryRef {
		return repositoryRef
	}
	return repositoryRef + "@" + sourceRef
}
