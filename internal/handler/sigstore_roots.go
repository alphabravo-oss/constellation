// Sigstore roots-of-trust CRUD (per-org, REST-managed).
//
//	GET    /api/v1/sigstore-roots        — list this org's roots
//	POST   /api/v1/sigstore-roots        — create a root (name + root_pem and/or tuf_root)
//	DELETE /api/v1/sigstore-roots/{id}   — delete a root
//
// SIG-ROOTS-38: augments the process-wide --signature-roots flag consumed by the scanner
// (cmd/constellation-scanner: buildSignatureRoots → sigverify.RootsOfTrust). Each row maps
// to one sigverify.RootOfTrust; RootsForOrg assembles them so DB-managed roots feed the same
// "trusted if ANY root verifies" verification path as the flag-configured roots.
//
// Wiring point: cmd/constellation-scanner/buildSignatureRoots currently builds roots from the
// flag only. To make these DB roots live per scan job, append RootsForOrg(ctx, pool, job.OrgID)
// to the flag roots before VerifyWithRoots is called (the scanner worker already knows the
// job's org). That crosses into cmd/constellation-scanner, so it is left as the documented
// follow-up rather than changed here.
//
// Route wiring (add under the authed /api/v1 group in internal/server/server.go):
//
//	sigRoots := handler.NewSigstoreRoots(s.db, s.auditLog)
//	r.Get("/sigstore-roots", s.requireVerb(rbac.VerbReadFindings, sigRoots.List))
//	r.Post("/sigstore-roots", s.requireVerb(rbac.VerbManageRegistries, sigRoots.Create))
//	r.Delete("/sigstore-roots/{id}", s.requireVerb(rbac.VerbManageRegistries, sigRoots.Delete))
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/sigverify"
)

// SigstoreRoots handles /api/v1/sigstore-roots.
type SigstoreRoots struct {
	db    *db.DB
	audit *audit.Logger
}

// NewSigstoreRoots constructs the handler.
func NewSigstoreRoots(d *db.DB, a *audit.Logger) *SigstoreRoots {
	return &SigstoreRoots{db: d, audit: a}
}

type sigstoreRootDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	RootPEM   string `json:"root_pem,omitempty"`
	TUFRoot   string `json:"tuf_root,omitempty"`
	CreatedAt string `json:"created_at"`
}

type sigstoreRootCreateRequest struct {
	Name    string `json:"name"`
	RootPEM string `json:"root_pem"`
	TUFRoot string `json:"tuf_root"`
}

// List returns this org's sigstore roots.
func (h *SigstoreRoots) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	roots, err := loadSigstoreRoots(r.Context(), h.db.Pool(), subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roots": roots})
}

// Create adds a new root scoped to the caller's org.
func (h *SigstoreRoots) Create(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var req sigstoreRootCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.RootPEM = strings.TrimSpace(req.RootPEM)
	req.TUFRoot = strings.TrimSpace(req.TUFRoot)
	if req.Name == "" {
		jsonError(w, http.StatusBadRequest, "name required")
		return
	}
	if req.RootPEM == "" && req.TUFRoot == "" {
		jsonError(w, http.StatusBadRequest, "root_pem or tuf_root required")
		return
	}
	id := uuid.New()
	var createdAt time.Time
	err := h.db.Pool().QueryRow(r.Context(), `
INSERT INTO sigstore_roots (id, org_id, name, root_pem, tuf_root)
VALUES ($1, $2, $3, $4, $5)
RETURNING created_at`, id, subj.OrgID, req.Name, req.RootPEM, req.TUFRoot).Scan(&createdAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(err.Error(), "sigstore_roots_org_id_name_key") {
			jsonError(w, http.StatusConflict, "a root with that name already exists")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.auditEvent(r.Context(), subj, "sigstore_root.create", id.String(), map[string]any{"name": req.Name})
	writeJSON(w, http.StatusCreated, sigstoreRootDTO{
		ID:        id.String(),
		Name:      req.Name,
		RootPEM:   req.RootPEM,
		TUFRoot:   req.TUFRoot,
		CreatedAt: createdAt.UTC().Format(time.RFC3339),
	})
}

// Delete removes a root, org-scoped so one org can never delete another's.
func (h *SigstoreRoots) Delete(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad id")
		return
	}
	tag, err := h.db.Pool().Exec(r.Context(),
		`DELETE FROM sigstore_roots WHERE id = $1 AND org_id = $2`, id, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "root not found")
		return
	}
	h.auditEvent(r.Context(), subj, "sigstore_root.delete", id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *SigstoreRoots) auditEvent(ctx context.Context, subj Subject, action, targetID string, after map[string]any) {
	if h.audit == nil {
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	_, _, _ = h.audit.Log(ctx, audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action: action, TargetKind: "sigstore_root", TargetID: targetID,
		After: after,
	})
}

// loadSigstoreRoots returns all roots for orgID, newest first.
func loadSigstoreRoots(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) ([]sigstoreRootDTO, error) {
	rows, err := pool.Query(ctx, `
SELECT id, name, COALESCE(root_pem, ''), COALESCE(tuf_root, ''), created_at
  FROM sigstore_roots
 WHERE org_id = $1
 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []sigstoreRootDTO{}
	for rows.Next() {
		var (
			id        uuid.UUID
			name      string
			rootPEM   string
			tufRoot   string
			createdAt time.Time
		)
		if err := rows.Scan(&id, &name, &rootPEM, &tufRoot, &createdAt); err != nil {
			return nil, err
		}
		out = append(out, sigstoreRootDTO{
			ID:        id.String(),
			Name:      name,
			RootPEM:   rootPEM,
			TUFRoot:   tufRoot,
			CreatedAt: createdAt.UTC().Format(time.RFC3339),
		})
	}
	return out, rows.Err()
}

// RootsForOrg loads this org's DB-managed sigstore roots and maps each row to a
// sigverify.RootOfTrust, so the scanner can append them to the flag-configured roots and
// trust an image if ANY root (flag OR DB) verifies it. root_pem populates the cosign public
// key (Mode=public-key); tuf_root bootstraps a private TUF mirror for air-gapped installs.
// This is the seam the scanner's buildSignatureRoots would call per job's org.
func RootsForOrg(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) (sigverify.RootsOfTrust, error) {
	dtos, err := loadSigstoreRoots(ctx, pool, orgID)
	if err != nil {
		return nil, err
	}
	roots := make(sigverify.RootsOfTrust, 0, len(dtos))
	for _, d := range dtos {
		policy := sigverify.TrustPolicy{}
		if d.RootPEM != "" {
			policy.Mode = "public-key"
			policy.PublicKeyPEM = d.RootPEM
		}
		roots = append(roots, sigverify.RootOfTrust{
			Name:        d.Name,
			TrustPolicy: policy,
			TUFRootJSON: d.TUFRoot,
		})
	}
	return roots, nil
}
