package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// CustomRoles manages org-defined RBAC roles (named bundles of user-grantable
// verbs). Resolution for the authz gate is served from a small per-org TTL cache
// so the verb check stays off the request-path DB.
type CustomRoles struct {
	db    *pgxpool.Pool
	mu    sync.Mutex
	cache map[uuid.UUID]cachedRoles
}

type cachedRoles struct {
	verbs map[string][]rbac.Verb
	exp   time.Time
}

const customRoleTTL = 30 * time.Second

func NewCustomRoles(db *pgxpool.Pool) *CustomRoles {
	return &CustomRoles{db: db, cache: map[uuid.UUID]cachedRoles{}}
}

type customRoleDTO struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Verbs       []string `json:"verbs"`
}

// VerbsForOrg returns name->verbs for the org's custom roles, cached for
// customRoleTTL. Passed into rbac.AuthorizeWithCustom by the authz middleware.
func (h *CustomRoles) VerbsForOrg(ctx context.Context, orgID uuid.UUID) map[string][]rbac.Verb {
	h.mu.Lock()
	if c, ok := h.cache[orgID]; ok && time.Now().Before(c.exp) {
		h.mu.Unlock()
		return c.verbs
	}
	h.mu.Unlock()

	out := map[string][]rbac.Verb{}
	rows, err := h.db.Query(ctx, `SELECT name, verbs FROM custom_roles WHERE org_id = $1`, orgID)
	if err != nil {
		return out // fail closed: no custom grants on lookup error
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var verbs []string
		if rows.Scan(&name, &verbs) != nil {
			continue
		}
		vs := make([]rbac.Verb, 0, len(verbs))
		for _, v := range verbs {
			vs = append(vs, rbac.Verb(v))
		}
		out[name] = vs
	}
	h.mu.Lock()
	h.cache[orgID] = cachedRoles{verbs: out, exp: time.Now().Add(customRoleTTL)}
	h.mu.Unlock()
	return out
}

func (h *CustomRoles) invalidate(orgID uuid.UUID) {
	h.mu.Lock()
	delete(h.cache, orgID)
	h.mu.Unlock()
}

func (h *CustomRoles) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	rows, err := h.db.Query(r.Context(),
		`SELECT id, name, description, verbs FROM custom_roles WHERE org_id = $1 ORDER BY name`, subj.OrgID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []customRoleDTO{}
	for rows.Next() {
		var d customRoleDTO
		var id uuid.UUID
		if err := rows.Scan(&id, &d.Name, &d.Description, &d.Verbs); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		d.ID = id.String()
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": out, "grantable_verbs": grantableVerbNames()})
}

func (h *CustomRoles) Create(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	var body customRoleDTO
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	if rbac.IsRole(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name collides with a built-in role"})
		return
	}
	verbs, err := sanitizeGrantableVerbs(body.Verbs)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var id uuid.UUID
	err = h.db.QueryRow(r.Context(),
		`INSERT INTO custom_roles (org_id, name, description, verbs) VALUES ($1,$2,$3,$4) RETURNING id`,
		subj.OrgID, name, strings.TrimSpace(body.Description), verbs).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "custom_roles_org_id_name_key") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "a custom role with that name already exists"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	h.invalidate(subj.OrgID)
	writeJSON(w, http.StatusCreated, customRoleDTO{ID: id.String(), Name: name, Description: body.Description, Verbs: verbs})
}

func (h *CustomRoles) Update(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var body customRoleDTO
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	verbs, err := sanitizeGrantableVerbs(body.Verbs)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE custom_roles SET description=$1, verbs=$2, updated_at=now() WHERE id=$3 AND org_id=$4`,
		strings.TrimSpace(body.Description), verbs, id, subj.OrgID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if ct.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "custom role not found"})
		return
	}
	h.invalidate(subj.OrgID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *CustomRoles) Delete(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	// Block delete while still assigned, so we never leave dangling role_assignments.
	var assigned int
	_ = h.db.QueryRow(r.Context(),
		`SELECT count(*) FROM role_assignments ra JOIN custom_roles cr ON cr.name = ra.role
		   WHERE cr.id = $1 AND cr.org_id = $2 AND ra.scope_org_id = $2`, id, subj.OrgID).Scan(&assigned)
	if assigned > 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "custom role is still assigned to users"})
		return
	}
	ct, err := h.db.Exec(r.Context(), `DELETE FROM custom_roles WHERE id=$1 AND org_id=$2`, id, subj.OrgID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if ct.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "custom role not found"})
		return
	}
	h.invalidate(subj.OrgID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// sanitizeGrantableVerbs dedups + validates: every verb must be known AND
// user-grantable. Returns an error naming the first service-only/unknown verb —
// this is the security boundary that keeps runtime-ingest et al. out of custom roles.
func sanitizeGrantableVerbs(in []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := rbac.Verb(strings.TrimSpace(raw))
		if v == "" {
			continue
		}
		if !rbac.IsKnownVerb(v) {
			return nil, errors.New("unknown verb: " + string(v))
		}
		if !rbac.IsUserGrantableVerb(v) {
			return nil, errors.New("verb not grantable to a custom role: " + string(v))
		}
		if _, dup := seen[string(v)]; dup {
			continue
		}
		seen[string(v)] = struct{}{}
		out = append(out, string(v))
	}
	return out, nil
}

func grantableVerbNames() []string {
	out := []string{}
	for _, vi := range rbac.VerbCatalog() {
		if vi.UserGrantable {
			out = append(out, vi.Name)
		}
	}
	return out
}

var _ = pgx.ErrNoRows
