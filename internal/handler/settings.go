package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// Settings serves the org_settings and user_settings JSON bags. Writes are audited
// with before/after so revealing a leaked toggle on the audit chain is straightforward.
type Settings struct {
	db    *db.DB
	audit *audit.Logger
}

// NewSettings constructs a Settings handler.
func NewSettings(d *db.DB, a *audit.Logger) *Settings {
	return &Settings{db: d, audit: a}
}

// GetOrg returns the org settings JSON. If absent, returns an empty object.
func (h *Settings) GetOrg(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var raw json.RawMessage
	err := h.db.Pool().QueryRow(r.Context(),
		`SELECT settings FROM org_settings WHERE org_id = $1`, subj.OrgID).Scan(&raw)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": raw})
}

// PatchOrg merges the request body into the org settings bag and audits the change.
// Body must be a JSON object; keys present in the body overwrite existing keys (top-level
// shallow merge), and a key with value `null` deletes that key.
func (h *Settings) PatchOrg(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var patch map[string]any
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var current map[string]any
	var rawCurrent json.RawMessage
	if err := tx.QueryRow(r.Context(),
		`SELECT settings FROM org_settings WHERE org_id = $1 FOR UPDATE`, subj.OrgID).Scan(&rawCurrent); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		current = map[string]any{}
	} else {
		_ = json.Unmarshal(rawCurrent, &current)
		if current == nil {
			current = map[string]any{}
		}
	}
	before := copyMap(current)
	for k, v := range patch {
		if v == nil {
			delete(current, k)
			continue
		}
		current[k] = v
	}
	merged, _ := json.Marshal(current)
	// Resolve updated_by to NULL when the subject's user_id doesn't exist (some
	// test paths use synthetic subjects without a real user row).
	var updatedBy any
	var exists bool
	if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, subj.UserID).Scan(&exists); err == nil && exists {
		updatedBy = subj.UserID
	}
	if _, err := tx.Exec(r.Context(), `
INSERT INTO org_settings (org_id, settings, updated_by) VALUES ($1, $2::jsonb, $3)
ON CONFLICT (org_id) DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
		subj.OrgID, merged, updatedBy); err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("upsert: %v", err))
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "settings.org.update",
			TargetKind: "org_settings", TargetID: oid.String(),
			Before: before, After: current,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": current})
}

// GetUser returns the calling user's settings bag.
func (h *Settings) GetUser(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var raw json.RawMessage
	err := h.db.Pool().QueryRow(r.Context(),
		`SELECT settings FROM user_settings WHERE user_id = $1`, subj.UserID).Scan(&raw)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": raw})
}

// PatchUser merges the request body into user_settings. Same merge semantics as PatchOrg.
func (h *Settings) PatchUser(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var patch map[string]any
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var current map[string]any
	var rawCurrent json.RawMessage
	if err := tx.QueryRow(r.Context(),
		`SELECT settings FROM user_settings WHERE user_id = $1 FOR UPDATE`, subj.UserID).Scan(&rawCurrent); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		current = map[string]any{}
	} else {
		_ = json.Unmarshal(rawCurrent, &current)
		if current == nil {
			current = map[string]any{}
		}
	}
	before := copyMap(current)
	for k, v := range patch {
		if v == nil {
			delete(current, k)
			continue
		}
		current[k] = v
	}
	merged, _ := json.Marshal(current)
	if _, err := tx.Exec(r.Context(), `
INSERT INTO user_settings (user_id, settings) VALUES ($1, $2::jsonb)
ON CONFLICT (user_id) DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()`,
		subj.UserID, merged); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "settings.user.update",
			TargetKind: "user_settings", TargetID: uid.String(),
			Before: before, After: current,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": current})
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
