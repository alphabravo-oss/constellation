package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/syscfg"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// SystemConfig serves the B1 runtime-mutable system configuration:
//
//	GET   /api/v1/system/config  — returns the org's live config, SECRETS REDACTED.
//	PATCH /api/v1/system/config  — partial, validated update; bumps the revision so the
//	                               in-process accessor hot-reloads WITHOUT a restart.
//
// Both routes are gated by rbac.VerbManageSystemConfig in the router. The handler shares
// the same syscfg.Provider the consumers (shared HTTP client, syslog/SIEM sender) read
// from, so a PATCH on this replica is reflected in those consumers immediately and on
// every other replica within one reloader tick.
type SystemConfig struct {
	db       *db.DB
	audit    *audit.Logger
	provider *syscfg.Provider
}

// NewSystemConfig constructs the handler. provider must be the same instance wired into
// the consumers so a PATCH updates the live value in-process.
func NewSystemConfig(d *db.DB, a *audit.Logger, p *syscfg.Provider) *SystemConfig {
	return &SystemConfig{db: d, audit: a, provider: p}
}

// Get returns the current system config with secrets redacted.
func (h *SystemConfig) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	cfg, rev, err := syscfg.Load(r.Context(), h.db.Pool(), subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{
		"config":   cfg.Redacted(),
		"revision": rev,
		"source":   "default",
	}
	var updatedAt time.Time
	var updatedBy sql.NullString
	var updatedByEmail sql.NullString
	err = h.db.Pool().QueryRow(r.Context(), `
SELECT sc.updated_at, sc.updated_by::text, u.email
  FROM system_config sc
  LEFT JOIN users u ON u.id = sc.updated_by
 WHERE sc.org_id = $1`, subj.OrgID).Scan(&updatedAt, &updatedBy, &updatedByEmail)
	if err == nil {
		resp["source"] = "system_config"
		resp["updated_at"] = updatedAt
		if updatedBy.Valid {
			resp["updated_by"] = updatedBy.String
		}
		if updatedByEmail.Valid {
			resp["updated_by_email"] = updatedByEmail.String
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Patch applies a partial, validated update and persists it, bumping the revision. The
// request body is a JSON object containing only the keys to change; unknown keys are
// rejected. A CA bundle echoed back as the redaction marker is left unchanged so a
// GET→edit→PATCH round-trip never wipes the stored secret. The response is redacted.
func (h *SystemConfig) Patch(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var patch json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	var updatedBy *uuid.UUID
	var exists bool
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, subj.UserID).Scan(&exists); err == nil && exists {
		uid := subj.UserID
		updatedBy = &uid
	}

	// Optimistic-concurrency loop: Load the current config + revision, apply the patch
	// onto it, and Save with that revision as a precondition. If a concurrent PATCH won
	// the race (ErrRevisionConflict) we re-Load and re-apply the SAME patch onto the new
	// base so neither writer's distinct field changes are silently lost (the prior bug was
	// a non-atomic read-modify-write that clobbered the loser's fields).
	var current, merged syscfg.Config
	var rev int64
	const maxAttempts = 5
	for attempt := 0; ; attempt++ {
		var baseRev int64
		var err error
		current, baseRev, err = syscfg.Load(r.Context(), h.db.Pool(), subj.OrgID)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		merged, err = current.ApplyPatch(patch)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		rev, err = syscfg.Save(r.Context(), h.db.Pool(), subj.OrgID, merged, baseRev, updatedBy)
		if err == nil {
			break
		}
		if errors.Is(err, syscfg.ErrRevisionConflict) {
			if attempt < maxAttempts-1 {
				continue // re-Load onto the winner's value and retry the patch
			}
			jsonError(w, http.StatusConflict, "system config changed concurrently; please retry")
			return
		}
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Hot-reload: make the writing replica's accessor reflect the change immediately;
	// other replicas pick it up on the next reloader tick.
	if h.provider != nil {
		h.provider.UpdateAfterPatch(subj.OrgID, merged, rev)
	}

	if h.audit != nil {
		oid, uid := subj.OrgID, subj.UserID
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "system.config.update",
			TargetKind: "system_config", TargetID: oid.String(),
			// Redact secrets in the audit trail too.
			Before: current.Redacted(), After: merged.Redacted(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":   merged.Redacted(),
		"revision": rev,
	})
}

// RefreshScanner sets scanner_db_refresh_now to the current unix time, signaling
// connected scanners (which poll /scanner/config) to refresh their Trivy/Grype DBs
// on their next check. The "force update" affordance behind the Scanner page.
func (h *SystemConfig) RefreshScanner(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	now := time.Now().Unix()
	patch := json.RawMessage(fmt.Sprintf(`{"scanner_db_refresh_now":%d}`, now))
	var merged syscfg.Config
	var rev int64
	const maxAttempts = 5
	for attempt := 0; ; attempt++ {
		current, baseRev, err := syscfg.Load(r.Context(), h.db.Pool(), subj.OrgID)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		merged, err = current.ApplyPatch(patch)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		rev, err = syscfg.Save(r.Context(), h.db.Pool(), subj.OrgID, merged, baseRev, nil)
		if err == nil {
			break
		}
		if errors.Is(err, syscfg.ErrRevisionConflict) && attempt < maxAttempts-1 {
			continue
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if h.provider != nil {
		h.provider.UpdateAfterPatch(subj.OrgID, merged, rev)
	}
	writeJSON(w, http.StatusOK, map[string]any{"refresh_now": now, "revision": rev})
}
