// Config-as-code HTTP API (Task B3).
//
// Endpoints (gated by manage-org — the config document carries the full org config,
// including users, role bindings, and re-sealed registry credentials):
//
//	GET  /api/v1/config/export   — stream the org's config as YAML (secrets redacted/re-sealed)
//	POST /api/v1/config/import   — apply a YAML config with an EXPLICIT ?mode=merge|replace flag
//
// Merge upserts by natural key (leaves not-present rows alone). Replace upserts AND
// deletes the org's rows not present in the document (scoped to the org). The default
// is merge: replace is destructive and must be requested explicitly.
//
// Replace caveats (the document is NOT fully authoritative for these):
//   - The importing principal's own users row is never deleted, so a replace that omits
//     the caller cannot lock the caller (or the org) out.
//   - role_bindings and org_settings are NOT delete-reconciled under replace (the
//     role_binding natural key is too coupled to remap safely; org_settings is a
//     singleton whose deletion would drop the KEK). A replace therefore cannot REVOKE a
//     stale role binding — use the direct /access-control routes for that.
//   - The identity tables (users, custom_roles, role_bindings) are written/reconciled
//     only when the caller holds manage-users (in addition to the manage-org route gate).
//
// A push-to-git connector (PushConfigToGit + pkg/gitops, roadmap B5) commits the exported
// config to a configured GitHub / Azure DevOps repo via PAT; see git_connector.go for the
// /config/git-connector API. The export endpoint still produces the same artifact for CI.
package handler

import (
	"context"
	"io"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/backup"
	"github.com/alphabravocompany/constellation/pkg/gitops"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// ConfigIO handles /api/v1/config/{export,import}.
type ConfigIO struct {
	db    *db.DB
	audit *audit.Logger
	// customRoles resolves the caller's org-defined RBAC verbs so import can enforce
	// per-table privilege separation (the identity tables require manage-users).
	customRoles *CustomRoles
}

// NewConfigIO returns a fresh handler. customRoles lets Import check whether the caller
// holds manage-users before it writes the identity tables (users/custom_roles/role_bindings).
func NewConfigIO(d *db.DB, a *audit.Logger, customRoles *CustomRoles) *ConfigIO {
	return &ConfigIO{db: d, audit: a, customRoles: customRoles}
}

// Export streams the calling org's config-as-code document as YAML. Secrets are
// redacted or re-sealed by backup.ExportConfig (user password hashes blanked,
// api_token hashes blanked, registry credentials kept AES-GCM-sealed, registry_kek
// stripped), so the body never contains cleartext credentials.
func (h *ConfigIO) Export(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	doc, err := backup.ExportConfig(r.Context(), h.db.Pool(), backup.ConfigExportOptions{
		OrgID:       subj.OrgID.String(),
		GeneratedBy: subj.Email,
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "export config: "+err.Error())
		return
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "marshal yaml: "+err.Error())
		return
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "config.export",
		TargetKind: "config",
		TargetID:   subj.OrgID.String(),
		After:      map[string]any{"tables": len(doc.Tables)},
	})
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="constellation-config.yaml"`)
	_, _ = w.Write(out)
}

// Import applies an uploaded YAML config document to the calling org. The merge-vs-
// replace selector is REQUIRED via the ?mode= query parameter; there is no implicit
// default that could silently delete rows. mode=merge upserts by natural key;
// mode=replace also deletes the org's rows not present in the document.
func (h *ConfigIO) Import(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	mode := backup.ConfigApplyMode(r.URL.Query().Get("mode"))
	if mode != backup.ConfigMerge && mode != backup.ConfigReplace {
		jsonError(w, http.StatusBadRequest, "query param mode is required and must be 'merge' or 'replace'")
		return
	}
	const maxSize = 32 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSize))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var doc backup.ConfigDocument
	if err := yaml.Unmarshal(body, &doc); err != nil {
		jsonError(w, http.StatusBadRequest, "parse yaml: "+err.Error())
		return
	}
	// The route is gated by manage-org, but the document's identity tables (users,
	// custom_roles, role_bindings) are otherwise gated by the distinct manage-users
	// verb. Resolve whether the caller holds manage-users; ApplyConfig refuses to write
	// (or delete-reconcile) those tables without it, so a manage-org-only principal can
	// never escalate via an imported role binding / admin re-enable.
	canManageUsers := h.subjectHasVerb(r, subj, rbac.VerbManageUsers)
	res, err := backup.ApplyConfig(r.Context(), h.db.Pool(), subj.OrgID.String(), &doc, mode, backup.ApplyOptions{
		SubjectEmail:   subj.Email,
		CanManageUsers: canManageUsers,
	})
	if err != nil {
		jsonError(w, http.StatusBadRequest, "apply config: "+err.Error())
		return
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "config.import",
		TargetKind: "config",
		TargetID:   subj.OrgID.String(),
		After:      map[string]any{"mode": string(mode), "tables": len(res.Tables)},
	})
	writeJSON(w, http.StatusOK, res)
}

// subjectHasVerb reports whether the subject is authorized for verb in its own org,
// honoring both role/custom-role grants AND the API-token scope envelope (a PAT must
// list the verb in its scopes too). Used by Import to decide whether the caller may
// write the identity tables.
func (h *ConfigIO) subjectHasVerb(r *http.Request, subj Subject, verb rbac.Verb) bool {
	if !subj.HasTokenScope(verb) {
		return false
	}
	var custom map[string][]rbac.Verb
	if h.customRoles != nil {
		custom = h.customRoles.VerbsForOrg(r.Context(), subj.OrgID)
	}
	return rbac.AuthorizeWithCustom(subj.Assignments, verb, rbac.Resource{OrgID: subj.OrgID}, custom) == nil
}

// PushConfigToGit exports the org's config-as-code document and commits it to the org's
// configured Git connector (roadmap B5). It replaces the former stub: it now renders the
// same YAML the /config/export endpoint produces, loads + unseals the org's connector
// (GitHub or Azure DevOps), and pushes via pkg/gitops.
//
// Returns gitops.ErrConnectorDisabled when no connector is configured/enabled, so callers
// (the /git-connector/push handler and the scheduled executor) can treat it as a no-op.
// The push outcome is recorded on the connector's last_push_* columns.
//
// TODO(matrix): a pull/reconcile path (fetch the repo's YAML and drift-detect/apply it
// against the live org config) is the B5 nice-to-have; the export+push half is wired here.
func PushConfigToGit(ctx context.Context, pool *pgxpool.Pool, orgID, generatedBy, commitMessage string) error {
	cfg, enabled, err := loadGitConnector(ctx, pool, orgID)
	if err != nil {
		return err
	}
	if !enabled {
		return gitops.ErrConnectorDisabled
	}
	doc, err := backup.ExportConfig(ctx, pool, backup.ConfigExportOptions{OrgID: orgID, GeneratedBy: generatedBy})
	if err != nil {
		return err
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if err := gitops.PushConfig(ctx, cfg, out, commitMessage); err != nil {
		recordGitPushResult(ctx, pool, orgID, "failed", err.Error())
		return err
	}
	recordGitPushResult(ctx, pool, orgID, "succeeded", "")
	return nil
}
