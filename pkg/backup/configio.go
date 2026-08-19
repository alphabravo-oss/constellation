// Config-as-code export/import.
//
// Where Export/Restore produce a signed tar.gz artifact, ExportConfig / ApplyConfig
// produce and consume a plain structured document (rendered as YAML by the HTTP
// handler) so an operator can keep their org's configuration in git and re-apply it
// with explicit merge-vs-replace semantics.
//
// The same per-table scoping and redaction logic the tarball exporter uses applies
// here: secrets are redacted or re-sealed exactly as in applyRedactions, so a config
// document never carries cleartext credentials. Tables whose contents are operational
// telemetry rather than configuration (audit events, federation runtime state) are
// excluded from the config document — they belong in the backup artifact, not in a
// hand-editable config file.
package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// jsonlEncode renders rows as the newline-delimited JSON the restore handlers parse
// via rowsFromJSONL, so ApplyConfig can reuse the tarball restore path verbatim.
func jsonlEncode(rows []map[string]any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, r := range rows {
		_ = enc.Encode(r)
	}
	return buf.Bytes()
}

// ConfigTables is the config-as-code subset of OrderedTables: the durable, operator-
// authored configuration. It deliberately omits inventory/telemetry tables
// (deployments, assets, audit_events_recent, federation_*) which are not config.
var ConfigTables = []string{
	"users",
	"custom_roles",
	"role_bindings",
	"org_settings",
	"policies",
	"groups",
	"vuln_profiles",
	"response_rules_v2",
	"response_rules", // E1 declarative response-rule engine (ConstellationResponseRule CRD source)
	"receivers",
	"registries",
	"waf_groups",
	"runtime_dlp_rules", // NET-BACKUP-44: live enforced DLP + L7/WAF rules (operator-authored config)
	"custom_frameworks",
	"api_tokens", // metadata only (token_hash redacted) — inventory of issued tokens
}

// ConfigDocument is the structured, deterministic config-as-code payload. Tables are
// kept as an ordered slice (not a map) so the YAML render is stable across exports.
type ConfigDocument struct {
	FormatVersion string             `json:"format_version" yaml:"format_version"`
	OrgID         string             `json:"org_id" yaml:"org_id"`
	OrgName       string             `json:"org_name" yaml:"org_name"`
	GeneratedAt   time.Time          `json:"generated_at" yaml:"generated_at"`
	GeneratedBy   string             `json:"generated_by,omitempty" yaml:"generated_by,omitempty"`
	Tables        []ConfigTableBlock `json:"tables" yaml:"tables"`
}

// ConfigTableBlock is one table's rows in the config document.
type ConfigTableBlock struct {
	Name string           `json:"name" yaml:"name"`
	Rows []map[string]any `json:"rows" yaml:"rows"`
}

// ConfigExportOptions configures ExportConfig.
type ConfigExportOptions struct {
	OrgID       string
	OrgName     string
	GeneratedBy string
}

// ExportConfig builds a ConfigDocument for one org. It reuses the tarball exporter's
// per-table scope query and redaction logic, so secrets are redacted / re-sealed
// identically (user password hashes blanked, api_token hashes blanked, registry
// credentials kept AES-GCM-sealed, org_settings registry_kek stripped).
func ExportConfig(ctx context.Context, pool *pgxpool.Pool, opts ConfigExportOptions) (*ConfigDocument, error) {
	if opts.OrgID == "" {
		return nil, fmt.Errorf("export config: OrgID required")
	}
	if opts.OrgName == "" {
		if err := pool.QueryRow(ctx, `SELECT name FROM orgs WHERE id=$1`, opts.OrgID).Scan(&opts.OrgName); err != nil {
			return nil, fmt.Errorf("resolve org name: %w", err)
		}
	}
	doc := &ConfigDocument{
		FormatVersion: FormatVersion,
		OrgID:         opts.OrgID,
		OrgName:       opts.OrgName,
		GeneratedAt:   time.Now().UTC(),
		GeneratedBy:   opts.GeneratedBy,
	}
	for _, tbl := range ConfigTables {
		rows, err := exportConfigRows(ctx, pool, tbl, opts.OrgID)
		if err != nil {
			if IsOptionalTable(tbl) && isMissingTable(err) {
				continue
			}
			return nil, fmt.Errorf("export %s: %w", tbl, err)
		}
		doc.Tables = append(doc.Tables, ConfigTableBlock{Name: tbl, Rows: rows})
	}
	return doc, nil
}

// exportConfigRows runs the table's scope query and returns redacted rows as plain
// maps (deterministic value normalization, secrets stripped/re-sealed).
func exportConfigRows(ctx context.Context, pool *pgxpool.Pool, table, orgID string) ([]map[string]any, error) {
	q, args := scopeQuery(table, orgID, 0)
	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	fd := rows.FieldDescriptions()
	cols := make([]string, len(fd))
	for i, f := range fd {
		cols[i] = string(f.Name)
	}
	var out []map[string]any
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, err
		}
		obj := make(map[string]any, len(cols))
		for i, c := range cols {
			obj[c] = normalizeValue(vals[i])
		}
		applyRedactions(table, obj)
		out = append(out, obj)
	}
	return out, rows.Err()
}

// ConfigApplyMode is the explicit merge-vs-replace selector for ApplyConfig.
type ConfigApplyMode string

const (
	// ConfigMerge upserts rows by natural key, leaving destination rows that are not
	// present in the document untouched.
	ConfigMerge ConfigApplyMode = "merge"
	// ConfigReplace upserts present rows AND deletes destination rows not present in
	// the document (scoped to the org), making the document authoritative.
	ConfigReplace ConfigApplyMode = "replace"
)

// ConfigApplyResult summarizes an ApplyConfig run.
type ConfigApplyResult struct {
	Mode   ConfigApplyMode     `json:"mode"`
	OrgID  string              `json:"org_id"`
	Tables []TableRestoreStats `json:"tables"`
}

// ApplyOptions carries the authorization context the importing handler resolved for
// the calling subject, so ApplyConfig can enforce per-table privilege separation and
// avoid the importer locking itself out.
type ApplyOptions struct {
	// SubjectEmail is the importing principal's email. Under replace, the principal's
	// own users row is never delete-reconciled, so an import that omits the caller can
	// never delete the caller (and thus the org) out of existence.
	SubjectEmail string
	// CanManageUsers reports whether the caller holds rbac.VerbManageUsers. The
	// identity-bearing tables (users, custom_roles, role_bindings) are otherwise gated
	// by that distinct verb on their direct routes; without it ApplyConfig refuses to
	// write them (and skips their replace-delete) so a manage-org-only principal can
	// never escalate privileges by importing a role binding / re-enabling an admin.
	CanManageUsers bool
}

// identityTables are the tables whose direct CRUD routes are gated by
// rbac.VerbManageUsers (not merely VerbManageOrg). ApplyConfig refuses to write or
// delete-reconcile these unless the caller holds VerbManageUsers, mirroring the verb
// that gates server.go's /access-control, /custom-roles, and /users routes.
var identityTables = map[string]bool{
	"users":         true,
	"custom_roles":  true,
	"role_bindings": true,
}

// ApplyConfig applies a ConfigDocument to the destination org with explicit merge or
// replace semantics. Merge upserts by natural key. Replace additionally deletes the
// org's rows whose natural key is absent from the document (scoped to the org so it
// can never touch another tenant's data).
//
// The destination org is identified by orgID directly (not by name remap): config-as-
// code re-applies to a known org, unlike a cross-instance backup restore. api_tokens
// are metadata-only and never written; role_bindings and the secret-bearing tables go
// through the same restore handlers the tarball path uses, so redaction/sealing is
// consistent.
//
// The entire apply runs inside a single pgx transaction: a failure on any table rolls
// back every prior table AND every replace-delete, so a partial import is never
// observable and a failed import leaves the org untouched. Identity tables (users,
// custom_roles, role_bindings) are written only when opts.CanManageUsers is set.
func ApplyConfig(ctx context.Context, pool *pgxpool.Pool, orgID string, doc *ConfigDocument, mode ConfigApplyMode, opts ApplyOptions) (*ConfigApplyResult, error) {
	if mode != ConfigMerge && mode != ConfigReplace {
		return nil, fmt.Errorf("apply config: mode must be %q or %q, got %q", ConfigMerge, ConfigReplace, mode)
	}
	res := &ConfigApplyResult{Mode: mode, OrgID: orgID}
	clusterMap := map[string]string{}

	// Build a quick lookup of table -> rows from the document.
	byTable := map[string][]map[string]any{}
	for _, b := range doc.Tables {
		byTable[b.Name] = b.Rows
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return res, fmt.Errorf("begin import tx: %w", err)
	}
	// Rollback is a no-op after a successful Commit; on any early return it undoes
	// every table written and every replace-delete performed so far.
	defer func() { _ = tx.Rollback(ctx) }()

	for _, tbl := range ConfigTables {
		// Identity tables require the manage-users verb. Without it the import neither
		// writes nor delete-reconciles them, so a manage-org-only principal can't grant
		// itself a role binding, re-enable a disabled admin, or rebind an admin identity.
		if identityTables[tbl] && !opts.CanManageUsers {
			continue
		}
		rows := byTable[tbl]
		if mode == ConfigReplace {
			if err := deleteAbsentRows(ctx, tx, tbl, orgID, opts.SubjectEmail, rows); err != nil {
				return res, fmt.Errorf("%s replace-delete: %w", tbl, err)
			}
		}
		body := jsonlEncode(rows)
		var stats TableRestoreStats
		switch tbl {
		case "users":
			stats, err = restoreUsers(ctx, tx, body, orgID, ConflictOverwrite)
		case "org_settings":
			stats, err = restoreOrgSettings(ctx, tx, body, orgID, ConflictOverwrite)
		case "role_bindings":
			stats, err = restoreRoleBindings(ctx, tx, body, orgID, ConflictOverwrite)
		case "registries":
			stats, err = restoreRegistries(ctx, tx, body, orgID, ConflictOverwrite)
		case "api_tokens":
			// metadata only — never written.
			stats = TableRestoreStats{}
		default:
			stats, err = restoreOrgNameKeyed(ctx, tx, tbl, body, orgID, ConflictOverwrite, clusterMap)
		}
		if err != nil {
			return res, fmt.Errorf("%s: %w", tbl, err)
		}
		stats.Name = tbl
		res.Tables = append(res.Tables, stats)
	}
	if err := tx.Commit(ctx); err != nil {
		return res, fmt.Errorf("commit import tx: %w", err)
	}
	return res, nil
}

// deleteAbsentRows removes the org's rows in `table` whose natural key is not present
// in `keep`. Scoped to the org so a replace can never delete another tenant's rows.
// api_tokens is never deleted (metadata-only / not managed by config). The natural key
// per table mirrors the restore handlers' conflict targets. The importing subject's own
// users row (subjEmail) is always preserved so a replace can never lock the caller (and
// thus the org) out by omitting the caller from the document.
func deleteAbsentRows(ctx context.Context, pool Querier, table, orgID, subjEmail string, keep []map[string]any) error {
	switch table {
	case "users":
		present := stringSet(keep, "email")
		// Never delete the importing principal: keep their row even if absent from the doc.
		if subjEmail != "" {
			present[subjEmail] = true
		}
		return deleteByKey(ctx, pool, `SELECT email FROM users WHERE org_id=$1`,
			`DELETE FROM users WHERE org_id=$1 AND email=$2`, orgID, present)
	case "org_settings":
		// Singleton row; replace keeps it (deleting org_settings would drop the KEK).
		return nil
	case "role_bindings":
		// Composite natural key (subject_id, role_id). Keep set is by destination
		// (email-or-id, role_id); too coupled to remap here safely — skip delete-not-present
		// for role_bindings under replace and let upsert reconcile additions/changes.
		return nil
	case "api_tokens":
		return nil
	default:
		present := stringSet(keep, "name")
		return deleteByKey(ctx, pool,
			fmt.Sprintf(`SELECT name FROM %s WHERE org_id=$1`, table),
			fmt.Sprintf(`DELETE FROM %s WHERE org_id=$1 AND name=$2`, table),
			orgID, present)
	}
}

// deleteByKey lists the org's existing keys via listSQL and deletes (via delSQL) those
// not in present.
func deleteByKey(ctx context.Context, pool Querier, listSQL, delSQL, orgID string, present map[string]bool) error {
	rows, err := pool.Query(ctx, listSQL, orgID)
	if err != nil {
		return err
	}
	var existing []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return err
		}
		existing = append(existing, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, k := range existing {
		if present[k] {
			continue
		}
		if _, err := pool.Exec(ctx, delSQL, orgID, k); err != nil {
			return err
		}
	}
	return nil
}

// stringSet collects the non-empty string values of `field` across rows into a set.
func stringSet(rows []map[string]any, field string) map[string]bool {
	out := map[string]bool{}
	for _, r := range rows {
		if s, ok := r[field].(string); ok && s != "" {
			out[s] = true
		}
	}
	return out
}
