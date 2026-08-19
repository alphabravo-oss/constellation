// Package backup implements Constellation's full-org backup / restore artifact format.
//
// The artifact is a gzip-compressed tar containing one JSON-lines export per relevant
// operator table, plus a manifest.json that pins the format version, the org identity,
// per-table row counts, and a sha256 over the concatenated table-export digests. The
// manifest is signed with cosign (either keyless via Sigstore Fulcio or with a static
// ed25519 key in cosign sign-blob format) so a restore on a foreign instance can prove
// provenance before applying any rows.
//
// Format version: "constellation-orgbackup/v1".
//
// Layout:
//
//	manifest.json
//	manifest.json.sig          (cosign sign-blob signature; base64)
//	manifest.json.cert         (Fulcio cert PEM; empty for static-key mode)
//	tables/<table>.jsonl       (newline-delimited JSON; one row per line; key sort)
//
// Per-table digests are sha256(table.jsonl), recorded in the manifest's Tables[].SHA256.
// The manifest's RootHash is sha256 over JSON-encoded (table_name + sha256) pairs in the
// declared order — a small Merkle-ish accumulator so a single signature covers everything.
//
// Tables are exported in dependency order (orgs first, then clusters/projects, then
// per-org tables, then audit-30d at the end). Restore replays in the same order so foreign
// keys are honored without deferral.
package backup

import (
	"encoding/json"
	"sort"
	"time"
)

// FormatVersion is the on-disk schema identifier. Bump on any non-backward-compatible
// change to the file layout, manifest fields, or table exports. Restore refuses to
// process unfamiliar versions unless --allow-unverified is passed.
const FormatVersion = "constellation-orgbackup/v1"

// Manifest is the top-level JSON document inside every backup tarball.
type Manifest struct {
	// FormatVersion pins the artifact layout. Always FormatVersion above for new writes.
	FormatVersion string `json:"format_version"`
	// OrgID is the source org's UUID. UPSERT on restore is by (OrgName) so cross-instance
	// restore works even if UUIDs differ; OrgID is recorded for audit-trail purposes.
	OrgID string `json:"org_id"`
	OrgName string `json:"org_name"`
	GeneratedAt time.Time `json:"generated_at"`
	GeneratedBy string `json:"generated_by,omitempty"` // best-effort email of the user that kicked the backup
	SourceInstance string `json:"source_instance,omitempty"` // best-effort hostname for ops triage
	Tables []TableEntry `json:"tables"`
	RootHash string `json:"root_hash"` // sha256 over JSON of [{table, sha256, rows}, ...]
	// SignerIdentity is set after signing. "keyless:<fulcio-subject>" or "key:<sha256-pubkey>".
	SignerIdentity string `json:"signer_identity,omitempty"`
}

// TableEntry summarizes one exported table.
type TableEntry struct {
	Name string `json:"name"` // e.g. "clusters"
	Rows int64 `json:"rows"`
	SHA256 string `json:"sha256"` // hex of sha256(table.jsonl bytes)
	Bytes int64 `json:"bytes"`
}

// ComputeRootHash returns the manifest's RootHash given its Tables list. Stable: re-sorts
// the tables by Name before hashing so the hash is independent of slice order, and a
// future reorder of the exporter's table list does not invalidate signatures.
func ComputeRootHash(tables []TableEntry) (string, error) {
	out := make([]TableEntry, len(tables))
	copy(out, tables)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	// JSON-encode each entry into a stable shape (only the fields that affect identity).
	type ent struct {
		Name string `json:"name"`
		SHA256 string `json:"sha256"`
		Rows int64 `json:"rows"`
	}
	items := make([]ent, len(out))
	for i, t := range out {
		items[i] = ent{Name: t.Name, SHA256: t.SHA256, Rows: t.Rows}
	}
	buf, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	return sha256Hex(buf), nil
}

// OrderedTables is the canonical dependency-ordered list of tables. Exporter writes in
// this order; Restorer reads and applies in this order. Tables further down may FK into
// tables earlier up.
//
// Excluded by design (per spec): findings, network_flows, events, cve_records.
// "Optional" tables that may not be present in this DB version are tolerated by the
// exporter (it logs and skips) and by the restorer (missing files are not an error).
var OrderedTables = []string{
	"orgs",                  // 1
	"users",                 // 2 (FK -> orgs; password_hash REDACTED at export time)
	"custom_roles",          // 3 (FK -> orgs; org-defined RBAC verb bundles)
	"role_bindings",         // 4 (FK -> orgs, users; subject_id/role_id)
	"org_settings",          // 5 (FK -> orgs; registry_kek REDACTED at export time)
	"clusters",              // 6 (FK -> orgs)
	"deployments",           // 7 (FK -> orgs, clusters)
	"assets",                // 8 (FK -> orgs, clusters)
	"policies",              // 9 (FK -> orgs, clusters)
	"groups",                // 10 (FK -> orgs, clusters)
	"vuln_profiles",         // 11
	"response_rules_v2",     // 12
	"response_rules",        // 12b E1 declarative response-rule engine (ConstellationResponseRule CRD)
	"receivers",             // 13 (secret_key REDACTED at export time)
	"registries",            // 14 (auth_secret stays AES-GCM SEALED; hex-encoded, never cleartext)
	"waf_groups",            // 15
	"runtime_dlp_rules",     // 16 (NET-BACKUP-44: the LIVE enforced DLP + L7/WAF rule store —
	//      the single authoritative table after waf_groups CRUD (WS-G G1) and dlp_sensors
	//      (P0-01) were removed; FK org_id+cluster_id so it restores after clusters)
	"image_acceptances",     // 17
	"custom_frameworks",     // 18
	"api_tokens",            // 19 (optional; token_hash EXCLUDED — metadata only, not restorable)
	"compliance_schedules",  // 20 (optional, N8)
	"federation_state",      // 21
	"fed_members",           // 22
	"audit_events_recent",   // 23 (last 30d only; full archive belongs to audit-archiver)
}

// IsOptionalTable returns true for tables whose absence (missing table in source DB or
// missing file in tarball) is not an error.
func IsOptionalTable(name string) bool {
	switch name {
	case "compliance_schedules", "custom_roles", "api_tokens":
		return true
	}
	return false
}
