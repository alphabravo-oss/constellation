// Exporter — builds a signed tarball for one org.
//
// Pattern: for each table in OrderedTables, run the table's scoping query (most: `WHERE
// org_id = $1`), encode each row as canonical JSON, write into a per-table .jsonl file
// inside a streaming tar/gzip. Hash each .jsonl as we go so the manifest pins exactly
// the bytes that went into the archive. Last, write manifest.json + signature.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ExportOptions configures Export.
type ExportOptions struct {
	OrgID         string
	OrgName       string
	Out           io.Writer
	GeneratedBy   string
	SourceInstance string
	Sign          SignerOptions
	// AuditRecentWindow caps the audit_events_recent export at the most recent N. Default
	// 30 days. Set to 0 to disable the audit export entirely.
	AuditRecentWindow time.Duration
}

// ExportResult summarizes what was written.
type ExportResult struct {
	Manifest Manifest
	Bytes    int64
	SignerIdentity string
	SignMode SignMode
}

// Export streams a backup tarball for the org identified by opts.OrgID into opts.Out.
// Returns the manifest + total bytes written. Caller is responsible for fsync'ing if
// opts.Out is a file.
func Export(ctx context.Context, pool *pgxpool.Pool, opts ExportOptions) (*ExportResult, error) {
	if opts.OrgID == "" {
		return nil, errors.New("export: OrgID required")
	}
	if opts.AuditRecentWindow == 0 {
		opts.AuditRecentWindow = 30 * 24 * time.Hour
	}

	// Resolve org name if not given.
	if opts.OrgName == "" {
		row := pool.QueryRow(ctx, `SELECT name FROM orgs WHERE id=$1`, opts.OrgID)
		if err := row.Scan(&opts.OrgName); err != nil {
			return nil, fmt.Errorf("resolve org name: %w", err)
		}
	}

	// Counting writer for total bytes.
	cw := &countingWriter{w: opts.Out}
	gz := gzip.NewWriter(cw)
	tw := tar.NewWriter(gz)

	manifest := Manifest{
		FormatVersion:  FormatVersion,
		OrgID:          opts.OrgID,
		OrgName:        opts.OrgName,
		GeneratedAt:    time.Now().UTC(),
		GeneratedBy:    opts.GeneratedBy,
		SourceInstance: opts.SourceInstance,
	}

	for _, tbl := range OrderedTables {
		entry, body, err := exportOne(ctx, pool, tbl, opts.OrgID, opts.AuditRecentWindow)
		if err != nil {
			if IsOptionalTable(tbl) && isMissingTable(err) {
				// Tolerated; record nothing.
				continue
			}
			return nil, fmt.Errorf("export %s: %w", tbl, err)
		}
		// Write the .jsonl into the tar.
		hdr := &tar.Header{
			Name:    "tables/" + tbl + ".jsonl",
			Mode:    0o644,
			Size:    int64(len(body)),
			ModTime: manifest.GeneratedAt,
			Format:  tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("tar header %s: %w", tbl, err)
		}
		if _, err := tw.Write(body); err != nil {
			return nil, fmt.Errorf("tar body %s: %w", tbl, err)
		}
		manifest.Tables = append(manifest.Tables, entry)
	}

	rootHash, err := ComputeRootHash(manifest.Tables)
	if err != nil {
		return nil, fmt.Errorf("root hash: %w", err)
	}
	manifest.RootHash = rootHash

	// Now sign the manifest (signature attests to RootHash + format version + tables).
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	sig, cert, identity, err := Sign(manifestBytes, opts.Sign)
	if err != nil {
		return nil, fmt.Errorf("sign manifest: %w", err)
	}
	if identity != "" {
		// Re-marshal so the identity is captured in the body too; the on-the-wire signature
		// covers the version that includes signer_identity so verifiers see one canonical doc.
		manifest.SignerIdentity = identity
		manifestBytes, _ = json.MarshalIndent(manifest, "", "  ")
		// Re-sign to bind identity into the signed bytes.
		sig, cert, identity, err = Sign(manifestBytes, opts.Sign)
		if err != nil {
			return nil, fmt.Errorf("re-sign manifest: %w", err)
		}
	}

	// Write manifest.json, manifest.json.sig, manifest.json.cert.
	if err := writeTarFile(tw, "manifest.json", manifest.GeneratedAt, manifestBytes); err != nil {
		return nil, err
	}
	if len(sig) > 0 {
		if err := writeTarFile(tw, "manifest.json.sig", manifest.GeneratedAt, sig); err != nil {
			return nil, err
		}
	}
	if len(cert) > 0 {
		if err := writeTarFile(tw, "manifest.json.cert", manifest.GeneratedAt, cert); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("close gzip: %w", err)
	}

	return &ExportResult{
		Manifest:       manifest,
		Bytes:          cw.n,
		SignerIdentity: identity,
		SignMode:       opts.Sign.Mode,
	}, nil
}

// exportOne returns a TableEntry and the .jsonl bytes for a single table. The bytes are
// returned in-memory because (a) per-table size is tractable for operator data and (b) we
// need the digest before we can write the tar header.
func exportOne(ctx context.Context, pool *pgxpool.Pool, table, orgID string, auditWindow time.Duration) (TableEntry, []byte, error) {
	q, args := scopeQuery(table, orgID, auditWindow)
	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		return TableEntry{}, nil, err
	}
	defer rows.Close()

	fd := rows.FieldDescriptions()
	colNames := make([]string, len(fd))
	for i, f := range fd {
		colNames[i] = string(f.Name)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)

	var n int64
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return TableEntry{}, nil, err
		}
		// Build a deterministic map (column -> value).
		obj := make(map[string]any, len(colNames))
		for i, col := range colNames {
			obj[col] = normalizeValue(vals[i])
		}
		// Apply per-table redactions (e.g. receivers.secret_key).
		applyRedactions(table, obj)
		if err := enc.Encode(obj); err != nil {
			return TableEntry{}, nil, err
		}
		n++
	}
	if rows.Err() != nil {
		return TableEntry{}, nil, rows.Err()
	}

	body := buf.Bytes()
	sum := sha256.Sum256(body)
	return TableEntry{
		Name:   table,
		Rows:   n,
		SHA256: hex.EncodeToString(sum[:]),
		Bytes:  int64(len(body)),
	}, body, nil
}

// scopeQuery returns the SELECT + args for one table scoped to a single org. For tables
// that don't carry org_id (orgs itself) the scoping is on id; for audit_events the
// caller-supplied window is honored.
func scopeQuery(table, orgID string, auditWindow time.Duration) (string, []any) {
	switch table {
	case "orgs":
		return `SELECT * FROM orgs WHERE id=$1`, []any{orgID}
	case "federation_state":
		return `SELECT * FROM federation_state WHERE org_id=$1`, []any{orgID}
	case "fed_members":
		return `SELECT * FROM fed_members WHERE org_id=$1`, []any{orgID}
	case "audit_events_recent":
		since := time.Now().Add(-auditWindow)
		return `SELECT id, org_id, actor_id, actor_ip::text AS actor_ip, action, target_kind, target_id, before, after, prev_hash, chain_hash, request_id, at FROM audit_events WHERE org_id=$1 AND at >= $2 ORDER BY id ASC`, []any{orgID, since}
	case "compliance_schedules":
		// Optional table (Wave N8). If it doesn't exist, exportOne treats the missing-table
		// error as non-fatal via IsOptionalTable + isMissingTable.
		return `SELECT * FROM compliance_schedules WHERE org_id=$1`, []any{orgID}
	case "role_bindings":
		// Carry subject_email alongside subject_id so the restorer can remap user
		// bindings to the destination user by email (source UUIDs are not portable).
		// LEFT JOIN so service-account subjects (no users row) still export.
		return `SELECT rb.*, u.email AS subject_email
		          FROM role_bindings rb
		          LEFT JOIN users u ON u.id::text = rb.subject_id
		         WHERE rb.org_id=$1`, []any{orgID}
	case "api_tokens":
		// api_tokens has no org_id; it scopes through users.user_id. We export the
		// columns needed for an inventory (name, lifecycle timestamps, scopes) but
		// NEVER token_hash — tokens are not restorable by design (see applyRedactions,
		// which blanks token_hash belt-and-suspenders even though we don't select it).
		return `SELECT t.id, t.user_id, u.email AS user_email, t.name,
		               '' AS token_hash, t.last_used_at, t.expires_at,
		               t.revoked_at, t.created_at, t.service_account_id,
		               t.scopes, t.status
		          FROM api_tokens t JOIN users u ON u.id = t.user_id
		         WHERE u.org_id=$1 ORDER BY t.created_at ASC`, []any{orgID}
	default:
		return fmt.Sprintf(`SELECT * FROM %s WHERE org_id=$1`, table), []any{orgID}
	}
}

// applyRedactions removes per-table secrets that the operator wants rotated post-restore
// rather than ported verbatim. The redacted columns are set to "" (not removed) so the
// restorer can still UPSERT against existing schemas without column-count mismatches.
func applyRedactions(table string, obj map[string]any) {
	switch table {
	case "receivers":
		if _, ok := obj["secret_key"]; ok {
			obj["secret_key"] = ""
		}
	case "users":
		// Password hashes never leave the instance. We blank rather than drop so the
		// restorer can UPSERT against the same column set; a restored user is OIDC- or
		// reset-flow-only until an operator sets a new password.
		if _, ok := obj["password_hash"]; ok {
			obj["password_hash"] = ""
		}
	case "api_tokens":
		// Tokens are not restorable by design: only metadata is exported. Blank the
		// hash belt-and-suspenders (the scope query already selects '' for it).
		if _, ok := obj["token_hash"]; ok {
			obj["token_hash"] = ""
		}
	case "registries":
		// auth_secret is AES-GCM ciphertext (BYTEA). normalizeValue renders BYTEA as a
		// hex string, so the credential travels RE-SEALED, never in cleartext. We leave
		// it intact so a restore on an instance sharing the KEK can decrypt it.
		// (No action needed; documented here so the redaction policy is explicit.)
	case "org_settings":
		// org_settings.settings is a free-form jsonb bag the UI/integrations write
		// arbitrary keys into (integration overrides, per migration 020). It can hold
		// the install-wide registry KEK ("registry_kek", see pkg/registry/secrets) and
		// operator-supplied integration secrets. Strip registry_kek explicitly, plus any
		// key that looks secret-bearing (token/secret/password/api_key/...), so a config
		// document never carries cleartext credentials out of the settings bag.
		redactSettingsSecrets(obj, "settings")
	}
}

// secretSettingKeyFragments are case-insensitive substrings that mark a settings key as
// secret-bearing. A key containing any of these is stripped from an exported settings
// bag. This is a denylist (the bag is open-ended), so operators should still avoid
// stashing secrets under innocuous key names; the registry KEK is also stripped by its
// exact key below as a belt-and-suspenders guarantee.
var secretSettingKeyFragments = []string{
	"secret", "password", "passwd", "token", "api_key", "apikey",
	"private_key", "privatekey", "credential", "kek", "client_secret",
}

// redactSettingsSecrets strips registry_kek and any secret-looking key from the jsonb
// column `col` of obj when it decoded to a JSON object. The column is left as valid JSON
// so the restorer can still UPSERT it.
func redactSettingsSecrets(obj map[string]any, col string) {
	raw, ok := obj[col]
	if !ok {
		return
	}
	var m map[string]any
	switch v := raw.(type) {
	case json.RawMessage:
		if json.Unmarshal(v, &m) != nil {
			return
		}
	case map[string]any:
		m = v
	default:
		return
	}
	changed := false
	for k := range m {
		lk := strings.ToLower(k)
		if k == "registry_kek" || containsAnyFragment(lk, secretSettingKeyFragments) {
			delete(m, k)
			changed = true
		}
	}
	if changed {
		if b, err := json.Marshal(m); err == nil {
			obj[col] = json.RawMessage(b)
		}
	}
}

// containsAnyFragment reports whether s contains any of the fragments.
func containsAnyFragment(s string, fragments []string) bool {
	for _, f := range fragments {
		if strings.Contains(s, f) {
			return true
		}
	}
	return false
}

// normalizeValue coerces pgx-returned values into JSON-friendly types.
func normalizeValue(v any) any {
	switch x := v.(type) {
	case []byte:
		// jsonb columns come back as []byte. Try to parse so the JSON doc isn't a
		// base64-encoded blob; fall back to a hex string if it's not valid JSON.
		var raw json.RawMessage
		if err := json.Unmarshal(x, &raw); err == nil {
			return raw
		}
		return fmt.Sprintf("%x", x)
	case [16]byte:
		// pgx returns uuid columns as [16]byte. Render as canonical UUID string so a
		// restore on a different instance can FK-look-up by source UUID without having to
		// decode a byte array. (The restorer treats UUID strings as opaque keys when
		// mapping cluster_id -> dest cluster id.)
		return fmt.Sprintf("%x-%x-%x-%x-%x", x[0:4], x[4:6], x[6:8], x[8:10], x[10:16])
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	default:
		return v
	}
}

// writeTarFile writes name -> body into tw.
func writeTarFile(tw *tar.Writer, name string, mtime time.Time, body []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    int64(len(body)),
		ModTime: mtime,
		Format:  tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("tar header %s: %w", name, err)
	}
	if _, err := tw.Write(body); err != nil {
		return fmt.Errorf("tar body %s: %w", name, err)
	}
	return nil
}

// isMissingTable returns true for pg's "relation does not exist" SQLSTATE 42P01, which
// the exporter tolerates for tables flagged IsOptionalTable.
func isMissingTable(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "42P01"
	}
	// String-y fallback for wrapped errors.
	if err != nil && containsAny(err.Error(), "does not exist", "42P01") {
		return true
	}
	return false
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// countingWriter wraps a writer and tracks bytes written.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// ExportToFile is a convenience that writes a backup to a local path. Closes the file
// on return (via os.File.Close()) and returns the result.
func ExportToFile(ctx context.Context, pool *pgxpool.Pool, path string, opts ExportOptions) (*ExportResult, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	opts.Out = f
	res, err := Export(ctx, pool, opts)
	if cerr := f.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return res, err
}
