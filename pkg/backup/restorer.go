// Restorer — applies a signed backup tarball to a Postgres instance.
//
// Algorithm:
//   1. Read the entire tar/gz into memory (operator data is small; convenience >
//      streaming complexity).
//   2. Verify the cosign signature over manifest.json. Abort unless --allow-unverified.
//   3. Recompute each table's sha256 from the tar bytes and confirm against the manifest.
//   4. For each table in OrderedTables, UPSERT rows in dependency order. Natural-key
//      conflict targets per table; FK columns (org_id, cluster_id, project_id) are
//      remapped to the destination's org row by name.
//   5. Audit-log a 'backup.restore' event with per-table counts.
//
// Conflict policy:
//   - "skip" (default): if a row already exists by natural key, skip it.
//   - "overwrite":      ON CONFLICT DO UPDATE SET (all-non-PK-columns) = (excluded).
//
// Tables that present a (org_id, name) UNIQUE constraint use that as the conflict target.
// Tables with composite keys (e.g. deployments) use the matching unique index.
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
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is the subset of pgx the per-table restore handlers need. Both
// *pgxpool.Pool and pgx.Tx satisfy it, so the same handlers serve the tarball
// restore (which runs per-table on the pool) and ApplyConfig (which runs the
// whole apply inside a single pgx.Tx for atomicity).
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ConflictPolicy enumerates how the restorer handles a natural-key conflict.
type ConflictPolicy string

const (
	ConflictSkip      ConflictPolicy = "skip"
	ConflictOverwrite ConflictPolicy = "overwrite"
)

// RestoreOptions configures Restore.
type RestoreOptions struct {
	In              io.Reader
	Verify          VerifierOptions
	AllowUnverified bool
	OnConflict      ConflictPolicy

	// DestOrgID pins the destination org to the authenticated caller's org. When set
	// (the multi-tenant HTTP API path), Restore writes EVERY row under this org_id and
	// never derives the write-target org from the uploaded archive's content. It also
	// requires the archive's org identity to match DestOrgName, refusing a cross-tenant
	// restore. Empty preserves the trusted CLI behavior (org taken from the archive).
	DestOrgID string
	// DestOrgName is the caller's org name, used to assert the archive's org identity
	// matches the caller when DestOrgID is set.
	DestOrgName string
	// CanManageUsers gates the identity tables (users, custom_roles, role_bindings),
	// mirroring ApplyConfig. It is only consulted when DestOrgID is set (the scoped API
	// path): without manage-users those tables are skipped so a manage-org-only caller
	// can't escalate by restoring a crafted role binding or re-enabling an admin. The
	// trusted CLI path (DestOrgID empty) restores identity tables unconditionally.
	CanManageUsers bool
}

// TableRestoreStats summarizes restore outcomes per table.
type TableRestoreStats struct {
	Name    string `json:"name"`
	New     int64  `json:"new"`
	Updated int64  `json:"updated"`
	Skipped int64  `json:"skipped"`
}

// RestoreResult is what Restore returns to its caller.
type RestoreResult struct {
	Manifest       Manifest            `json:"manifest"`
	SignerIdentity string              `json:"signer_identity,omitempty"`
	Verified       bool                `json:"verified"`
	Tables         []TableRestoreStats `json:"tables"`
}

// Restore reads a backup tarball from opts.In and applies it to pool. Returns per-table
// stats. The transaction is per-table (not whole-archive) so a partial failure leaves the
// destination in a defined state and the operator can re-run with --on-conflict=skip.
func Restore(ctx context.Context, pool *pgxpool.Pool, opts RestoreOptions) (*RestoreResult, error) {
	if opts.OnConflict == "" {
		opts.OnConflict = ConflictSkip
	}
	// Read tar.gz fully into a map[name][]byte for random access.
	files, err := readTarGz(opts.In)
	if err != nil {
		return nil, fmt.Errorf("read archive: %w", err)
	}
	mBytes, ok := files["manifest.json"]
	if !ok {
		return nil, errors.New("manifest.json missing")
	}
	var manifest Manifest
	if err := json.Unmarshal(mBytes, &manifest); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}

	// Verify signature unless allowed to skip.
	res := &RestoreResult{Manifest: manifest}
	sig := files["manifest.json.sig"]
	cert := files["manifest.json.cert"]
	if len(sig) > 0 && opts.Verify.Mode == "" {
		// Infer mode from cert presence.
		if len(cert) > 0 {
			opts.Verify.Mode = SignModeKeyless
		} else {
			opts.Verify.Mode = SignModeStaticKey
		}
	}
	if opts.Verify.Mode != SignModeNone && opts.Verify.Mode != "" {
		identity, err := Verify(mBytes, sig, cert, opts.Verify)
		if err != nil {
			if !opts.AllowUnverified {
				return nil, fmt.Errorf("signature verify: %w", err)
			}
			res.Verified = false
		} else {
			res.Verified = true
			res.SignerIdentity = identity
		}
	} else if !opts.AllowUnverified {
		return nil, errors.New("no signature found; pass --allow-unverified to apply anyway")
	}

	// Recompute table digests for integrity. This also asserts the archive carries no
	// table file outside the signed manifest (completeness), so a validly-signed backup
	// can't be padded with an unsigned table.
	if err := verifyTableDigests(files, manifest); err != nil {
		if !opts.AllowUnverified {
			return nil, err
		}
	}

	// Resolve the destination org. When DestOrgID is set (the multi-tenant API path),
	// the write-target is pinned to the AUTHENTICATED caller's org — never to an org
	// named in the (attacker-controlled) archive. We also require the archive's org
	// identity to match the caller, refusing a cross-tenant restore outright.
	var destOrgID string
	if opts.DestOrgID != "" {
		if !orgIdentityMatches(manifest, files["tables/orgs.jsonl"], opts.DestOrgName) {
			return nil, fmt.Errorf("restore refused: archive org %q does not match caller org %q", manifest.OrgName, opts.DestOrgName)
		}
		destOrgID = opts.DestOrgID
	} else {
		// Trusted CLI path: locate or create the destination org row from the archive.
		destOrgID, err = upsertOrg(ctx, pool, files["tables/orgs.jsonl"], opts.OnConflict)
		if err != nil {
			return nil, fmt.Errorf("orgs: %w", err)
		}
	}

	// Build a cluster name -> id map after upserting clusters (used for cluster_id remap).
	clusterMap := map[string]string{}

	// Iterate the dependency-ordered list (orgs handled above).
	for _, tbl := range OrderedTables {
		body, ok := files["tables/"+tbl+".jsonl"]
		if !ok {
			// optional or never included; skip silently.
			continue
		}
		// Identity tables require manage-users on the scoped API path. Without it we
		// neither write nor account a mutation, so a manage-org-only caller can't grant
		// itself a role binding or re-enable a disabled admin via a restore. The trusted
		// CLI path (DestOrgID empty) is exempt and restores identity tables as before.
		if opts.DestOrgID != "" && identityTables[tbl] && !opts.CanManageUsers {
			skipped, _ := rowsFromJSONL(body)
			res.Tables = append(res.Tables, TableRestoreStats{Name: tbl, Skipped: int64(len(skipped))})
			continue
		}
		var stats TableRestoreStats
		switch tbl {
		case "orgs":
			// Handled above. When pinned to the caller we never rewrite the org row.
			if opts.DestOrgID != "" {
				stats = TableRestoreStats{Skipped: 1}
			} else {
				stats = TableRestoreStats{New: 1}
			}
		case "users":
			stats, err = restoreUsers(ctx, pool, body, destOrgID, opts.OnConflict)
		case "org_settings":
			stats, err = restoreOrgSettings(ctx, pool, body, destOrgID, opts.OnConflict)
		case "role_bindings":
			stats, err = restoreRoleBindings(ctx, pool, body, destOrgID, opts.OnConflict)
		case "registries":
			stats, err = restoreRegistries(ctx, pool, body, destOrgID, opts.OnConflict)
		case "api_tokens":
			// Tokens are metadata-only in the export and not restorable by design (the
			// hash never leaves the source). Record a no-op so the manifest table is
			// accounted for without mutating credentials on the destination.
			stats = TableRestoreStats{}
		case "clusters":
			stats, err = restoreClusters(ctx, pool, body, destOrgID, opts.OnConflict, clusterMap)
		case "deployments":
			stats, err = restoreDeployments(ctx, pool, body, destOrgID, opts.OnConflict, clusterMap)
		case "assets":
			stats, err = restoreAssets(ctx, pool, body, destOrgID, opts.OnConflict, clusterMap)
		case "audit_events_recent":
			stats, err = restoreAuditEvents(ctx, pool, body, destOrgID, opts.OnConflict)
		case "federation_state":
			stats, err = restoreFederationState(ctx, pool, body, destOrgID, opts.OnConflict)
		case "fed_members":
			stats, err = restoreFedMembers(ctx, pool, body, destOrgID, opts.OnConflict)
		case "image_acceptances":
			stats, err = restoreImageAcceptances(ctx, pool, body, destOrgID, opts.OnConflict)
		case "custom_frameworks":
			stats, err = restoreCustomFrameworks(ctx, pool, body, destOrgID, opts.OnConflict)
		default:
			// All the (org_id, name)-keyed tables share the generic shape.
			stats, err = restoreOrgNameKeyed(ctx, pool, tbl, body, destOrgID, opts.OnConflict, clusterMap)
		}
		if err != nil {
			return res, fmt.Errorf("%s: %w", tbl, err)
		}
		stats.Name = tbl
		res.Tables = append(res.Tables, stats)
	}

	return res, nil
}

// maxArchiveBytes caps the total DECOMPRESSED size of a restore archive. readTarGz runs
// before any signature/digest verification, so the tar header's advertised Size is fully
// untrusted: a tiny gzip can declare a huge member (or many members) to OOM the shared API
// process. Operator backups are small (low tens of MB); 512 MiB is a generous ceiling.
// A var (not const) so tests can lower it without generating half a gigabyte of input.
var maxArchiveBytes int64 = 512 << 20

// readTarGz reads a gzipped tar from r and returns a map of (path within archive) -> bytes.
func readTarGz(r io.Reader) (map[string][]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		// hdr.Size is attacker-controlled and unverified here. Never pre-allocate the
		// advertised size: cap the initial capacity to the remaining budget, and enforce the
		// hard ceiling on the actual bytes copied (LimitReader detects a header that
		// under-declares Size). Both guard against a member claiming gigabytes.
		remaining := maxArchiveBytes - total
		capHint := hdr.Size
		if capHint < 0 || capHint > remaining {
			capHint = remaining
		}
		bw := bytes.NewBuffer(make([]byte, 0, capHint))
		n, err := io.Copy(bw, io.LimitReader(tr, remaining+1))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		if n > remaining {
			return nil, fmt.Errorf("archive exceeds %d-byte decompressed limit", maxArchiveBytes)
		}
		total += n
		out[hdr.Name] = bw.Bytes()
	}
	return out, nil
}

// verifyTableDigests confirms the sha256 of each tables/<name>.jsonl matches
// manifest.Tables[].SHA256 (manifest -> archive), AND that the archive contains no
// tables/*.jsonl file outside the manifest (archive -> manifest). The reverse check is
// essential: the cosign signature covers only manifest.json, so an attacker starting
// from a validly-signed backup could append an unsigned table file (e.g. custom_roles
// with elevated RBAC) and have it applied under a "verified" restore. Asserting the
// archive's table set is a subset of the signed manifest closes that gap.
func verifyTableDigests(files map[string][]byte, m Manifest) error {
	listed := make(map[string]bool, len(m.Tables))
	for _, t := range m.Tables {
		listed[t.Name] = true
		body, ok := files["tables/"+t.Name+".jsonl"]
		if !ok {
			return fmt.Errorf("table %s missing from archive", t.Name)
		}
		got := sha256.Sum256(body)
		if hex.EncodeToString(got[:]) != t.SHA256 {
			return fmt.Errorf("table %s digest mismatch: archive=%s manifest=%s",
				t.Name, hex.EncodeToString(got[:]), t.SHA256)
		}
	}
	// Reject any table file the signed manifest does not cover.
	for name := range files {
		if !strings.HasPrefix(name, "tables/") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		tbl := strings.TrimSuffix(strings.TrimPrefix(name, "tables/"), ".jsonl")
		if !listed[tbl] {
			return fmt.Errorf("archive contains table file %q not covered by the signed manifest", name)
		}
	}
	// Recompute root hash and confirm.
	got, err := ComputeRootHash(m.Tables)
	if err != nil {
		return err
	}
	if got != m.RootHash {
		return fmt.Errorf("manifest root hash mismatch: got=%s expected=%s", got, m.RootHash)
	}
	return nil
}

// rowsFromJSONL parses a tables/<name>.jsonl byte slice into a slice of generic objects.
func rowsFromJSONL(body []byte) ([]map[string]any, error) {
	var out []map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	for dec.More() {
		var row map[string]any
		if err := dec.Decode(&row); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}

// ---- per-table restore handlers ----

// upsertOrg handles the orgs row. If the destination already has a row with the same
// `name`, we update display_name/region/ai_enabled when OnConflict=overwrite, otherwise
// we leave it alone. Returns the destination org's id (which may differ from the source's
// because UUIDs are not portable).
func upsertOrg(ctx context.Context, pool Querier, body []byte, conflict ConflictPolicy) (string, error) {
	if len(body) == 0 {
		return "", errors.New("orgs table missing from archive")
	}
	rows, err := rowsFromJSONL(body)
	if err != nil {
		return "", err
	}
	if len(rows) != 1 {
		return "", fmt.Errorf("expected exactly 1 org row, got %d", len(rows))
	}
	r := rows[0]
	name, _ := r["name"].(string)
	display, _ := r["display_name"].(string)
	region, _ := r["region"].(string)
	aiEnabled, _ := r["ai_enabled"].(bool)
	if name == "" {
		return "", errors.New("org row missing name")
	}

	var id string
	if conflict == ConflictOverwrite {
		err = pool.QueryRow(ctx, `
INSERT INTO orgs(name, display_name, region, ai_enabled)
VALUES ($1, $2, $3, $4)
ON CONFLICT (name) DO UPDATE
  SET display_name = EXCLUDED.display_name,
      region       = EXCLUDED.region,
      ai_enabled   = EXCLUDED.ai_enabled,
      updated_at   = NOW()
RETURNING id`, name, display, region, aiEnabled).Scan(&id)
	} else {
		err = pool.QueryRow(ctx, `
INSERT INTO orgs(name, display_name, region, ai_enabled)
VALUES ($1, $2, $3, $4)
ON CONFLICT (name) DO UPDATE SET updated_at = orgs.updated_at
RETURNING id`, name, display, region, aiEnabled).Scan(&id)
	}
	return id, err
}

// orgIdentityMatches reports whether the archive's org identity matches the caller's
// org name. Used by the scoped API restore to refuse a cross-tenant archive before any
// row is written. Both the manifest's OrgName and (if present) the orgs.jsonl row name
// must agree with wantName; an empty wantName never matches.
func orgIdentityMatches(m Manifest, orgsJSONL []byte, wantName string) bool {
	if wantName == "" || m.OrgName != wantName {
		return false
	}
	if len(orgsJSONL) > 0 {
		rows, err := rowsFromJSONL(orgsJSONL)
		if err == nil && len(rows) == 1 {
			if name, _ := rows[0]["name"].(string); name != "" && name != wantName {
				return false
			}
		}
	}
	return true
}

// restoreClusters upserts on (org_id, name). Populates clusterMap[name] = destClusterID.
func restoreClusters(ctx context.Context, pool Querier, body []byte, orgID string, conflict ConflictPolicy, clusterMap map[string]string) (TableRestoreStats, error) {
	stats := TableRestoreStats{}
	rows, err := rowsFromJSONL(body)
	if err != nil {
		return stats, err
	}
	for _, r := range rows {
		name, _ := r["name"].(string)
		if name == "" {
			stats.Skipped++
			continue
		}
		// Determine if an existing row is present (for new vs updated accounting).
		var existing string
		_ = pool.QueryRow(ctx, `SELECT id FROM clusters WHERE org_id=$1 AND name=$2`, orgID, name).Scan(&existing)

		distro := stringOr(r, "distro", "kubernetes")
		cloud := nullStr(r, "cloud_provider")
		region := nullStr(r, "region")
		state := stringOr(r, "state", "pending")
		agentVer := nullStr(r, "agent_version")

		var id string
		if existing != "" && conflict == ConflictSkip {
			id = existing
			stats.Skipped++
		} else if existing != "" && conflict == ConflictOverwrite {
			err = pool.QueryRow(ctx, `
UPDATE clusters SET distro=$3, cloud_provider=$4, region=$5, state=$6, agent_version=$7, updated_at=NOW()
WHERE org_id=$1 AND name=$2 RETURNING id`, orgID, name, distro, cloud, region, state, agentVer).Scan(&id)
			if err != nil {
				return stats, err
			}
			stats.Updated++
		} else {
			err = pool.QueryRow(ctx, `
INSERT INTO clusters(org_id, name, distro, cloud_provider, region, state, agent_version)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
				orgID, name, distro, cloud, region, state, agentVer).Scan(&id)
			if err != nil {
				return stats, err
			}
			stats.New++
		}
		clusterMap[name] = id
		// Also map source cluster_id -> dest cluster_id for any restore handlers that
		// need to remap by UUID rather than name.
		if srcID, ok := r["id"].(string); ok && srcID != "" {
			clusterMap[srcID] = id
		}
	}
	return stats, nil
}

func restoreDeployments(ctx context.Context, pool Querier, body []byte, orgID string, conflict ConflictPolicy, clusterMap map[string]string) (TableRestoreStats, error) {
	stats := TableRestoreStats{}
	rows, err := rowsFromJSONL(body)
	if err != nil {
		return stats, err
	}
	for _, r := range rows {
		ns := stringOr(r, "namespace", "")
		name := stringOr(r, "name", "")
		kind := stringOr(r, "kind", "")
		if name == "" || kind == "" {
			stats.Skipped++
			continue
		}
		clusterID := remapCluster(r, clusterMap)
		labels := jsonValue(r, "labels", "{}")
		imageRefs, _ := r["image_refs"].([]any)
		var refs []string
		for _, v := range imageRefs {
			if s, ok := v.(string); ok {
				refs = append(refs, s)
			}
		}
		var existing string
		_ = pool.QueryRow(ctx, `SELECT id FROM deployments WHERE org_id=$1 AND COALESCE(cluster_id::text,'')=COALESCE($2,'') AND namespace=$3 AND name=$4 AND kind=$5`,
			orgID, clusterID, ns, name, kind).Scan(&existing)
		if existing != "" && conflict == ConflictSkip {
			stats.Skipped++
			continue
		}
		if existing != "" && conflict == ConflictOverwrite {
			_, err = pool.Exec(ctx, `
UPDATE deployments SET labels=$2, image_refs=$3 WHERE id=$1`, existing, labels, refs)
			if err != nil {
				return stats, err
			}
			stats.Updated++
			continue
		}
		_, err = pool.Exec(ctx, `
INSERT INTO deployments(org_id, cluster_id, namespace, name, kind, labels, image_refs)
VALUES ($1, NULLIF($2,'')::uuid, $3, $4, $5, $6, $7)`,
			orgID, clusterID, ns, name, kind, labels, refs)
		if err != nil {
			return stats, err
		}
		stats.New++
	}
	return stats, nil
}

func restoreAssets(ctx context.Context, pool Querier, body []byte, orgID string, conflict ConflictPolicy, clusterMap map[string]string) (TableRestoreStats, error) {
	stats := TableRestoreStats{}
	rows, err := rowsFromJSONL(body)
	if err != nil {
		return stats, err
	}
	for _, r := range rows {
		kind := stringOr(r, "kind", "")
		name := stringOr(r, "name", "")
		digest := stringOr(r, "digest", "")
		if kind == "" || name == "" {
			stats.Skipped++
			continue
		}
		clusterID := remapCluster(r, clusterMap)
		labels := jsonValue(r, "labels", "{}")
		ai, _ := r["ai_workload"].(bool)
		crit := stringOr(r, "criticality", "medium")
		var existing string
		_ = pool.QueryRow(ctx, `SELECT id FROM assets WHERE org_id=$1 AND kind=$2 AND name=$3 AND COALESCE(digest,'')=COALESCE($4,'')`,
			orgID, kind, name, digest).Scan(&existing)
		if existing != "" && conflict == ConflictSkip {
			stats.Skipped++
			continue
		}
		if existing != "" && conflict == ConflictOverwrite {
			_, err = pool.Exec(ctx, `
UPDATE assets SET labels=$2, ai_workload=$3, criticality=$4 WHERE id=$1`,
				existing, labels, ai, crit)
			if err != nil {
				return stats, err
			}
			stats.Updated++
			continue
		}
		_, err = pool.Exec(ctx, `
INSERT INTO assets(org_id, cluster_id, kind, name, digest, labels, ai_workload, criticality)
VALUES ($1, NULLIF($2,'')::uuid, $3, $4, NULLIF($5,''), $6, $7, $8)`,
			orgID, clusterID, kind, name, digest, labels, ai, crit)
		if err != nil {
			return stats, err
		}
		stats.New++
	}
	return stats, nil
}

// restoreOrgNameKeyed handles the bulk of tables that have a (org_id, name) unique key.
// It inserts only the columns the destination table has, falling back to JSON-passthrough
// for jsonb/array columns. This generic path covers: policies, groups, vuln_profiles,
// response_rules_v2, receivers, waf_groups, runtime_dlp_rules, compliance_schedules.
func restoreOrgNameKeyed(ctx context.Context, pool Querier, table string, body []byte, orgID string, conflict ConflictPolicy, clusterMap map[string]string) (TableRestoreStats, error) {
	stats := TableRestoreStats{}
	rows, err := rowsFromJSONL(body)
	if err != nil {
		return stats, err
	}
	if len(rows) == 0 {
		return stats, nil
	}
	// Discover destination columns + types once.
	destCols, colTypes, err := tableColumnTypes(ctx, pool, table)
	if err != nil {
		return stats, err
	}
	for _, r := range rows {
		name, _ := r["name"].(string)
		if name == "" {
			stats.Skipped++
			continue
		}
		// Existence check (for new vs updated accounting). All these tables have org_id+name unique.
		var existing string
		_ = pool.QueryRow(ctx, fmt.Sprintf(`SELECT id FROM %s WHERE org_id=$1 AND name=$2`, table), orgID, name).Scan(&existing)
		if existing != "" && conflict == ConflictSkip {
			stats.Skipped++
			continue
		}

		// Compose column list intersection: destCols ∩ keys(r), minus PK/timestamps we can't copy.
		excluded := map[string]bool{"id": true, "created_at": true, "updated_at": true, "created_by": true}
		cols := make([]string, 0, len(destCols))
		for _, c := range destCols {
			if excluded[c] {
				continue
			}
			v, ok := r[c]
			if !ok {
				continue
			}
			// Drop NULL FK / nullable fields entirely when the destination column has a
			// useful default. Encode is type-aware below; here we just keep the column.
			_ = v
			cols = append(cols, c)
		}
		sort.Strings(cols) // deterministic order
		// Build vals in sorted-cols order.
		vals2 := make([]any, len(cols))
		for i, c := range cols {
			switch c {
			case "org_id":
				vals2[i] = orgID
			case "cluster_id":
				if v, ok := r[c]; ok {
					if remap := remapClusterByID(v, clusterMap); remap != "" {
						vals2[i] = remap
					} else {
						vals2[i] = nil
					}
				}
			case "project_id":
				vals2[i] = nil
			default:
				vals2[i] = encodeForColumn(r[c], colTypes[c])
			}
		}

		placeholders := make([]string, len(cols))
		for i := range cols {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
		}

		if existing != "" && conflict == ConflictOverwrite {
			// UPDATE with column = $n list.
			setParts := []string{}
			updateVals := []any{existing} // $1 is the row id
			pi := 2
			for i, c := range cols {
				if c == "name" || c == "org_id" {
					continue
				}
				setParts = append(setParts, fmt.Sprintf("%s = $%d", c, pi))
				updateVals = append(updateVals, vals2[i])
				pi++
			}
			if len(setParts) == 0 {
				stats.Skipped++
				continue
			}
			_, err = pool.Exec(ctx, fmt.Sprintf(`UPDATE %s SET %s WHERE id=$1`, table, strings.Join(setParts, ", ")), updateVals...)
			if err != nil {
				return stats, err
			}
			stats.Updated++
			continue
		}

		q := fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s)`, table, strings.Join(cols, ", "), strings.Join(placeholders, ", "))
		_, err = pool.Exec(ctx, q, vals2...)
		if err != nil {
			// Some tables (response_rules_v2, vuln_profiles) have FKs to users(created_by);
			// we already strip created_by. If we still get a conflict, surface it.
			return stats, fmt.Errorf("insert row: %w", err)
		}
		stats.New++
	}
	return stats, nil
}

func restoreFederationState(ctx context.Context, pool Querier, body []byte, orgID string, conflict ConflictPolicy) (TableRestoreStats, error) {
	stats := TableRestoreStats{}
	rows, err := rowsFromJSONL(body)
	if err != nil {
		return stats, err
	}
	if len(rows) == 0 {
		return stats, nil
	}
	r := rows[0]
	state := stringOr(r, "state", "standalone")
	masterID := stringOr(r, "master_id", "")
	clusterName := stringOr(r, "cluster_name", "")
	var existing string
	_ = pool.QueryRow(ctx, `SELECT org_id FROM federation_state WHERE org_id=$1`, orgID).Scan(&existing)
	if existing != "" && conflict == ConflictSkip {
		stats.Skipped++
		return stats, nil
	}
	if existing != "" {
		_, err = pool.Exec(ctx, `UPDATE federation_state SET state=$2, master_id=$3, cluster_name=$4, updated_at=NOW() WHERE org_id=$1`, orgID, state, masterID, clusterName)
		if err != nil {
			return stats, err
		}
		stats.Updated++
		return stats, nil
	}
	_, err = pool.Exec(ctx, `INSERT INTO federation_state(org_id, state, master_id, cluster_name) VALUES($1, $2, $3, $4)`, orgID, state, masterID, clusterName)
	if err != nil {
		return stats, err
	}
	stats.New++
	return stats, nil
}

func restoreFedMembers(ctx context.Context, pool Querier, body []byte, orgID string, conflict ConflictPolicy) (TableRestoreStats, error) {
	stats := TableRestoreStats{}
	rows, err := rowsFromJSONL(body)
	if err != nil {
		return stats, err
	}
	for _, r := range rows {
		cid := stringOr(r, "cluster_id", "")
		if cid == "" {
			stats.Skipped++
			continue
		}
		var existing string
		_ = pool.QueryRow(ctx, `SELECT id FROM fed_members WHERE org_id=$1 AND cluster_id=$2`, orgID, cid).Scan(&existing)
		if existing != "" && conflict == ConflictSkip {
			stats.Skipped++
			continue
		}
		name := stringOr(r, "name", "")
		role := stringOr(r, "role", "joint")
		endpoint := stringOr(r, "endpoint", "")
		if existing != "" {
			_, err = pool.Exec(ctx, `UPDATE fed_members SET name=$2, role=$3, endpoint=$4 WHERE id=$1`, existing, name, role, endpoint)
			if err != nil {
				return stats, err
			}
			stats.Updated++
			continue
		}
		_, err = pool.Exec(ctx, `INSERT INTO fed_members(org_id, cluster_id, name, role, endpoint) VALUES($1, $2, $3, $4, $5)`, orgID, cid, name, role, endpoint)
		if err != nil {
			return stats, err
		}
		stats.New++
	}
	return stats, nil
}

func restoreImageAcceptances(ctx context.Context, pool Querier, body []byte, orgID string, conflict ConflictPolicy) (TableRestoreStats, error) {
	stats := TableRestoreStats{}
	rows, err := rowsFromJSONL(body)
	if err != nil {
		return stats, err
	}
	for _, r := range rows {
		digest := stringOr(r, "image_digest", "")
		until := stringOr(r, "accepted_until", "")
		if digest == "" || until == "" {
			stats.Skipped++
			continue
		}
		var existing string
		_ = pool.QueryRow(ctx, `SELECT id FROM image_acceptances WHERE org_id=$1 AND image_digest=$2 AND accepted_until=$3`,
			orgID, digest, until).Scan(&existing)
		if existing != "" {
			stats.Skipped++
			continue
		}
		// approver_id FK to users — we don't restore users in this wave; if the user is
		// absent in the destination we skip this row rather than fail the whole table.
		approver, _ := r["approver_id"].(string)
		if approver != "" {
			var hit string
			_ = pool.QueryRow(ctx, `SELECT id FROM users WHERE id=$1`, approver).Scan(&hit)
			if hit == "" {
				stats.Skipped++
				continue
			}
		}
		rationale := stringOr(r, "rationale", "restored from backup")
		_, err = pool.Exec(ctx, `
INSERT INTO image_acceptances(org_id, image_digest, rationale, approver_id, accepted_until)
VALUES ($1, $2, $3, $4, $5)`, orgID, digest, rationale, approver, until)
		if err != nil {
			return stats, err
		}
		stats.New++
	}
	return stats, nil
}

func restoreCustomFrameworks(ctx context.Context, pool Querier, body []byte, orgID string, conflict ConflictPolicy) (TableRestoreStats, error) {
	stats := TableRestoreStats{}
	rows, err := rowsFromJSONL(body)
	if err != nil {
		return stats, err
	}
	for _, r := range rows {
		name := stringOr(r, "name", "")
		if name == "" {
			stats.Skipped++
			continue
		}
		category := stringOr(r, "category", "custom")
		description := stringOr(r, "description", "")
		ids, _ := r["control_ids"].([]any)
		var ctlIDs []string
		for _, v := range ids {
			if s, ok := v.(string); ok {
				ctlIDs = append(ctlIDs, s)
			}
		}
		var existing string
		_ = pool.QueryRow(ctx, `SELECT id FROM custom_frameworks WHERE org_id=$1 AND name=$2`, orgID, name).Scan(&existing)
		if existing != "" && conflict == ConflictSkip {
			stats.Skipped++
			continue
		}
		if existing != "" {
			_, err = pool.Exec(ctx, `UPDATE custom_frameworks SET category=$2, description=$3, control_ids=$4 WHERE id=$1`,
				existing, category, description, ctlIDs)
			if err != nil {
				return stats, err
			}
			stats.Updated++
			continue
		}
		_, err = pool.Exec(ctx, `INSERT INTO custom_frameworks(org_id, name, category, description, control_ids) VALUES($1, $2, $3, $4, $5)`,
			orgID, name, category, description, ctlIDs)
		if err != nil {
			return stats, err
		}
		stats.New++
	}
	return stats, nil
}

// restoreUsers upserts users on (org_id, email). password_hash is intentionally
// NULL on restore — the export redacts it, so a restored user authenticates via
// OIDC or a password-reset flow until an operator sets a new password. Returns no
// FK map because role_bindings are remapped by email, not by source user id.
func restoreUsers(ctx context.Context, pool Querier, body []byte, orgID string, conflict ConflictPolicy) (TableRestoreStats, error) {
	stats := TableRestoreStats{}
	rows, err := rowsFromJSONL(body)
	if err != nil {
		return stats, err
	}
	for _, r := range rows {
		email := stringOr(r, "email", "")
		if email == "" {
			stats.Skipped++
			continue
		}
		display := stringOr(r, "display_name", email)
		oidcSub := nullStr(r, "oidc_subject")
		oidcIss := nullStr(r, "oidc_issuer")
		disabled, _ := r["disabled"].(bool)
		var existing string
		_ = pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1 AND email=$2`, orgID, email).Scan(&existing)
		if existing != "" && conflict == ConflictSkip {
			stats.Skipped++
			continue
		}
		if existing != "" {
			_, err = pool.Exec(ctx, `
UPDATE users SET display_name=$2, oidc_subject=$3, oidc_issuer=$4, disabled=$5, updated_at=NOW()
WHERE id=$1`, existing, display, oidcSub, oidcIss, disabled)
			if err != nil {
				return stats, err
			}
			stats.Updated++
			continue
		}
		_, err = pool.Exec(ctx, `
INSERT INTO users(org_id, email, display_name, oidc_subject, oidc_issuer, disabled)
VALUES ($1, $2, $3, $4, $5, $6)`, orgID, email, display, oidcSub, oidcIss, disabled)
		if err != nil {
			return stats, err
		}
		stats.New++
	}
	return stats, nil
}

// restoreOrgSettings upserts the singleton org_settings row. The export redacts
// registry_kek, so a restore never imports a foreign master key — the destination
// keeps its own KEK (or bootstraps a fresh one).
func restoreOrgSettings(ctx context.Context, pool Querier, body []byte, orgID string, conflict ConflictPolicy) (TableRestoreStats, error) {
	stats := TableRestoreStats{}
	rows, err := rowsFromJSONL(body)
	if err != nil {
		return stats, err
	}
	if len(rows) == 0 {
		return stats, nil
	}
	settings := jsonValue(rows[0], "settings", "{}")
	var existing string
	_ = pool.QueryRow(ctx, `SELECT org_id FROM org_settings WHERE org_id=$1`, orgID).Scan(&existing)
	if existing != "" && conflict == ConflictSkip {
		stats.Skipped++
		return stats, nil
	}
	if existing != "" {
		// Merge incoming settings over the destination's, but never clobber the
		// destination's registry_kek (which the export stripped anyway).
		_, err = pool.Exec(ctx, `
UPDATE org_settings
   SET settings = (settings || $2::jsonb) - 'registry_kek'
       || jsonb_build_object('registry_kek', settings->'registry_kek'),
       updated_at = NOW()
 WHERE org_id=$1`, orgID, settings)
		if err != nil {
			// Fall back to a plain merge if the KEK-preserving expression trips on a
			// missing key (older PG planners): keep destination settings authoritative.
			_, err = pool.Exec(ctx, `UPDATE org_settings SET settings = settings || ($2::jsonb - 'registry_kek'), updated_at=NOW() WHERE org_id=$1`, orgID, settings)
			if err != nil {
				return stats, err
			}
		}
		stats.Updated++
		return stats, nil
	}
	_, err = pool.Exec(ctx, `INSERT INTO org_settings(org_id, settings) VALUES($1, ($2::jsonb - 'registry_kek'))`, orgID, settings)
	if err != nil {
		return stats, err
	}
	stats.New++
	return stats, nil
}

// restoreRoleBindings re-grants role bindings. subject_id is remapped from a source
// user id to the destination user id by joining through the exported users' emails;
// when subject_type is service_account (api_tokens, not restored) or the subject
// can't be resolved, the row is skipped rather than orphaning a binding.
func restoreRoleBindings(ctx context.Context, pool Querier, body []byte, orgID string, conflict ConflictPolicy) (TableRestoreStats, error) {
	stats := TableRestoreStats{}
	rows, err := rowsFromJSONL(body)
	if err != nil {
		return stats, err
	}
	for _, r := range rows {
		subjectType := stringOr(r, "subject_type", "user")
		roleID := stringOr(r, "role_id", "")
		subjectID := stringOr(r, "subject_id", "")
		if roleID == "" || subjectID == "" {
			stats.Skipped++
			continue
		}
		// Only user bindings are portable: service-account subjects reference
		// api_tokens, which are metadata-only and not restored.
		if subjectType != "user" {
			stats.Skipped++
			continue
		}
		// Resolve the destination user id. The source subject_id is a source-instance
		// user UUID; map it via the email the source row may carry, else by checking
		// whether the same UUID happens to exist in the destination org.
		var destUser string
		if email := stringOr(r, "subject_email", ""); email != "" {
			_ = pool.QueryRow(ctx, `SELECT id::text FROM users WHERE org_id=$1 AND email=$2`, orgID, email).Scan(&destUser)
		}
		if destUser == "" {
			_ = pool.QueryRow(ctx, `SELECT id::text FROM users WHERE org_id=$1 AND id::text=$2`, orgID, subjectID).Scan(&destUser)
		}
		if destUser == "" {
			stats.Skipped++
			continue
		}
		scopes := jsonValue(r, "scopes", "[]")
		var existing string
		_ = pool.QueryRow(ctx, `SELECT id FROM role_bindings WHERE org_id=$1 AND subject_id=$2 AND role_id=$3`, orgID, destUser, roleID).Scan(&existing)
		if existing != "" && conflict == ConflictSkip {
			stats.Skipped++
			continue
		}
		if existing != "" {
			_, err = pool.Exec(ctx, `UPDATE role_bindings SET scopes=$2 WHERE id=$1`, existing, scopes)
			if err != nil {
				return stats, err
			}
			stats.Updated++
			continue
		}
		_, err = pool.Exec(ctx, `
INSERT INTO role_bindings(org_id, subject_id, subject_type, role_id, scopes)
VALUES ($1, $2, 'user', $3, $4)`, orgID, destUser, roleID, scopes)
		if err != nil {
			return stats, err
		}
		stats.New++
	}
	return stats, nil
}

// restoreRegistries upserts on (org_id, name). auth_secret arrives as a hex string
// (the export hex-encodes the AES-GCM ciphertext); we decode it back to BYTEA so the
// credential is restored STILL SEALED. A destination sharing the source's KEK can
// decrypt it; otherwise the operator re-enters credentials. We never see cleartext.
func restoreRegistries(ctx context.Context, pool Querier, body []byte, orgID string, conflict ConflictPolicy) (TableRestoreStats, error) {
	stats := TableRestoreStats{}
	rows, err := rowsFromJSONL(body)
	if err != nil {
		return stats, err
	}
	for _, r := range rows {
		name := stringOr(r, "name", "")
		if name == "" {
			stats.Skipped++
			continue
		}
		kind := stringOr(r, "kind", "")
		endpoint := stringOr(r, "endpoint", "")
		authKind := stringOr(r, "auth_kind", "none")
		var sealed []byte
		if hexStr := stringOr(r, "auth_secret", ""); hexStr != "" {
			if b, derr := hex.DecodeString(hexStr); derr == nil {
				sealed = b
			}
		}
		var existing string
		_ = pool.QueryRow(ctx, `SELECT id FROM registries WHERE org_id=$1 AND name=$2`, orgID, name).Scan(&existing)
		if existing != "" && conflict == ConflictSkip {
			stats.Skipped++
			continue
		}
		if existing != "" {
			if sealed != nil {
				_, err = pool.Exec(ctx, `UPDATE registries SET kind=$2, endpoint=$3, auth_kind=$4, auth_secret=$5, updated_at=NOW() WHERE id=$1`, existing, kind, endpoint, authKind, sealed)
			} else {
				_, err = pool.Exec(ctx, `UPDATE registries SET kind=$2, endpoint=$3, auth_kind=$4, updated_at=NOW() WHERE id=$1`, existing, kind, endpoint, authKind)
			}
			if err != nil {
				return stats, err
			}
			stats.Updated++
			continue
		}
		_, err = pool.Exec(ctx, `
INSERT INTO registries(org_id, name, kind, endpoint, auth_kind, auth_secret)
VALUES ($1, $2, $3, $4, $5, $6)`, orgID, name, kind, endpoint, authKind, sealed)
		if err != nil {
			return stats, err
		}
		stats.New++
	}
	return stats, nil
}

func restoreAuditEvents(ctx context.Context, pool Querier, body []byte, orgID string, conflict ConflictPolicy) (TableRestoreStats, error) {
	stats := TableRestoreStats{}
	rows, err := rowsFromJSONL(body)
	if err != nil {
		return stats, err
	}
	// audit_events is a single GLOBAL hash chain: every row's chain_hash is
	// sha256(prev_chain_hash || canonical(row)) anchored at the destination's current head
	// (see pkg/audit). Importing the archive's foreign prev_hash/chain_hash splices a
	// discontinuous segment into that chain, so audit.VerifyChain permanently reports the
	// destination as tampered and every subsequent Logger.Log links onto the foreign hash.
	// The correct re-anchor is to re-hash each row against the live head, but the audit
	// package exposes no re-chain/append-with-fixed-timestamp helper (Log() computes the
	// hash internally and can't reproduce a historical `at`/actor_ip faithfully), so we do
	// NOT restore audit_events at all. This matches intent: audit_events_recent is purely
	// informational for the operator UI, and the canonical, verifiable log lives in S3 via
	// audit-archiver. Rows are reported as skipped rather than inserted.
	// ponytail: ceiling = drop audit rows on restore. Upgrade path: add an
	// audit.Logger.Append(ev, at) that re-anchors to the current head, then re-hash and
	// insert each row here instead of skipping.
	stats.Skipped = int64(len(rows))
	return stats, nil
}

// ---- column / row helpers ----

func tableColumns(ctx context.Context, pool Querier, table string) ([]string, error) {
	cols, _, err := tableColumnTypes(ctx, pool, table)
	return cols, err
}

// tableColumnTypes returns (column names in ordinal order, map of column->data_type).
// data_type is e.g. "jsonb", "uuid", "text", "ARRAY".
func tableColumnTypes(ctx context.Context, pool Querier, table string) ([]string, map[string]string, error) {
	rows, err := pool.Query(ctx, `
SELECT column_name, data_type FROM information_schema.columns
WHERE table_schema='public' AND table_name=$1
ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var names []string
	types := map[string]string{}
	for rows.Next() {
		var c, t string
		if err := rows.Scan(&c, &t); err != nil {
			return nil, nil, err
		}
		names = append(names, c)
		types[c] = t
	}
	return names, types, nil
}

func stringOr(r map[string]any, key, def string) string {
	if v, ok := r[key].(string); ok && v != "" {
		return v
	}
	return def
}

func nullStr(r map[string]any, key string) any {
	if v, ok := r[key].(string); ok && v != "" {
		return v
	}
	return nil
}

func jsonValue(r map[string]any, key, def string) []byte {
	v, ok := r[key]
	if !ok {
		return []byte(def)
	}
	switch x := v.(type) {
	case json.RawMessage:
		return []byte(x)
	case []byte:
		return x
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return []byte(def)
		}
		return b
	}
}

// remapCluster returns the destination cluster id (string UUID) for a row that has a
// source cluster_id and/or cluster_name attribute. Returns "" when the source row had no
// cluster (cluster_id was null).
func remapCluster(r map[string]any, clusterMap map[string]string) string {
	if s, ok := r["cluster_id"].(string); ok && s != "" {
		if dest, hit := clusterMap[s]; hit {
			return dest
		}
	}
	return ""
}

// remapClusterByID coerces v (assumed a UUID string) to a destination cluster id.
func remapClusterByID(v any, clusterMap map[string]string) string {
	s, ok := v.(string)
	if !ok || s == "" {
		return ""
	}
	if dest, hit := clusterMap[s]; hit {
		return dest
	}
	return ""
}

// encodeForColumn coerces a JSON-decoded value into the form pgx expects for the given
// Postgres data_type. The data_type strings come straight from
// information_schema.columns.data_type: "jsonb", "uuid", "text", "boolean", "integer",
// "bigint", "ARRAY", "timestamp with time zone", and friends.
//
// Rules:
//   jsonb / json    -> []byte of JSON-marshaled value (handles null, [], {}, nested objects)
//   ARRAY           -> []string when caller-supplied a []any of strings; else JSON bytes
//   uuid            -> the string (NULLIF-handled by SQL when "")
//   anything else   -> pass-through (driver will coerce numbers / strings / bools).
func encodeForColumn(v any, dataType string) any {
	if v == nil {
		// For jsonb columns, persist the JSON null literal rather than SQL NULL: the
		// source's `members: null` jsonb value should round-trip as jsonb null in the
		// destination, not as SQL NULL (which violates NOT NULL on most operator tables).
		if dataType == "jsonb" || dataType == "json" {
			return []byte("null")
		}
		return nil
	}
	switch dataType {
	case "jsonb", "json":
		// Re-marshal whatever we decoded back to JSON bytes. This handles maps, slices,
		// scalars, and nulls uniformly.
		if rm, ok := v.(json.RawMessage); ok {
			return []byte(rm)
		}
		b, err := json.Marshal(v)
		if err != nil {
			return []byte("null")
		}
		return b
	case "ARRAY":
		// Postgres array. Convert []any to []string (most operator arrays are text[]).
		if arr, ok := v.([]any); ok {
			out := make([]string, 0, len(arr))
			for _, e := range arr {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
			return out
		}
		return v
	case "uuid":
		// Empty-string sentinel -> nil so NULLable FK columns work.
		if s, ok := v.(string); ok && s == "" {
			return nil
		}
		return v
	default:
		return v
	}
}

// normalizeForInsert coerces a value freshly unmarshaled from JSON into a form that pgx
// can map to a Postgres column. json.RawMessage stays as []byte; []any becomes a []string
// when all elements are strings (Postgres text[] friendly); other types pass through.
func normalizeForInsert(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case json.RawMessage:
		return []byte(x)
	case []any:
		// Try to coerce to []string for text[] columns.
		out := make([]string, 0, len(x))
		allStr := true
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			} else {
				allStr = false
				break
			}
		}
		if allStr {
			return out
		}
		b, _ := json.Marshal(x)
		return b
	case map[string]any:
		b, _ := json.Marshal(x)
		return b
	default:
		return v
	}
}

// pgx import below kept for restoreAuditEvents transaction-style sentinel use; if we
// later switch to a Begin/Commit there the import remains needed.
var _ = pgx.ErrNoRows
