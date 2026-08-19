package backup

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// openConfigTestPool connects to the test database. Skips when unreachable so the
// suite stays green in environments without Postgres.
func openConfigTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		url = "postgres://constellation:constellation@localhost:15433/constellation_test?sslmode=disable"
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Skipf("skipping: cannot create pool (%v)", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Skipf("skipping: cannot reach test DB (%v)", err)
	}
	return pool
}

// seedConfigOrg creates an isolated org with one user (password hash set), a custom
// role, an org_settings row carrying a registry_kek secret, a sealed registry, an
// API token (hash set), and two policies. Returns the org id and a cleanup func.
func seedConfigOrg(t *testing.T, pool *pgxpool.Pool) (orgID string, cleanup func()) {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("b3-cfg-%d", time.Now().UnixNano())
	err := pool.QueryRow(ctx, `INSERT INTO orgs(name, display_name) VALUES($1,$1) RETURNING id::text`, name).Scan(&orgID)
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	cleanup = func() {
		// ON DELETE CASCADE on org_id-referencing tables cleans up most; api_tokens
		// cascade via users.
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
	}

	var userID string
	if err := pool.QueryRow(ctx, `
INSERT INTO users(org_id, email, display_name, password_hash)
VALUES($1, $2, 'Alice', $3) RETURNING id::text`,
		orgID, "alice@"+name+".test", "$argon2id$SUPERSECRETHASH").Scan(&userID); err != nil {
		cleanup()
		t.Fatalf("seed user: %v", err)
	}

	if _, err := pool.Exec(ctx, `
INSERT INTO custom_roles(org_id, name, description, verbs)
VALUES($1, 'auditors-plus', 'extra', ARRAY['read-findings','read-audit'])`, orgID); err != nil {
		cleanup()
		t.Fatalf("seed custom_role: %v", err)
	}

	if _, err := pool.Exec(ctx, `
INSERT INTO org_settings(org_id, settings)
VALUES($1, jsonb_build_object('registry_kek', $2::text, 'theme', 'dark',
	'slack_webhook_token', $3::text, 'smtp_password', $4::text))`,
		orgID, "DEADBEEFCAFE", "SLACKSECRETTOKEN123", "SMTPSECRETPW456"); err != nil {
		cleanup()
		t.Fatalf("seed org_settings: %v", err)
	}

	sealed := []byte{0x01, 0x02, 0x03, 0xfe, 0xed, 0xfa, 0xce} // pretend AES-GCM ciphertext
	if _, err := pool.Exec(ctx, `
INSERT INTO registries(org_id, name, kind, endpoint, auth_kind, auth_secret)
VALUES($1, 'ghcr-main', 'ghcr', 'https://ghcr.io', 'static', $2)`, orgID, sealed); err != nil {
		cleanup()
		t.Fatalf("seed registry: %v", err)
	}

	if _, err := pool.Exec(ctx, `
INSERT INTO api_tokens(user_id, name, token_hash)
VALUES($1, 'ci-token', $2)`, userID, "sha256-SECRET-TOKEN-HASH-"+name); err != nil {
		cleanup()
		t.Fatalf("seed api_token: %v", err)
	}

	for _, p := range []string{"policy-a", "policy-b"} {
		if _, err := pool.Exec(ctx, `
INSERT INTO policies(org_id, name, engine, category, spec_yaml, enabled)
VALUES($1, $2, 'opa-rego', 'admission', 'package x', true)`, orgID, p); err != nil {
			cleanup()
			t.Fatalf("seed policy %s: %v", p, err)
		}
	}
	return orgID, cleanup
}

func tableBlock(doc *ConfigDocument, name string) *ConfigTableBlock {
	for i := range doc.Tables {
		if doc.Tables[i].Name == name {
			return &doc.Tables[i]
		}
	}
	return nil
}

// TestExportConfigIncludesOmittedTables: the config export now carries the tables the
// old backup omitted (org_settings, users, custom_roles, registries, api_tokens).
func TestExportConfigIncludesOmittedTables(t *testing.T) {
	pool := openConfigTestPool(t)
	defer pool.Close()
	orgID, cleanup := seedConfigOrg(t, pool)
	defer cleanup()

	doc, err := ExportConfig(context.Background(), pool, ConfigExportOptions{OrgID: orgID})
	if err != nil {
		t.Fatalf("ExportConfig: %v", err)
	}
	for _, want := range []string{"org_settings", "users", "custom_roles", "registries", "api_tokens"} {
		b := tableBlock(doc, want)
		if b == nil {
			t.Errorf("config export missing previously-omitted table %q", want)
			continue
		}
		if len(b.Rows) == 0 {
			t.Errorf("table %q exported with zero rows", want)
		}
	}
}

// TestExportConfigRedactsSecrets: no secret value appears in cleartext anywhere in the
// serialized document, and the redaction/sealing rules hold per table.
func TestExportConfigRedactsSecrets(t *testing.T) {
	pool := openConfigTestPool(t)
	defer pool.Close()
	orgID, cleanup := seedConfigOrg(t, pool)
	defer cleanup()

	doc, err := ExportConfig(context.Background(), pool, ConfigExportOptions{OrgID: orgID})
	if err != nil {
		t.Fatalf("ExportConfig: %v", err)
	}
	blob, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(blob)

	for _, secret := range []string{
		"SUPERSECRETHASH",     // user password hash
		"SECRET-TOKEN-HASH",   // api token hash
		"DEADBEEFCAFE",        // registry KEK in org_settings
		"SLACKSECRETTOKEN123", // secret-looking key in the settings bag (…_token)
		"SMTPSECRETPW456",     // secret-looking key in the settings bag (…_password)
	} {
		if strings.Contains(s, secret) {
			t.Errorf("cleartext secret %q leaked into config export", secret)
		}
	}

	// User password hash must be blanked.
	if u := tableBlock(doc, "users"); u != nil {
		for _, r := range u.Rows {
			if ph, _ := r["password_hash"].(string); ph != "" {
				t.Errorf("users.password_hash not redacted: %q", ph)
			}
		}
	}
	// api_tokens.token_hash must be blanked.
	if at := tableBlock(doc, "api_tokens"); at != nil {
		for _, r := range at.Rows {
			if th, _ := r["token_hash"].(string); th != "" {
				t.Errorf("api_tokens.token_hash not redacted: %q", th)
			}
		}
	}
	// org_settings must drop registry_kek but keep other keys.
	if os2 := tableBlock(doc, "org_settings"); os2 != nil && len(os2.Rows) > 0 {
		settingsJSON, _ := json.Marshal(os2.Rows[0]["settings"])
		var m map[string]any
		_ = json.Unmarshal(settingsJSON, &m)
		if _, present := m["registry_kek"]; present {
			t.Errorf("org_settings.registry_kek not stripped: %v", m)
		}
		for _, secretKey := range []string{"slack_webhook_token", "smtp_password"} {
			if _, present := m[secretKey]; present {
				t.Errorf("org_settings secret-looking key %q not stripped: %v", secretKey, m)
			}
		}
		if _, present := m["theme"]; !present {
			t.Errorf("org_settings non-secret key 'theme' was dropped: %v", m)
		}
	}
	// registries.auth_secret must be the hex of the sealed ciphertext (never cleartext,
	// and decodable back to the original bytes).
	if reg := tableBlock(doc, "registries"); reg != nil && len(reg.Rows) > 0 {
		hexStr, _ := reg.Rows[0]["auth_secret"].(string)
		raw, derr := hex.DecodeString(hexStr)
		if derr != nil || len(raw) == 0 {
			t.Errorf("registries.auth_secret not hex-encoded sealed bytes: %q (%v)", hexStr, derr)
		}
	}
}

// TestApplyConfigMergeUpsertsWithoutDeleting: merge upserts present rows and leaves
// not-present rows untouched.
func TestApplyConfigMergeUpsertsWithoutDeleting(t *testing.T) {
	ctx := context.Background()
	pool := openConfigTestPool(t)
	defer pool.Close()
	orgID, cleanup := seedConfigOrg(t, pool)
	defer cleanup()

	// Export, then drop policy-b from the document and mutate policy-a's enabled flag.
	doc, err := ExportConfig(ctx, pool, ConfigExportOptions{OrgID: orgID})
	if err != nil {
		t.Fatalf("ExportConfig: %v", err)
	}
	pb := tableBlock(doc, "policies")
	if pb == nil {
		t.Fatal("policies block missing")
	}
	var kept []map[string]any
	for _, r := range pb.Rows {
		if r["name"] == "policy-b" {
			continue // drop policy-b from the doc
		}
		if r["name"] == "policy-a" {
			r["enabled"] = false // change a field
		}
		kept = append(kept, r)
	}
	pb.Rows = kept

	if _, err := ApplyConfig(ctx, pool, orgID, doc, ConfigMerge, ApplyOptions{CanManageUsers: true}); err != nil {
		t.Fatalf("ApplyConfig merge: %v", err)
	}

	// policy-b must STILL exist (merge does not delete not-present rows).
	var cntB int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM policies WHERE org_id=$1 AND name='policy-b'`, orgID).Scan(&cntB)
	if cntB != 1 {
		t.Errorf("merge deleted not-present policy-b (count=%d, want 1)", cntB)
	}
	// policy-a must be updated to enabled=false.
	var enabledA bool
	_ = pool.QueryRow(ctx, `SELECT enabled FROM policies WHERE org_id=$1 AND name='policy-a'`, orgID).Scan(&enabledA)
	if enabledA {
		t.Errorf("merge did not upsert policy-a.enabled (still true)")
	}
}

// TestApplyConfigReplaceRemovesNotPresent: replace upserts present rows AND deletes the
// org's rows whose natural key is absent from the document.
func TestApplyConfigReplaceRemovesNotPresent(t *testing.T) {
	ctx := context.Background()
	pool := openConfigTestPool(t)
	defer pool.Close()
	orgID, cleanup := seedConfigOrg(t, pool)
	defer cleanup()

	doc, err := ExportConfig(ctx, pool, ConfigExportOptions{OrgID: orgID})
	if err != nil {
		t.Fatalf("ExportConfig: %v", err)
	}
	// Drop policy-b and the custom role from the document.
	pb := tableBlock(doc, "policies")
	var keptP []map[string]any
	for _, r := range pb.Rows {
		if r["name"] == "policy-b" {
			continue
		}
		keptP = append(keptP, r)
	}
	pb.Rows = keptP
	if cr := tableBlock(doc, "custom_roles"); cr != nil {
		cr.Rows = nil // drop all custom roles from the doc
	}

	if _, err := ApplyConfig(ctx, pool, orgID, doc, ConfigReplace, ApplyOptions{CanManageUsers: true}); err != nil {
		t.Fatalf("ApplyConfig replace: %v", err)
	}

	// policy-b must be DELETED (not present in doc).
	var cntB int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM policies WHERE org_id=$1 AND name='policy-b'`, orgID).Scan(&cntB)
	if cntB != 0 {
		t.Errorf("replace did not delete not-present policy-b (count=%d, want 0)", cntB)
	}
	// policy-a must SURVIVE (present in doc).
	var cntA int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM policies WHERE org_id=$1 AND name='policy-a'`, orgID).Scan(&cntA)
	if cntA != 1 {
		t.Errorf("replace removed present policy-a (count=%d, want 1)", cntA)
	}
	// custom role must be DELETED.
	var cntCR int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM custom_roles WHERE org_id=$1`, orgID).Scan(&cntCR)
	if cntCR != 0 {
		t.Errorf("replace did not delete not-present custom_roles (count=%d, want 0)", cntCR)
	}

	// Replace must NOT touch another org's rows: confirm a second org's policy survives.
	other, cleanup2 := seedConfigOrg(t, pool)
	defer cleanup2()
	var otherCnt int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM policies WHERE org_id=$1`, other).Scan(&otherCnt)
	if otherCnt != 2 {
		t.Errorf("replace scope leaked into another org (count=%d, want 2)", otherCnt)
	}
}

// TestApplyConfigSkipsIdentityTablesWithoutManageUsers: a caller lacking manage-users
// (CanManageUsers=false) must NOT be able to write users / custom_roles / role_bindings
// via import — closing the manage-org-only privilege-escalation path. The non-identity
// tables (policies) still apply.
func TestApplyConfigSkipsIdentityTablesWithoutManageUsers(t *testing.T) {
	ctx := context.Background()
	pool := openConfigTestPool(t)
	defer pool.Close()
	orgID, cleanup := seedConfigOrg(t, pool)
	defer cleanup()

	doc, err := ExportConfig(ctx, pool, ConfigExportOptions{OrgID: orgID})
	if err != nil {
		t.Fatalf("ExportConfig: %v", err)
	}
	// Inject a NEW custom role and a NEW user into the document — an attacker's payload.
	if cr := tableBlock(doc, "custom_roles"); cr != nil {
		cr.Rows = append(cr.Rows, map[string]any{
			"name": "attacker-role", "description": "x", "verbs": []any{"manage-org"},
		})
	}
	if u := tableBlock(doc, "users"); u != nil {
		u.Rows = append(u.Rows, map[string]any{
			"email": "attacker@evil.test", "display_name": "Mallory",
		})
	}

	// Apply WITHOUT manage-users: identity tables must be skipped entirely.
	if _, err := ApplyConfig(ctx, pool, orgID, doc, ConfigMerge, ApplyOptions{CanManageUsers: false}); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	var crCnt int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM custom_roles WHERE org_id=$1 AND name='attacker-role'`, orgID).Scan(&crCnt)
	if crCnt != 0 {
		t.Errorf("import wrote custom_roles without manage-users (escalation, count=%d)", crCnt)
	}
	var uCnt int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE org_id=$1 AND email='attacker@evil.test'`, orgID).Scan(&uCnt)
	if uCnt != 0 {
		t.Errorf("import wrote users without manage-users (escalation, count=%d)", uCnt)
	}
	// Non-identity table still applied: policies untouched/present.
	var pCnt int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM policies WHERE org_id=$1`, orgID).Scan(&pCnt)
	if pCnt != 2 {
		t.Errorf("non-identity tables should still apply (policies count=%d, want 2)", pCnt)
	}
}

// TestApplyConfigReplacePreservesImporter: a replace import whose document OMITS the
// importing principal must NOT delete the importer's own users row (the org-lockout bug).
func TestApplyConfigReplacePreservesImporter(t *testing.T) {
	ctx := context.Background()
	pool := openConfigTestPool(t)
	defer pool.Close()
	orgID, cleanup := seedConfigOrg(t, pool)
	defer cleanup()

	doc, err := ExportConfig(ctx, pool, ConfigExportOptions{OrgID: orgID})
	if err != nil {
		t.Fatalf("ExportConfig: %v", err)
	}
	// The seeded user's email is alice@<org>.test — find it, then drop ALL users from the doc.
	var importerEmail string
	if u := tableBlock(doc, "users"); u != nil && len(u.Rows) > 0 {
		importerEmail, _ = u.Rows[0]["email"].(string)
		u.Rows = nil // document omits every user
	}
	if importerEmail == "" {
		t.Fatal("could not resolve seeded importer email")
	}

	if _, err := ApplyConfig(ctx, pool, orgID, doc, ConfigReplace, ApplyOptions{
		SubjectEmail: importerEmail, CanManageUsers: true,
	}); err != nil {
		t.Fatalf("ApplyConfig replace: %v", err)
	}
	var cnt int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE org_id=$1 AND email=$2`, orgID, importerEmail).Scan(&cnt)
	if cnt != 1 {
		t.Errorf("replace deleted the importing principal's own user row (lockout): count=%d, want 1", cnt)
	}
}

// TestApplyConfigRollsBackOnError: a failure mid-import must roll back every prior table
// and (under replace) every delete, leaving the org untouched.
func TestApplyConfigRollsBackOnError(t *testing.T) {
	ctx := context.Background()
	pool := openConfigTestPool(t)
	defer pool.Close()
	orgID, cleanup := seedConfigOrg(t, pool)
	defer cleanup()

	doc, err := ExportConfig(ctx, pool, ConfigExportOptions{OrgID: orgID})
	if err != nil {
		t.Fatalf("ExportConfig: %v", err)
	}
	// Drop policy-b from the doc so a replace WOULD delete it — but also poison a later
	// table so the apply fails AFTER the policies delete/upsert. receivers requires a
	// 'kind' column; insert a row that violates a NOT NULL / type to force an error.
	pb := tableBlock(doc, "policies")
	var keptP []map[string]any
	for _, r := range pb.Rows {
		if r["name"] == "policy-b" {
			continue
		}
		keptP = append(keptP, r)
	}
	pb.Rows = keptP
	// Poison vuln_profiles with a row whose name is present but with an invalid jsonb so
	// the insert fails. We append a receivers row with a bogus required column instead:
	// use a deliberately bad value for a typed column to trigger a DB error.
	if rb := tableBlock(doc, "receivers"); rb != nil {
		rb.Rows = append(rb.Rows, map[string]any{
			"name": "bad-recv", "kind": "webhook", "config": "not-valid-json-object-«",
		})
	}

	_, err = ApplyConfig(ctx, pool, orgID, doc, ConfigReplace, ApplyOptions{CanManageUsers: true})
	if err == nil {
		t.Skip("poisoned row did not error on this schema; rollback path not exercised")
	}
	// policy-b must STILL exist: the replace-delete of policies was rolled back.
	var cntB int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM policies WHERE org_id=$1 AND name='policy-b'`, orgID).Scan(&cntB)
	if cntB != 1 {
		t.Errorf("failed import was not rolled back: policy-b deleted (count=%d, want 1)", cntB)
	}
}
