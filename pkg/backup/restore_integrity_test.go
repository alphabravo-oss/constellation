package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func archiveFixture(t *testing.T, orgName string, tables map[string]string) map[string][]byte {
	t.Helper()
	manifest, files := buildManifestAndFiles(t, tables)
	manifest.OrgName = orgName
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files["manifest.json"] = encoded
	return files
}

func TestRestoreIntegrityCannotBeWaived(t *testing.T) {
	for _, mutation := range []string{"digest", "unlisted", "missing", "version", "counts", "duplicate", "json"} {
		t.Run(mutation, func(t *testing.T) {
			files := archiveFixture(t, "acme", map[string]string{"orgs": `{"name":"acme"}`})
			var manifest Manifest
			if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "digest":
				files["tables/orgs.jsonl"] = []byte(`{"name":"tampered"}`)
			case "unlisted":
				files["tables/custom_roles.jsonl"] = []byte(`{"name":"admin"}`)
			case "missing":
				delete(files, "tables/orgs.jsonl")
			case "version":
				manifest.FormatVersion = "future"
			case "counts":
				manifest.Tables[0].Rows++
			case "duplicate":
				manifest.Tables = append(manifest.Tables, manifest.Tables[0])
			case "json":
				manifest.Tables[0].SHA256, files["tables/orgs.jsonl"] = tableFile(`{"name":"acme"}]`)
				manifest.Tables[0].Bytes = int64(len(files["tables/orgs.jsonl"]))
			}
			manifest.RootHash, _ = ComputeRootHash(manifest.Tables)
			files["manifest.json"], _ = json.Marshal(manifest)
			archive := makeTarGz(t, files)
			for _, allow := range []bool{false, true} {
				options := RestoreOptions{In: bytes.NewReader(archive), AllowUnverified: allow}
				if _, err := VerifyArchive(options); err == nil {
					t.Fatalf("verification accepted %s (allow=%v)", mutation, allow)
				}
				options.In = bytes.NewReader(archive)
				if _, err := Restore(context.Background(), nil, options); err == nil {
					t.Fatal("restore accepted invalid evidence before opening a DB transaction")
				}
			}
		})
	}
}

func TestVerifyArchiveUsesCryptographicIdentity(t *testing.T) {
	directory := t.TempDir()
	privateKey, publicKey := filepath.Join(directory, "private.pem"), filepath.Join(directory, "public.pem")
	if err := GenerateEd25519Keypair(privateKey, publicKey); err != nil {
		t.Fatal(err)
	}
	files := archiveFixture(t, "acme", map[string]string{"orgs": `{"name":"acme"}`})
	var manifest Manifest
	_ = json.Unmarshal(files["manifest.json"], &manifest)
	manifest.SignerIdentity = "attacker-claimed-identity"
	files["manifest.json"], _ = json.Marshal(manifest)
	signature, _, identity, err := Sign(files["manifest.json"], SignerOptions{Mode: SignModeStaticKey, KeyPath: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	files["manifest.json.sig"] = signature
	result, err := VerifyArchive(RestoreOptions{
		In: bytes.NewReader(makeTarGz(t, files)), Verify: VerifierOptions{KeyPath: publicKey},
	})
	if err != nil || !result.Verified || result.SignerIdentity != identity {
		t.Fatalf("signature verification failed: %+v %v", result, err)
	}
	delete(files, "manifest.json.sig")
	options := RestoreOptions{In: bytes.NewReader(makeTarGz(t, files))}
	if _, err := VerifyArchive(options); err == nil {
		t.Fatal("unsigned archive accepted without operator opt-in")
	}
	options.In = bytes.NewReader(makeTarGz(t, files))
	options.AllowUnverified = true
	result, err = VerifyArchive(options)
	if err != nil || result.Verified || result.SignerIdentity != "" {
		t.Fatalf("unverified archive acquired a trusted identity: %+v %v", result, err)
	}
}

func TestRestoreTenantAndIdentityScope(t *testing.T) {
	pool := openConfigTestPool(t)
	defer pool.Close()
	orgID, cleanup := seedConfigOrg(t, pool)
	defer cleanup()
	ctx := context.Background()
	var orgName string
	if err := pool.QueryRow(ctx, `SELECT name FROM orgs WHERE id=$1`, orgID).Scan(&orgName); err != nil {
		t.Fatal(err)
	}
	options := RestoreOptions{DestOrgID: orgID, DestOrgName: orgName, AllowUnverified: true, OnConflict: ConflictOverwrite}
	files := archiveFixture(t, "victim", map[string]string{"orgs": `{"name":"victim"}`})
	options.In = bytes.NewReader(makeTarGz(t, files))
	if _, err := Restore(ctx, pool, options); err == nil {
		t.Fatal("cross-tenant archive accepted")
	}
	files = archiveFixture(t, orgName, map[string]string{
		"orgs":         `{"name":"` + orgName + `"}`,
		"users":        `{"email":"injected@test.invalid","display_name":"Injected"}`,
		"custom_roles": `{"name":"injected","verbs":["manage-users"]}`,
		"policies":     `{"name":"restored-policy","engine":"opa-rego","category":"admission","spec_yaml":"package test"}`,
	})
	for range 2 {
		options.In = bytes.NewReader(makeTarGz(t, files))
		if _, err := Restore(ctx, pool, options); err != nil {
			t.Fatal(err)
		}
	}
	var users, roles, policies int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM users WHERE org_id=$1 AND email='injected@test.invalid'),
		(SELECT count(*) FROM custom_roles WHERE org_id=$1 AND name='injected'),
		(SELECT count(*) FROM policies WHERE org_id=$1 AND name='restored-policy')`, orgID).Scan(&users, &roles, &policies); err != nil {
		t.Fatal(err)
	}
	if users != 0 || roles != 0 || policies != 1 {
		t.Fatalf("scope/idempotency mismatch: users=%d roles=%d policies=%d", users, roles, policies)
	}
}

func TestRestoreRollsBackEarlierTablesOnFailure(t *testing.T) {
	pool := openConfigTestPool(t)
	defer pool.Close()
	orgID, cleanup := seedConfigOrg(t, pool)
	defer cleanup()
	ctx := context.Background()
	var orgName string
	if err := pool.QueryRow(ctx, `SELECT name FROM orgs WHERE id=$1`, orgID).Scan(&orgName); err != nil {
		t.Fatal(err)
	}
	files := archiveFixture(t, orgName, map[string]string{
		"orgs":     `{"name":"` + orgName + `"}`,
		"users":    `{"email":"rollback@test.invalid","display_name":"Rollback"}`,
		"policies": `{"name":"bad-policy","engine":"invalid-engine","category":"admission"}`,
	})
	result, err := Restore(ctx, pool, RestoreOptions{
		In: bytes.NewReader(makeTarGz(t, files)), DestOrgID: orgID, DestOrgName: orgName,
		AllowUnverified: true, CanManageUsers: true,
	})
	if err == nil || result != nil {
		t.Fatalf("failed restore reported committed counts: %+v %v", result, err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE org_id=$1 AND email='rollback@test.invalid')`, orgID).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("earlier user table committed despite later failure")
	}
}

func TestConfigImportRejectsForeignClusterWithoutBroadening(t *testing.T) {
	pool := openConfigTestPool(t)
	defer pool.Close()
	orgID, cleanup := seedConfigOrg(t, pool)
	defer cleanup()
	document := &ConfigDocument{Tables: []ConfigTableBlock{{Name: "policies", Rows: []map[string]any{{
		"name": "foreign-cluster", "cluster_id": uuid.NewString(), "engine": "opa-rego", "category": "admission", "spec_yaml": "package test",
	}}}}}
	_, err := ApplyConfig(context.Background(), pool, orgID, document, ConfigMerge, ApplyOptions{})
	if err == nil || !strings.Contains(err.Error(), "unresolved cluster scope") {
		t.Fatalf("foreign cluster became org-wide: %v", err)
	}
}
