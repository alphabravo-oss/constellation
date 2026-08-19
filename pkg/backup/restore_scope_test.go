package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// tableFile builds a (digest, body) pair for a synthetic table file.
func tableFile(body string) (string, []byte) {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:]), []byte(body)
}

// buildManifestAndFiles returns a manifest + matching files map covering exactly the
// named tables, with a correct RootHash so verifyTableDigests passes the forward checks.
func buildManifestAndFiles(t *testing.T, tables map[string]string) (Manifest, map[string][]byte) {
	t.Helper()
	files := map[string][]byte{}
	var entries []TableEntry
	for name, body := range tables {
		digest, b := tableFile(body)
		files["tables/"+name+".jsonl"] = b
		entries = append(entries, TableEntry{Name: name, SHA256: digest, Rows: 1, Bytes: int64(len(b))})
	}
	root, err := ComputeRootHash(entries)
	if err != nil {
		t.Fatalf("root hash: %v", err)
	}
	return Manifest{FormatVersion: FormatVersion, OrgName: "acme", Tables: entries, RootHash: root}, files
}

// A validly-signed manifest plus an UNLISTED table file (the cosign signature only
// covers manifest.json) must be rejected — closing the "append an unsigned custom_roles"
// RBAC-injection path.
func TestVerifyTableDigestsRejectsUnlistedFile(t *testing.T) {
	m, files := buildManifestAndFiles(t, map[string]string{
		"orgs":     `{"name":"acme"}`,
		"clusters": `{"name":"prod"}`,
	})
	// Baseline: the legitimate set verifies.
	if err := verifyTableDigests(files, m); err != nil {
		t.Fatalf("expected legitimate archive to verify, got %v", err)
	}
	// Attacker appends an unsigned table not covered by the manifest.
	files["tables/custom_roles.jsonl"] = []byte(`{"name":"superadmin","verbs":["*"]}`)
	err := verifyTableDigests(files, m)
	if err == nil {
		t.Fatal("expected rejection of table file not covered by the signed manifest")
	}
}

// verifyTableDigests must still catch the forward case: a manifest table missing from the
// archive, or a digest mismatch.
func TestVerifyTableDigestsForwardChecks(t *testing.T) {
	m, files := buildManifestAndFiles(t, map[string]string{"orgs": `{"name":"acme"}`})
	delete(files, "tables/orgs.jsonl")
	if err := verifyTableDigests(files, m); err == nil {
		t.Fatal("expected error for manifest table missing from archive")
	}

	m2, files2 := buildManifestAndFiles(t, map[string]string{"orgs": `{"name":"acme"}`})
	files2["tables/orgs.jsonl"] = []byte(`{"name":"tampered"}`)
	if err := verifyTableDigests(files2, m2); err == nil {
		t.Fatal("expected digest mismatch error")
	}
}

// orgIdentityMatches is the cross-tenant guard: the scoped API restore must refuse an
// archive whose org identity differs from the authenticated caller's org name, and never
// match on an empty caller name.
func TestOrgIdentityMatches(t *testing.T) {
	cases := []struct {
		name      string
		manifest  string
		orgsRow   string
		wantName  string
		wantMatch bool
	}{
		{"same org", "acme", `{"name":"acme"}`, "acme", true},
		{"cross-tenant manifest", "victim", `{"name":"victim"}`, "acme", false},
		{"manifest lies, orgs row is victim", "acme", `{"name":"victim"}`, "acme", false},
		{"empty caller never matches", "acme", `{"name":"acme"}`, "", false},
		{"no orgs row, manifest agrees", "acme", "", "acme", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := Manifest{OrgName: c.manifest}
			var body []byte
			if c.orgsRow != "" {
				body = []byte(c.orgsRow)
			}
			if got := orgIdentityMatches(m, body, c.wantName); got != c.wantMatch {
				t.Fatalf("orgIdentityMatches=%v want %v", got, c.wantMatch)
			}
		})
	}
}
