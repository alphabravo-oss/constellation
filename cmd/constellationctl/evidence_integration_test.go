//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

func TestInventoryCLIExportAndOfflineVerification(t *testing.T) {
	// Environment overrides deliberately prove that verify never consults a DB or AWS.
	t.Setenv("DATABASE_URL", "postgres://should-never-connect.invalid/secret")
	t.Setenv("AWS_ENDPOINT_URL", "http://should-never-connect.invalid")
	pool := pgtest.Pool(t)
	var org, target, evidence uuid.UUID
	if err := pool.QueryRow(t.Context(), `INSERT INTO orgs(name,display_name) VALUES($1,'archive fixture') RETURNING id`, uuid.NewString()).Scan(&org); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `INSERT INTO scan_targets(org_id,type,ref,source_type) VALUES($1,'image','fixture/image','manual') RETURNING id`, org).Scan(&target); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `INSERT INTO scan_evidence(org_id,scan_target_id,target_type,target_ref,source_type,evidence_type,inventory_hash,package_count,payload,observed_at) VALUES($1,$2,'image','fixture/image','manual','package-inventory','fixture',1,'{"private_inventory":true}',now()) RETURNING id`, org, target).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	private, public := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
	if err := backup.GenerateEd25519Keypair(private, public); err != nil {
		t.Fatal(err)
	}
	cmd := evidenceCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"export-inventory", "--database-url", pool.Config().ConnString(), "--org-id", org.String(), "--evidence-id", evidence.String(), "--sign-key", private, "--verify-key", public, "--out-dir", filepath.Join(dir, "archives")})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(result.Path)
	if err != nil || stat.Mode().Perm() != 0o600 {
		t.Fatalf("archive permissions: %v", err)
	}
	cmd = evidenceCmd()
	output.Reset()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"verify-inventory", "--in", result.Path, "--verify-key", public})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "private_inventory") || !strings.Contains(output.String(), evidence.String()) {
		t.Fatal("verification output incorrect or leaks inventory")
	}
	if err := os.WriteFile(result.Path, []byte(`{"tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd = evidenceCmd()
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"verify-inventory", "--in", result.Path, "--verify-key", public})
	if err := cmd.ExecuteContext(t.Context()); err == nil {
		t.Fatal("tampered file verified")
	}
}
