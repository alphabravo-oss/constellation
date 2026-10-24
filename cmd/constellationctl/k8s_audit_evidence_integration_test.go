//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/k8sauditarchive"
	"github.com/alphabravocompany/constellation/internal/server/database"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

func seedK8sArchiveCLIScope(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	org, cluster := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'CLI fixture')`, org, org.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'CLI fixture')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	return org, cluster
}

func TestK8sAuditCLIIndependentRecovery(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://never-connect.invalid/secret")
	t.Setenv("AWS_ENDPOINT_URL", "http://never-connect.invalid")
	source := pgtest.Pool(t)
	org, cluster := seedK8sArchiveCLIScope(t, source)
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, err := source.Exec(t.Context(), `INSERT INTO k8s_audit_events(org_id,cluster_id,verb,raw,at) VALUES($1,$2,'get','{"private_event":"kept"}',$3)`, org, cluster, at); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	private, public := filepath.Join(dir, "private"), filepath.Join(dir, "public")
	if err := backup.GenerateEd25519Keypair(private, public); err != nil {
		t.Fatal(err)
	}
	cmd := evidenceCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"export-k8s-audit", "--org-id", org.String(), "--cluster-id", cluster.String(), "--from", at.Format(time.RFC3339), "--through", at.Add(time.Hour).Format(time.RFC3339), "--sign-key", private, "--verify-key", public, "--out-dir", filepath.Join(dir, "archives"), "--database-url", source.Config().ConnString()})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	var exported struct {
		Path   string                 `json:"path"`
		Report k8sauditarchive.Report `json:"archive"`
	}
	if err := json.Unmarshal(output.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	if exported.Report.Manifest.Count != 1 || strings.Contains(output.String(), "private_event") {
		t.Fatal("export report leaked raw data or has wrong count")
	}
	info, err := os.Stat(exported.Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private file: %v", err)
	}
	source.Close()
	cmd = evidenceCmd()
	output.Reset()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"verify-k8s-audit", "--in", exported.Path, "--verify-key", public})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "private_event") {
		t.Fatal("offline verification leaked event")
	}
	dest, err := pgxpool.New(t.Context(), pgtest.FreshURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dest.Close)
	if _, err = database.MigratePool(t.Context(), dest, slog.Default()); err != nil {
		t.Fatal(err)
	}
	destOrg, destCluster := seedK8sArchiveCLIScope(t, dest)
	cmd = evidenceCmd()
	output.Reset()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"restore-k8s-audit", "--in", exported.Path, "--verify-key", public, "--org-id", destOrg.String(), "--cluster-id", destCluster.String(), "--database-url", dest.Config().ConnString()})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	var result k8sauditarchive.RestoreResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.Inserted != 1 || result.OrgID != destOrg || result.ClusterID != destCluster {
		t.Fatalf("CLI restore: %+v %v", result, err)
	}
}
