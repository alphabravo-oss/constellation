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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/server/database"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
	"github.com/alphabravocompany/constellation/internal/threatarchive"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

func TestRuntimeThreatCLIIndependentRecovery(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://never-connect.invalid/secret")
	t.Setenv("AWS_ENDPOINT_URL", "http://never-connect.invalid")
	source := pgtest.Pool(t)
	org, cluster := seedK8sArchiveCLIScope(t, source)
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, err := source.Exec(t.Context(), `INSERT INTO runtime_threats(org_id,cluster_id,threat_id,severity,msg,packet,reported_at,at) VALUES($1,$2,4294967295,9,'private_event',decode('00ff80','hex'),$3,$3)`, org, cluster, at); err != nil {
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
	cmd.SetArgs([]string{"export-runtime-threat", "--org-id", org.String(), "--cluster-id", cluster.String(), "--from", at.Format(time.RFC3339), "--through", at.Add(time.Hour).Format(time.RFC3339), "--sign-key", private, "--verify-key", public, "--out-dir", filepath.Join(dir, "archives"), "--database-url", source.Config().ConnString()})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	var exported struct {
		Path   string               `json:"path"`
		Report threatarchive.Report `json:"archive"`
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
	cmd.SetArgs([]string{"verify-runtime-threat", "--in", exported.Path, "--verify-key", public})
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
	cmd.SetArgs([]string{"restore-runtime-threat", "--in", exported.Path, "--verify-key", public, "--org-id", destOrg.String(), "--cluster-id", destCluster.String(), "--database-url", dest.Config().ConnString()})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	var result threatarchive.RestoreResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.Inserted != 1 || result.OrgID != destOrg || result.ClusterID != destCluster {
		t.Fatalf("CLI restore: %+v %v", result, err)
	}
}
