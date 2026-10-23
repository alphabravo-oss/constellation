//go:build integration

package main

import (
	"flag"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/alphabravocompany/constellation/internal/auditarchive"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

func TestVerifyCLIWithDatabaseUnavailable(t *testing.T) {
	pool := pgtest.Pool(t)
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "private"), filepath.Join(dir, "public")
	if err := backup.GenerateEd25519Keypair(priv, pub); err != nil {
		t.Fatal(err)
	}
	if _, _, err := audit.New(pool).Log(t.Context(), audit.Event{Action: "cli.proof", ActorIP: net.ParseIP("10.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	c := auditarchive.Config{Bucket: "evidence", BatchSize: 1, DryRun: true, OutDir: filepath.Join(dir, "archive"), Signer: backup.SignerOptions{Mode: backup.SignModeStaticKey, KeyPath: priv}, Verifier: backup.VerifierOptions{Mode: backup.SignModeStaticKey, KeyPath: pub}}
	m, err := auditarchive.Run(t.Context(), pool, nil, c)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	t.Setenv("DATABASE_URL", "not-a-valid-database-url")
	t.Setenv("AWS_ENDPOINT_URL_S3", "not-an-endpoint")
	oldArgs, oldFlags := os.Args, flag.CommandLine
	defer func() { os.Args = oldArgs; flag.CommandLine = oldFlags }()
	args := []string{"audit-archiver", "--sign-mode=static-key", "--verify-key=" + pub,
		"--verify-manifest=" + filepath.Join(c.OutDir, filepath.Base(m.ManifestKey)),
		"--verify-archive=" + filepath.Join(c.OutDir, filepath.Base(m.ArchiveKey)),
		"--signature=" + filepath.Join(c.OutDir, filepath.Base(m.SignatureKey))}
	os.Args = args
	flag.CommandLine = flag.NewFlagSet("offline-verification", flag.ContinueOnError)
	if err = run(); err != nil {
		t.Fatalf("offline CLI required database or AWS: %v", err)
	}
	signature := filepath.Join(c.OutDir, filepath.Base(m.SignatureKey))
	if err = os.WriteFile(signature, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	flag.CommandLine = flag.NewFlagSet("offline-tampered", flag.ContinueOnError)
	if err = run(); err == nil {
		t.Fatal("CLI accepted corrupt signature")
	}
}
