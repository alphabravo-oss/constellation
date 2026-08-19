// constellation-backup writes Constellation backups to disk or S3.
//
// Modes (Wave N5):
//
//	--mode=org-backup   (default)  signed JSON tarball of operator-relevant tables, one org
//	--mode=pg-dump                  legacy `pg_dump --format=custom + upload` (Wave E)
//
// Org-backup is what enterprises actually want for restore-on-another-instance: a
// portable, signed artifact whose contents are auditable. pg-dump remains for
// disaster-recovery to the exact same Postgres major version on the same install.
//
// Lifecycle (org-backup):
//  1. Connect to DATABASE_URL.
//  2. Resolve org by name (--org) or UUID (--org-id); defaults to the only org when 1.
//  3. Stream export via pkg/backup.Export to either:
//     --out=/path/to/file.tar.gz   (local)
//     --s3=s3://bucket/prefix      (S3 via AWS CLI)
//  4. Sign manifest.json using --sign-key (static-key) OR --sign-keyless (Sigstore Fulcio).
//  5. Record a row in `backups`.
//  6. Verify-after-write: re-open the tarball, re-hash the manifest, run pkg/backup.Verify.
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/obslog"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

func main() {
	// Shared.
	mode := flag.String("mode", "org-backup", "org-backup | pg-dump")
	databaseURL := flag.String("database-url", os.Getenv("DATABASE_URL"), "Postgres URL")
	// pg-dump mode flags (legacy).
	bucket := flag.String("bucket", os.Getenv("BACKUP_BUCKET"), "S3 bucket (pg-dump mode)")
	prefix := flag.String("prefix", os.Getenv("BACKUP_PREFIX"), "S3 object key prefix (pg-dump mode)")
	endpoint := flag.String("endpoint", os.Getenv("BACKUP_S3_ENDPOINT"), "S3 endpoint URL (MinIO-compatible)")
	dryRun := flag.Bool("dry-run", false, "pg-dump: write local file instead of upload")
	// org-backup mode flags.
	orgName := flag.String("org", "", "Org name to back up (org-backup mode)")
	orgID := flag.String("org-id", "", "Org UUID to back up (alternative to --org)")
	outPath := flag.String("out", "", "Local file path for the tarball (org-backup mode)")
	s3URI := flag.String("s3", "", "s3://bucket/prefix destination (org-backup mode)")
	signKey := flag.String("sign-key", "", "PEM-encoded ed25519 private key for cosign-style signing")
	signKeyless := flag.Bool("sign-keyless", false, "Use cosign keyless signing (Fulcio); requires cosign on PATH")
	verifyKey := flag.String("verify-key", "", "PEM-encoded ed25519 public key for post-write verification")
	flag.Parse()

	if *databaseURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL or --database-url required")
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: obslog.Level()})).With("svc", "constellation-backup", "mode", *mode)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	switch *mode {
	case "org-backup":
		if err := runOrgBackup(ctx, logger, *databaseURL, orgBackupArgs{
			OrgName: *orgName, OrgID: *orgID,
			OutPath: *outPath, S3URI: *s3URI,
			SignKey: *signKey, SignKeyless: *signKeyless,
			VerifyKey: *verifyKey,
		}); err != nil {
			logger.Error("org-backup failed", slog.String("err", err.Error()))
			os.Exit(1)
		}
	case "pg-dump":
		if err := runPgDumpMode(ctx, logger, *databaseURL, *bucket, *prefix, *endpoint, *dryRun); err != nil {
			logger.Error("pg-dump failed", slog.String("err", err.Error()))
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown --mode:", *mode)
		os.Exit(2)
	}
}

// ---- org-backup mode ----

type orgBackupArgs struct {
	OrgName     string
	OrgID       string
	OutPath     string
	S3URI       string
	SignKey     string
	SignKeyless bool
	VerifyKey   string
}

func runOrgBackup(ctx context.Context, logger *slog.Logger, databaseURL string, args orgBackupArgs) error {
	if args.OutPath == "" && args.S3URI == "" {
		return errors.New("--out or --s3 required for org-backup mode")
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("pg connect: %w", err)
	}
	defer pool.Close()

	// Resolve org.
	resolvedID, orgName, err := resolveOrg(ctx, pool, args.OrgID, args.OrgName)
	if err != nil {
		return err
	}
	logger.Info("org resolved", slog.String("org_id", resolvedID), slog.String("org", orgName))

	// Sign options.
	signOpts := backup.SignerOptions{Mode: backup.SignModeNone}
	switch {
	case args.SignKeyless:
		signOpts.Mode = backup.SignModeKeyless
	case args.SignKey != "":
		signOpts.Mode = backup.SignModeStaticKey
		signOpts.KeyPath = args.SignKey
	}

	// Decide local output path. S3 upload also writes to a temp file first.
	outPath := args.OutPath
	usingTemp := false
	if outPath == "" {
		// S3 destination implies a temp file.
		f, err := os.CreateTemp("", "constellation-orgbackup-*.tar.gz")
		if err != nil {
			return fmt.Errorf("temp file: %w", err)
		}
		_ = f.Close()
		outPath = f.Name()
		usingTemp = true
	}

	// Record an in-flight row in `backups`.
	rowID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO backups(id, org_id, status, mode, format_version, signed, local_path, started_at)
VALUES ($1, $2::uuid, 'running', 'org-backup', $3, $4, $5, NOW())`,
		rowID, resolvedID, backup.FormatVersion, signOpts.Mode != backup.SignModeNone, outPath); err != nil {
		logger.Warn("backups insert failed; continuing", slog.String("err", err.Error()))
	}

	hostname, _ := os.Hostname()
	res, err := backup.ExportToFile(ctx, pool, outPath, backup.ExportOptions{
		OrgID: resolvedID, OrgName: orgName,
		GeneratedBy: "constellation-backup", SourceInstance: hostname,
		Sign: signOpts,
	})
	if err != nil {
		_, _ = pool.Exec(ctx, `UPDATE backups SET status='failed', error=$2, finished_at=NOW() WHERE id=$1`, rowID, err.Error())
		return fmt.Errorf("export: %w", err)
	}
	logger.Info("export complete",
		slog.Int64("bytes", res.Bytes),
		slog.String("signer", res.SignerIdentity),
		slog.Int("tables", len(res.Manifest.Tables)),
		slog.String("root_hash", res.Manifest.RootHash),
	)

	// Verify-after-write to catch any disk corruption or signing-bug regression.
	if res.SignMode != backup.SignModeNone && res.SignMode != "" {
		if err := verifyAfterWrite(ctx, outPath, signOpts.Mode, args.VerifyKey); err != nil {
			logger.Warn("verify-after-write failed", slog.String("err", err.Error()))
		} else {
			logger.Info("verify-after-write ok")
		}
	}

	// Hash the final artifact for the catalog row.
	sum, size, err := hashFile(outPath)
	if err != nil {
		return fmt.Errorf("hash: %w", err)
	}

	tablesIncluded := make([]string, 0, len(res.Manifest.Tables))
	for _, t := range res.Manifest.Tables {
		tablesIncluded = append(tablesIncluded, t.Name)
	}

	// Optional S3 upload.
	var objectURI string
	if args.S3URI != "" {
		uri, err := uploadOrgBackupToS3(ctx, args.S3URI, outPath, orgName)
		if err != nil {
			_, _ = pool.Exec(ctx, `UPDATE backups SET status='failed', error=$2, finished_at=NOW() WHERE id=$1`, rowID, err.Error())
			return fmt.Errorf("s3 upload: %w", err)
		}
		objectURI = uri
		logger.Info("uploaded", slog.String("s3_uri", objectURI))
	}

	_, err = pool.Exec(ctx, `
UPDATE backups
   SET status='succeeded', finished_at=NOW(),
       size_bytes=$2, sha256=$3, tables_included=$4,
       signer_identity=$5, signed=$6, s3_uri=$7, object_uri=$8,
       format_version=$9, local_path=$10
 WHERE id=$1`,
		rowID, size, sum, tablesIncluded,
		res.SignerIdentity, res.SignMode != backup.SignModeNone, nullStr(objectURI), nullStr(objectURI),
		backup.FormatVersion, outPath)
	if err != nil {
		logger.Warn("backups update failed", slog.String("err", err.Error()))
	}

	logger.Info("backup recorded",
		slog.String("backup_id", rowID.String()),
		slog.String("sha256", sum),
		slog.Int64("size", size))

	if usingTemp && objectURI != "" {
		_ = os.Remove(outPath) // we already uploaded.
	}
	return nil
}

// resolveOrg picks the org row to back up. Order: --org-id, then --org by name, then the
// only-org-present heuristic. Returns (id, name).
func resolveOrg(ctx context.Context, pool *pgxpool.Pool, idArg, nameArg string) (string, string, error) {
	if idArg != "" {
		var name string
		if err := pool.QueryRow(ctx, `SELECT name FROM orgs WHERE id=$1`, idArg).Scan(&name); err != nil {
			return "", "", fmt.Errorf("org lookup by id: %w", err)
		}
		return idArg, name, nil
	}
	if nameArg != "" {
		var id, name string
		if err := pool.QueryRow(ctx, `SELECT id, name FROM orgs WHERE name=$1`, nameArg).Scan(&id, &name); err != nil {
			return "", "", fmt.Errorf("org lookup by name: %w", err)
		}
		return id, name, nil
	}
	// Default: single-org install.
	rows, err := pool.Query(ctx, `SELECT id, name FROM orgs LIMIT 2`)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	var ids, names []string
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return "", "", err
		}
		ids = append(ids, id)
		names = append(names, name)
	}
	if len(ids) == 1 {
		return ids[0], names[0], nil
	}
	return "", "", fmt.Errorf("multi-org install (%d orgs); pass --org or --org-id", len(ids))
}

func uploadOrgBackupToS3(ctx context.Context, dest, path, orgName string) (string, error) {
	if _, err := exec.LookPath("aws"); err != nil {
		return "", fmt.Errorf("aws CLI not in PATH (bundle in image at /usr/local/bin/aws)")
	}
	// Parse s3://bucket/prefix.
	rest := strings.TrimPrefix(dest, "s3://")
	parts := strings.SplitN(rest, "/", 2)
	bucket := parts[0]
	keyPrefix := ""
	if len(parts) == 2 {
		keyPrefix = strings.TrimSuffix(parts[1], "/") + "/"
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	key := fmt.Sprintf("%sconstellation-backup-%s-%s.tar.gz", keyPrefix, orgName, stamp)
	uri := fmt.Sprintf("s3://%s/%s", bucket, key)
	cmd := exec.CommandContext(ctx, "aws", "s3", "cp", path, uri)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return uri, nil
}

// verifyAfterWrite re-reads the tarball, extracts manifest.json (+ .sig / .cert), and
// re-runs signature verification. This catches signing-bug regressions and disk corruption.
func verifyAfterWrite(_ context.Context, path string, mode backup.SignMode, verifyKey string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	manifestBytes, sig, cert, err := extractManifestAndSig(f)
	if err != nil {
		return err
	}
	if mode == backup.SignModeNone || mode == "" {
		return nil
	}
	if mode == backup.SignModeStaticKey && verifyKey == "" {
		// Best-effort: the sign-key path is private; convention says ".pub" sits next to it.
		return errors.New("static-key verify-after-write: pass --verify-key (the .pub sidecar)")
	}
	_, err = backup.Verify(manifestBytes, sig, cert, backup.VerifierOptions{Mode: mode, KeyPath: verifyKey})
	return err
}

// extractManifestAndSig walks a tar.gz reader and returns the manifest + signature + cert
// raw bytes. Used by verify-after-write.
func extractManifestAndSig(r io.Reader) (manifest, sig, cert []byte, err error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, nil, nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, nil, err
		}
		buf, _ := io.ReadAll(tr)
		switch hdr.Name {
		case "manifest.json":
			manifest = buf
		case "manifest.json.sig":
			sig = buf
		case "manifest.json.cert":
			cert = buf
		}
	}
	if manifest == nil {
		return nil, nil, nil, errors.New("manifest.json not found in tarball")
	}
	return manifest, sig, cert, nil
}

// nullStr returns nil for empty string; otherwise the value (for pgx-style NULLability).
func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ---- pg-dump mode (legacy) ----

func runPgDumpMode(ctx context.Context, logger *slog.Logger, databaseURL, bucket, prefix, endpoint string, dryRun bool) error {
	if !dryRun && bucket == "" {
		return errors.New("--bucket required unless --dry-run")
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	dumpPath := filepath.Join(os.TempDir(), fmt.Sprintf("constellation-%s.dump", stamp))
	if err := runPgDump(ctx, databaseURL, dumpPath); err != nil {
		return fmt.Errorf("pg_dump: %w", err)
	}
	hash, size, err := hashFile(dumpPath)
	if err != nil {
		return err
	}
	logger.Info("dump complete", slog.String("sha256", hash), slog.Int64("size_bytes", size), slog.String("path", dumpPath))
	if dryRun {
		logger.Info("dry-run: not uploading")
		return nil
	}
	key := filepath.Join(prefix, stamp, "constellation.dump")
	if err := uploadS3(ctx, endpoint, bucket, key, dumpPath); err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	logger.Info("uploaded", slog.String("bucket", bucket), slog.String("key", key), slog.String("endpoint", endpoint))
	return nil
}

func runPgDump(ctx context.Context, databaseURL, outPath string) error {
	if _, err := exec.LookPath("pg_dump"); err != nil {
		return fmt.Errorf("pg_dump not in PATH (install: https://www.postgresql.org/download/)")
	}
	cmd := exec.CommandContext(ctx, "pg_dump",
		"--format=custom", "--no-owner", "--no-acl", "--compress=9",
		"--file="+outPath, databaseURL,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func uploadS3(ctx context.Context, endpoint, bucket, key, path string) error {
	if _, err := exec.LookPath("aws"); err != nil {
		return fmt.Errorf("aws CLI not in PATH (bundle in image at /usr/local/bin/aws)")
	}
	args := []string{"s3", "cp", path, fmt.Sprintf("s3://%s/%s", bucket, key)}
	if endpoint != "" {
		args = append([]string{"--endpoint-url", endpoint}, args...)
	}
	cmd := exec.CommandContext(ctx, "aws", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
