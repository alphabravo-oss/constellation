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
//  5. Verify explicit/keyless signatures on the pinned artifact before upload.
//  6. Confirm catalog success only after the selected output completes.
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
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/obslog"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

func main() {
	// Shared.
	mode := flag.String("mode", "org-backup", "org-backup | pg-dump")
	databaseURL := flag.String("database-url", "", "Postgres URL (or DATABASE_URL)")
	// pg-dump mode flags (legacy).
	bucket := flag.String("bucket", os.Getenv("BACKUP_BUCKET"), "S3 bucket (pg-dump mode)")
	prefix := flag.String("prefix", os.Getenv("BACKUP_PREFIX"), "S3 object key prefix (pg-dump mode)")
	endpoint := flag.String("endpoint", "", "S3 endpoint URL (or BACKUP_S3_ENDPOINT; MinIO-compatible)")
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

	provided := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	if !provided["database-url"] {
		*databaseURL = os.Getenv("DATABASE_URL")
	}
	if !provided["endpoint"] {
		*endpoint = os.Getenv("BACKUP_S3_ENDPOINT")
	}
	if err := validateSigningFlagPresence(*mode, *signKey, *verifyKey, provided); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

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

func validateSigningFlagPresence(mode, key, verify string, provided map[string]bool) error {
	if mode == "pg-dump" && (provided["sign-key"] || provided["sign-keyless"] || provided["verify-key"]) {
		return errors.New("signing and verification flags require --mode=org-backup")
	}
	if provided["sign-key"] && key == "" {
		return errors.New("--sign-key must not be empty")
	}
	if provided["verify-key"] && verify == "" {
		return errors.New("--verify-key must not be empty")
	}
	return nil
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

func runOrgBackup(ctx context.Context, logger *slog.Logger, databaseURL string, args orgBackupArgs) (resultErr error) {
	signMode, err := validateOrgBackupArgs(args)
	if err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return backup.CLIFailure("database configuration", err)
	}
	defer pool.Close()
	resolvedID, orgName, err := resolveOrg(ctx, pool, args.OrgID, args.OrgName)
	if err != nil {
		return backup.CLIFailure("organization lookup", err)
	}
	rowID := uuid.New()
	at := time.Now().UTC()
	outPath := args.OutPath
	var workspace *backup.CLIWorkspace
	if outPath == "" {
		workspace, err = backup.NewCLIWorkspace(orgName, rowID, at)
		if err != nil {
			return err
		}
		outPath = workspace.Path
		defer func() { resultErr = errors.Join(resultErr, workspace.Close()) }()
	}
	if _, err = pool.Exec(ctx, `INSERT INTO backups(id,org_id,status,mode,format_version,signed,local_path,started_at) VALUES($1,$2::uuid,'running','org-backup',$3,$4,$5,NOW())`, rowID, resolvedID, backup.FormatVersion, signMode != backup.SignModeNone, outPath); err != nil {
		return backup.CLIFailure("backup catalog creation", err)
	}
	hostname, _ := os.Hostname()
	res, err := backup.ExportToFile(ctx, pool, outPath, backup.ExportOptions{OrgID: resolvedID, OrgName: orgName, GeneratedBy: "constellation-backup", SourceInstance: hostname, Sign: backup.SignerOptions{Mode: signMode, KeyPath: args.SignKey}})
	if err != nil {
		return recordOrgBackupFailure(ctx, pool, rowID, "backup export", err)
	}
	file, err := backup.OpenArtifact(outPath)
	if err != nil {
		return recordOrgBackupFailure(ctx, pool, rowID, "backup artifact open", err)
	}
	defer func() { resultErr = errors.Join(resultErr, backup.CLIFailure("backup artifact close", file.Close())) }()
	if err = verifyRequestedOrgBackup(ctx, logger, file, args, signMode); err != nil {
		return recordOrgBackupFailure(ctx, pool, rowID, "backup verification", err)
	}
	sum, size, err := hashOpenedArtifact(file)
	if err != nil {
		return recordOrgBackupFailure(ctx, pool, rowID, "backup artifact hashing", err)
	}
	if workspace != nil {
		workspace.Preserve()
	} // Completed artifact survives uncertain upload/catalog acknowledgment.
	objectURI, err := uploadOrgBackup(ctx, args.S3URI, orgName, rowID, at, file, size)
	if err != nil {
		return errors.Join(recordOrgBackupFailure(ctx, pool, rowID, "backup S3 upload", err), fmt.Errorf("completed backup retained at %s", outPath))
	}
	receipt := standaloneBackupReceipt{ID: rowID, Path: outPath, URI: objectURI, SHA: sum, Size: size, Mode: signMode, Temporary: workspace != nil, Result: res}
	if err = receipt.record(ctx, pool); err != nil {
		return err
	}
	if workspace != nil && objectURI != "" {
		workspace.Discard()
	}
	logger.Info("backup recorded", slog.String("backup_id", rowID.String()), slog.String("sha256", sum), slog.Int64("size", size), slog.String("object_uri", objectURI))
	return nil
}

func recordOrgBackupFailure(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID, stage string, cause error) error {
	_, recordErr := pool.Exec(ctx, `UPDATE backups SET status='failed',error=$2,finished_at=NOW() WHERE id=$1`, id, stage+" failed")
	return errors.Join(backup.CLIFailure(stage, cause), backup.CLIFailure("backup failure catalog confirmation", recordErr))
}

type standaloneBackupReceipt struct {
	ID             uuid.UUID
	Path, URI, SHA string
	Size           int64
	Mode           backup.SignMode
	Temporary      bool
	Result         *backup.ExportResult
}

func (r standaloneBackupReceipt) record(ctx context.Context, pool *pgxpool.Pool) error {
	tables := make([]string, 0, len(r.Result.Manifest.Tables))
	for _, table := range r.Result.Manifest.Tables {
		tables = append(tables, table.Name)
	}
	local := any(r.Path)
	if r.Temporary && r.URI != "" {
		local = nil
	}
	tag, err := pool.Exec(ctx, `UPDATE backups SET status='succeeded',finished_at=NOW(),size_bytes=$2,sha256=$3,tables_included=$4,signer_identity=$5,signed=$6,s3_uri=$7,object_uri=$7,format_version=$8,local_path=$9 WHERE id=$1`, r.ID, r.Size, r.SHA, tables, r.Result.SignerIdentity, r.Mode != backup.SignModeNone, nullStr(r.URI), backup.FormatVersion, local)
	if err != nil || tag.RowsAffected() != 1 {
		return errors.Join(backup.CLIFailure("backup artifact created but catalog acknowledgment", err), fmt.Errorf("backup catalog success unconfirmed; backup_id=%s; retained_path=%s; object_uri=%s", r.ID, r.Path, r.URI))
	}
	return nil
}

func validateOrgBackupArgs(args orgBackupArgs) (backup.SignMode, error) {
	mode, err := backup.ValidateCLIBackupSigning(args.SignKey, args.SignKeyless, args.VerifyKey)
	if err != nil {
		return "", err
	}
	if args.OutPath == "" && args.S3URI == "" {
		return "", errors.New("--out or --s3 required for org-backup mode")
	}
	if args.S3URI != "" {
		if _, err = backup.S3ArtifactURI(args.S3URI, "validation"); err != nil {
			return "", err
		}
	}
	return mode, nil
}
func verifyRequestedOrgBackup(ctx context.Context, logger *slog.Logger, file *os.File, args orgBackupArgs, mode backup.SignMode) error {
	if mode != backup.SignModeKeyless && args.VerifyKey == "" {
		return nil
	}
	if err := verifyOpenedBackup(ctx, file, mode, args.VerifyKey); err != nil {
		return err
	}
	logger.Info("verify-after-write ok")
	return nil
}
func uploadOrgBackup(ctx context.Context, destination, name string, id uuid.UUID, at time.Time, file *os.File, size int64) (string, error) {
	if destination == "" {
		return "", nil
	}
	uri, err := backup.S3BackupURI(destination, name, id, at)
	if err != nil {
		return "", err
	}
	return uri, backup.UploadS3Artifact(ctx, uri, "", file, size)
}

func verifyOpenedBackup(ctx context.Context, file *os.File, mode backup.SignMode, key string) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	manifest, sig, cert, err := extractManifestAndSig(file)
	if err != nil {
		return err
	}
	_, err = backup.Verify(ctx, manifest, sig, cert, backup.VerifierOptions{Mode: mode, KeyPath: key})
	return err
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
	if err := rows.Err(); err != nil {
		return "", "", err
	}
	if len(ids) == 1 {
		return ids[0], names[0], nil
	}
	return "", "", fmt.Errorf("multi-org install (%d orgs); pass --org or --org-id", len(ids))
}

// extractManifestAndSig walks a tar.gz reader and returns the manifest + signature + cert
// raw bytes. Used by verify-after-write.
func extractManifestAndSig(r io.Reader) (manifest, sig, cert []byte, err error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { err = errors.Join(err, gz.Close()) }()
	limited := &io.LimitedReader{R: gz, N: (512 << 20) + 1}
	tr := tar.NewReader(limited)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, nil, err
		}
		if hdr.Size > 512<<20 {
			return nil, nil, nil, errors.New("backup signature inspection exceeds 512 MiB decompressed limit")
		}
		switch hdr.Name {
		case "manifest.json", "manifest.json.sig", "manifest.json.cert":
			buf, readErr := io.ReadAll(tr)
			if readErr != nil {
				return nil, nil, nil, readErr
			}
			switch hdr.Name {
			case "manifest.json":
				manifest = buf
			case "manifest.json.sig":
				sig = buf
			case "manifest.json.cert":
				cert = buf
			}
		}

	}
	if _, readErr := io.Copy(io.Discard, io.LimitReader(limited, (512<<20)+1)); readErr != nil {
		return nil, nil, nil, readErr
	}
	if limited.N == 0 {
		return nil, nil, nil, errors.New("backup signature inspection exceeds 512 MiB decompressed limit")
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

func runPgDumpMode(ctx context.Context, logger *slog.Logger, databaseURL, bucket, prefix, endpoint string, dryRun bool) (resultErr error) {
	if !dryRun && bucket == "" {
		return errors.New("--bucket required unless --dry-run")
	}
	id := uuid.New()
	at := time.Now().UTC()
	keyName := "constellation-" + at.Format("20060102T150405Z") + "-" + id.String() + ".dump"
	destination := ""
	var err error
	if !dryRun {
		if err = backup.ValidateS3Endpoint(endpoint); err != nil {
			return err
		}
		destination, err = backup.S3ArtifactURI("s3://"+bucket+"/"+prefix, keyName)
		if err != nil {
			return err
		}
	}
	workspace, err := backup.NewCLIWorkspace("database", id, at)
	if err != nil {
		return err
	}
	workspace.Path = filepath.Join(filepath.Dir(workspace.Path), keyName)
	defer func() { resultErr = errors.Join(resultErr, workspace.Close()) }()
	if err = runPgDump(ctx, databaseURL, workspace.Path); err != nil {
		return err
	}
	file, err := backup.OpenArtifact(workspace.Path)
	if err != nil {
		return backup.CLIFailure("completed dump open", err)
	}
	defer func() { resultErr = errors.Join(resultErr, backup.CLIFailure("dump close", file.Close())) }()
	hash, size, err := hashOpenedArtifact(file)
	if err != nil {
		return backup.CLIFailure("dump hashing", err)
	}
	logger.Info("dump complete", slog.String("sha256", hash), slog.Int64("size_bytes", size), slog.String("path", workspace.Path))
	if dryRun {
		workspace.Preserve()
		logger.Info("dry-run: not uploading")
		return nil
	}
	if err = backup.UploadS3Artifact(ctx, destination, endpoint, file, size); err != nil {
		workspace.Preserve()
		return errors.Join(err, fmt.Errorf("completed dump retained at %s", workspace.Path))
	}
	logger.Info("uploaded", slog.String("object_uri", destination))
	return nil
}

func runPgDump(ctx context.Context, databaseURL, outPath string) (resultErr error) {
	if _, err := exec.LookPath("pg_dump"); err != nil {
		return backup.CLIFailure("pg_dump lookup", err)
	}
	profile := filepath.Join(filepath.Dir(outPath), "pg_service.conf")
	env, err := pgDumpEnvironment(ctx, databaseURL, filepath.Dir(outPath))
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(profile); err != nil && !os.IsNotExist(err) {
			resultErr = errors.Join(resultErr, backup.CLIFailure("private database profile cleanup", err))
		}
	}()
	root, err := os.OpenRoot(filepath.Dir(outPath))
	if err != nil {
		return backup.CLIFailure("dump directory open", err)
	}
	defer func() { resultErr = errors.Join(resultErr, backup.CLIFailure("dump directory close", root.Close())) }()
	name := filepath.Base(outPath)
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return backup.CLIFailure("private dump creation", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, backup.CLIFailure("dump write close", file.Close()))
		if resultErr != nil {
			if removeErr := root.Remove(name); removeErr != nil && !os.IsNotExist(removeErr) {
				resultErr = errors.Join(resultErr, backup.CLIFailure("partial dump cleanup", removeErr))
			}
		}
	}()
	cmd := exec.CommandContext(ctx, "pg_dump", "--format=custom", "--no-owner", "--no-acl", "--compress=9", "--no-password", "--dbname=service=constellation_backup")
	cmd.Env = env
	cmd.Stdout = file
	cmd.Stderr = io.Discard
	if err = cmd.Run(); err != nil {
		return backup.CLIFailure("pg_dump execution", errors.Join(ctx.Err(), err))
	}
	if err = ctx.Err(); err != nil {
		return backup.CLIFailure("pg_dump cancellation", err)
	}
	if err = file.Sync(); err != nil {
		return backup.CLIFailure("dump synchronization", err)
	}
	info, err := file.Stat()
	if err != nil || info.Size() == 0 {
		return errors.New("pg_dump produced no complete artifact")
	}
	return nil
}

func hashOpenedArtifact(file *os.File) (string, int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, err := io.Copy(h, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
