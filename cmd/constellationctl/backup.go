// Backup subcommand. Calls the same library as the standalone constellation-backup +
// constellation-restore binaries so behaviour is identical regardless of entrypoint.
//
//	constellationctl backup create   --out=PATH | --s3=s3://...
//	                                 [--sign-key=PEM | --sign-keyless]
//	constellationctl backup list     [--server=URL] (defaults to local DB via --database-url)
//	constellationctl backup restore  PATH  [--verify-key=PEM] [--on-conflict=skip|overwrite]
//	constellationctl backup gen-key  PRIV.pem PUB.pem
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

func backupCmd() *cobra.Command {
	c := &cobra.Command{Use: "backup", Short: "Full-org backup / restore (Wave N5)"}
	c.AddCommand(backupCreateCmd(), backupListCmd(), backupRestoreCmd(), backupGenKeyCmd())
	return c
}

type cliBackupCreateOptions struct {
	dbURL, out, s3URI, orgName, orgID, signKey, verifyKey string
	signKeyless                                           bool
}

func backupCreateCmd() *cobra.Command {
	var args cliBackupCreateOptions
	c := &cobra.Command{Use: "create", Short: "Create a signed full-org backup", RunE: func(cmd *cobra.Command, _ []string) error { return args.run(cmd) }}
	c.Flags().StringVar(&args.dbURL, "database-url", "", "Postgres URL (or DATABASE_URL)")
	c.Flags().StringVar(&args.out, "out", "", "Local file path for the tarball")
	c.Flags().StringVar(&args.s3URI, "s3", "", "s3://bucket/prefix destination uploaded with the AWS CLI")
	c.Flags().StringVar(&args.orgName, "org", "", "Org name to back up (default: only org)")
	c.Flags().StringVar(&args.orgID, "org-id", "", "Org UUID to back up")
	c.Flags().StringVar(&args.signKey, "sign-key", "", "PEM ed25519 private key for cosign-style signing")
	c.Flags().BoolVar(&args.signKeyless, "sign-keyless", false, "Use cosign keyless signing (Fulcio)")
	c.Flags().StringVar(&args.verifyKey, "verify-key", "", "Public key for verify-after-write")
	return c
}

func (a *cliBackupCreateOptions) preflight(cmd *cobra.Command) (backup.SignMode, error) {
	if cmd.Flags().Changed("sign-key") && a.signKey == "" {
		return "", errors.New("--sign-key must not be empty")
	}
	if cmd.Flags().Changed("verify-key") && a.verifyKey == "" {
		return "", errors.New("--verify-key must not be empty")
	}
	mode, err := backup.ValidateCLIBackupSigning(a.signKey, a.signKeyless, a.verifyKey)
	if err != nil {
		return "", err
	}
	if a.s3URI != "" {
		if _, err = backup.S3ArtifactURI(a.s3URI, "validation"); err != nil {
			return "", err
		}
	}
	if a.dbURL == "" {
		a.dbURL = os.Getenv("DATABASE_URL")
	}
	if a.dbURL == "" {
		return "", errors.New("--database-url or DATABASE_URL required")
	}
	if a.out == "" && a.s3URI == "" {
		return "", errors.New("--out or --s3 required")
	}
	return mode, nil
}

func (a cliBackupCreateOptions) run(cmd *cobra.Command) (resultErr error) {
	mode, err := a.preflight(cmd)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, a.dbURL)
	if err != nil {
		return backup.CLIFailure("database configuration", err)
	}
	defer pool.Close()
	orgID, name, err := resolveOrgCLI(ctx, pool, a.orgID, a.orgName)
	if err != nil {
		return backup.CLIFailure("organization lookup", err)
	}
	rowID := uuid.New()
	at := time.Now().UTC()
	out := a.out
	var workspace *backup.CLIWorkspace
	if out == "" {
		workspace, err = backup.NewCLIWorkspace(name, rowID, at)
		if err != nil {
			return err
		}
		out = workspace.Path
		defer func() { resultErr = errors.Join(resultErr, workspace.Close()) }()
	}
	hostname, _ := os.Hostname()
	res, err := backup.ExportToFile(ctx, pool, out, backup.ExportOptions{OrgID: orgID, OrgName: name, GeneratedBy: "constellationctl", SourceInstance: hostname, Sign: backup.SignerOptions{Mode: mode, KeyPath: a.signKey}})
	if err != nil {
		return backup.CLIFailure("backup export", err)
	}
	artifact, err := backup.OpenArtifact(out)
	if err != nil {
		return backup.CLIFailure("backup artifact open", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, backup.CLIFailure("backup artifact close", artifact.Close()))
	}()
	if err = a.verify(ctx, artifact, mode); err != nil {
		return err
	}
	if workspace != nil {
		workspace.Preserve()
	}
	uri, err := a.upload(ctx, name, rowID, at, artifact, res.Bytes)
	if err != nil {
		return errors.Join(err, fmt.Errorf("completed backup retained at %s", out))
	}
	receipt := cliBackupReceipt{ID: rowID, OrgID: orgID, Out: out, URI: uri, Temporary: workspace != nil, Mode: mode, Result: res}
	if err = receipt.record(ctx, pool); err != nil {
		return err
	}
	if workspace != nil && uri != "" {
		workspace.Discard()
	}
	return receipt.print(cmd, name, a.verifyKey != "")
}

func (a cliBackupCreateOptions) verify(ctx context.Context, file *os.File, mode backup.SignMode) error {
	if mode != backup.SignModeKeyless && a.verifyKey == "" {
		return nil
	}
	return backup.CLIFailure("backup verification", verifyOpenedCLIBackup(ctx, file, mode, a.verifyKey))
}
func (a cliBackupCreateOptions) upload(ctx context.Context, name string, id uuid.UUID, at time.Time, file *os.File, size int64) (string, error) {
	if a.s3URI == "" {
		return "", nil
	}
	uri, err := buildBackupS3URI(a.s3URI, name, at, id)
	if err != nil {
		return "", err
	}
	return uri, backup.UploadS3Artifact(ctx, uri, "", file, size)
}

type cliBackupReceipt struct {
	ID              uuid.UUID
	OrgID, Out, URI string
	Temporary       bool
	Mode            backup.SignMode
	Result          *backup.ExportResult
}

func (r cliBackupReceipt) record(ctx context.Context, pool *pgxpool.Pool) error {
	tables := make([]string, 0, len(r.Result.Manifest.Tables))
	for _, table := range r.Result.Manifest.Tables {
		tables = append(tables, table.Name)
	}
	local := any(r.Out)
	if r.Temporary && r.URI != "" {
		local = nil
	}
	_, err := pool.Exec(ctx, `
INSERT INTO backups (id, org_id, mode, status, started_at, finished_at,
                     size_bytes, signed, signer_identity, format_version,
                     tables_included, local_path, s3_uri, object_uri)
VALUES ($10, $1::uuid, 'org-backup', 'succeeded', NOW(), NOW(),
        $2, $3, $4, $5, $6, $7, $8, $9)`, r.OrgID, r.Result.Bytes, r.Mode != backup.SignModeNone, r.Result.SignerIdentity, backup.FormatVersion, tables, local, nullableString(r.URI), nullableString(r.URI), r.ID)
	if err != nil {
		return errors.Join(backup.CLIFailure("backup artifact created but catalog acknowledgment", err), fmt.Errorf("backup catalog success unconfirmed; backup_id=%s; retained_path=%s; object_uri=%s", r.ID, r.Out, r.URI))
	}
	return nil
}
func (r cliBackupReceipt) print(cmd *cobra.Command, name string, explicitVerify bool) error {
	output := &commandOutput{ctx: cmd.Context(), writer: cmd.OutOrStdout()}
	if r.URI != "" {
		output.printf("uploaded %s (%d bytes)\n", r.URI, r.Result.Bytes)
	} else {
		output.printf("wrote %s (%d bytes)\n", r.Out, r.Result.Bytes)
	}
	output.printf("org=%s tables=%d root_hash=%s\n", name, len(r.Result.Manifest.Tables), r.Result.Manifest.RootHash)
	if r.Result.SignerIdentity != "" {
		output.printf("signed by %s\n", r.Result.SignerIdentity)
	}
	if r.Mode == backup.SignModeKeyless || explicitVerify {
		output.println("signature verified")
	}
	return output.result()
}

func verifyOpenedCLIBackup(ctx context.Context, file *os.File, mode backup.SignMode, key string) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	manifest, sig, cert, err := extractCLIManifestAndSig(file)
	if err != nil {
		return err
	}
	_, err = backup.Verify(ctx, manifest, sig, cert, backup.VerifierOptions{Mode: mode, KeyPath: key})
	return err
}

func extractCLIManifestAndSig(r io.Reader) (manifest, sig, cert []byte, err error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { err = errors.Join(err, gz.Close()) }()
	limited := &io.LimitedReader{R: gz, N: (512 << 20) + 1}
	tr := tar.NewReader(limited)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
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

func buildBackupS3URI(dest, orgName string, at time.Time, id uuid.UUID) (string, error) {
	return backup.S3BackupURI(dest, orgName, id, at)
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func backupListCmd() *cobra.Command {
	var dbURL, server string
	c := &cobra.Command{
		Use:   "list",
		Short: "List recorded backups",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if server != "" {
				return listViaServer(cmd.Context(), server, cmd.OutOrStdout())
			}
			if dbURL == "" {
				dbURL = os.Getenv("DATABASE_URL")
			}
			if dbURL == "" {
				return fmt.Errorf("--database-url or DATABASE_URL or --server required")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()
			pool, err := pgxpool.New(ctx, dbURL)
			if err != nil {
				return backup.CLIFailure("database configuration", err)
			}
			defer pool.Close()
			rows, err := pool.Query(ctx, `
SELECT id, COALESCE(mode,'org-backup'), status, COALESCE(format_version,''),
       COALESCE(signed,false), COALESCE(signer_identity,''),
       COALESCE(size_bytes,0), COALESCE(s3_uri,''), COALESCE(local_path,''),
       started_at, finished_at
  FROM backups
 ORDER BY started_at DESC LIMIT 50`)
			if err != nil {
				return err
			}
			defer rows.Close()
			output := &commandOutput{ctx: cmd.Context(), writer: cmd.OutOrStdout()}
			output.printf("%-36s %-12s %-10s %-10s %-12s %s\n", "ID", "MODE", "STATUS", "SIZE", "SIGNED", "WHEN")
			if err := output.result(); err != nil {
				return err
			}
			for rows.Next() {
				var id, mode, status, fmtVer, signer, s3uri, lp string
				var signed bool
				var size int64
				var started, finished interface{}
				if err := rows.Scan(&id, &mode, &status, &fmtVer, &signed, &signer, &size, &s3uri, &lp, &started, &finished); err != nil {
					return err
				}
				ts := ""
				if t, ok := started.(time.Time); ok {
					ts = t.Format(time.RFC3339)
				}
				sgn := "no"
				if signed {
					sgn = "yes"
				}
				output.printf("%-36s %-12s %-10s %-10d %-12s %s\n", id, mode, status, size, sgn, ts)
				if err := output.result(); err != nil {
					return err
				}
			}
			return rows.Err()
		},
	}
	c.Flags().StringVar(&dbURL, "database-url", "", "Postgres URL (or DATABASE_URL)")
	c.Flags().StringVar(&server, "server", "", "Constellation API URL (uses /api/v1/backups)")
	return c
}

func listViaServer(ctx context.Context, server string, out io.Writer) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(server, "/")+"/api/v1/backups", nil)
	if err != nil {
		return err
	}
	if cfg != nil && cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	resp, err := newAPIClient().Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.Join(fmt.Errorf("list backups: server returned %d", resp.StatusCode), resp.Body.Close())
	}
	// Preserve the configured Write contract rather than an embedded ReaderFrom
	// implementation that can bypass an output wrapper's failure handling.
	_, err = io.Copy(struct{ io.Writer }{out}, resp.Body)
	return errors.Join(err, resp.Body.Close(), ctx.Err())
}

func backupRestoreCmd() *cobra.Command {
	var (
		dbURL           string
		verifyKey       string
		allowUnverified bool
		onConflict      string
	)
	c := &cobra.Command{
		Use:   "restore <path>",
		Short: "Restore a backup tarball into the destination database",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (resultErr error) {
			path := args[0]
			if dbURL == "" {
				dbURL = os.Getenv("DATABASE_URL")
			}
			if dbURL == "" {
				return fmt.Errorf("--database-url or DATABASE_URL required")
			}
			policy := backup.ConflictPolicy(onConflict)
			if policy != backup.ConflictSkip && policy != backup.ConflictOverwrite {
				return fmt.Errorf("--on-conflict must be skip|overwrite")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
			defer cancel()

			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
			pool, err := pgxpool.New(ctx, dbURL)
			if err != nil {
				return backup.CLIFailure("database configuration", err)
			}
			defer pool.Close()

			mode := backup.SignModeNone
			if verifyKey != "" {
				mode = backup.SignModeStaticKey
			}
			res, err := backup.Restore(ctx, pool, backup.RestoreOptions{
				In:              f,
				Verify:          backup.VerifierOptions{Mode: mode, KeyPath: verifyKey},
				AllowUnverified: allowUnverified,
				OnConflict:      policy,
			})
			if err != nil {
				return err
			}
			output := &commandOutput{ctx: cmd.Context(), writer: cmd.OutOrStdout()}
			output.printf("Restored org=%s verified=%t signer=%s\n",
				res.Manifest.OrgName, res.Verified, res.SignerIdentity)
			for _, t := range res.Tables {
				output.printf("  %s: %d new / %d updated / %d skipped\n", t.Name, t.New, t.Updated, t.Skipped)
			}
			return output.result()
		},
	}
	c.Flags().StringVar(&dbURL, "database-url", "", "Postgres URL (or DATABASE_URL)")
	c.Flags().StringVar(&verifyKey, "verify-key", "", "PEM public key for verification (static-key)")
	c.Flags().BoolVar(&allowUnverified, "allow-unverified", false, "DEV ONLY: skip signature verification")
	c.Flags().StringVar(&onConflict, "on-conflict", "skip", "skip | overwrite")
	return c
}

func backupGenKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gen-key <priv.pem> <pub.pem>",
		Short: "Generate a cosign-compatible ed25519 keypair for signing backups",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			if err := backup.GenerateEd25519Keypair(args[0], args[1]); err != nil {
				return err
			}
			output := &commandOutput{ctx: cmd.Context(), writer: cmd.OutOrStdout()}
			output.printf("wrote %s (private, 0600) and %s (public, 0644)\n", args[0], args[1])
			return output.result()
		},
	}
}

// resolveOrgCLI mirrors the standalone-binary org resolver. Returns (id, name).
func resolveOrgCLI(ctx context.Context, pool *pgxpool.Pool, idArg, nameArg string) (string, string, error) {
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

// JSON-decoder helper used elsewhere in the file in the future.
var _ = json.NewDecoder
