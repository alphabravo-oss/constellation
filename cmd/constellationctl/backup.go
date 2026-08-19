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
	"os/exec"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

func backupCmd() *cobra.Command {
	c := &cobra.Command{Use: "backup", Short: "Full-org backup / restore (Wave N5)"}
	c.AddCommand(backupCreateCmd(), backupListCmd(), backupRestoreCmd(), backupGenKeyCmd())
	return c
}

func backupCreateCmd() *cobra.Command {
	var (
		dbURL       string
		out         string
		s3URI       string
		orgName     string
		orgID       string
		signKey     string
		signKeyless bool
		verifyKey   string
	)
	c := &cobra.Command{
		Use:   "create",
		Short: "Create a signed full-org backup",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dbURL == "" {
				dbURL = os.Getenv("DATABASE_URL")
			}
			if dbURL == "" {
				return fmt.Errorf("--database-url or DATABASE_URL required")
			}
			if out == "" && s3URI == "" {
				return fmt.Errorf("--out or --s3 required")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
			defer cancel()

			pool, err := pgxpool.New(ctx, dbURL)
			if err != nil {
				return err
			}
			defer pool.Close()

			// Resolve org.
			id, name, err := resolveOrgCLI(ctx, pool, orgID, orgName)
			if err != nil {
				return err
			}

			signOpts := backup.SignerOptions{Mode: backup.SignModeNone}
			if signKeyless {
				signOpts.Mode = backup.SignModeKeyless
			} else if signKey != "" {
				signOpts.Mode = backup.SignModeStaticKey
				signOpts.KeyPath = signKey
			}

			outPath := out
			if outPath == "" {
				f, err := os.CreateTemp("", "constellation-backup-*.tar.gz")
				if err != nil {
					return err
				}
				_ = f.Close()
				outPath = f.Name()
			}
			usingTemp := out == ""
			hostname, _ := os.Hostname()
			res, err := backup.ExportToFile(ctx, pool, outPath, backup.ExportOptions{
				OrgID: id, OrgName: name,
				GeneratedBy: "constellationctl", SourceInstance: hostname,
				Sign: signOpts,
			})
			if err != nil {
				return err
			}
			if verifyKey != "" && (signOpts.Mode == backup.SignModeNone || signOpts.Mode == "") {
				return fmt.Errorf("--verify-key requires --sign-key or --sign-keyless")
			}
			if signOpts.Mode == backup.SignModeKeyless || (signOpts.Mode == backup.SignModeStaticKey && verifyKey != "") {
				if err := verifyCLIBackupAfterWrite(outPath, signOpts.Mode, verifyKey); err != nil {
					return fmt.Errorf("verify after write: %w", err)
				}
			}
			var objectURI string
			if s3URI != "" {
				objectURI, err = uploadCLIBackupToS3(ctx, s3URI, outPath, name)
				if err != nil {
					return fmt.Errorf("s3 upload: %w", err)
				}
			}
			// Record the backup row in the catalog so `backup list` and the UI see it.
			tables := make([]string, 0, len(res.Manifest.Tables))
			for _, t := range res.Manifest.Tables {
				tables = append(tables, t.Name)
			}
			localPath := any(outPath)
			if usingTemp && objectURI != "" {
				localPath = nil
			}
			_, _ = pool.Exec(ctx, `
INSERT INTO backups (id, org_id, mode, status, started_at, finished_at,
                     size_bytes, signed, signer_identity, format_version,
                     tables_included, local_path, s3_uri, object_uri)
VALUES (gen_random_uuid(), $1::uuid, 'org-backup', 'succeeded', NOW(), NOW(),
        $2, $3, $4, $5, $6, $7, $8, $9)`,
				id, res.Bytes, signOpts.Mode != backup.SignModeNone && signOpts.Mode != "",
				res.SignerIdentity, backup.FormatVersion, tables, localPath, nullableString(objectURI), nullableString(objectURI))
			if objectURI != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "uploaded %s (%d bytes)\n", objectURI, res.Bytes)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%d bytes)\n", outPath, res.Bytes)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "org=%s tables=%d root_hash=%s\n", name, len(res.Manifest.Tables), res.Manifest.RootHash)
			if res.SignerIdentity != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "signed by %s\n", res.SignerIdentity)
			}
			if signOpts.Mode == backup.SignModeKeyless || (signOpts.Mode == backup.SignModeStaticKey && verifyKey != "") {
				fmt.Fprintln(cmd.OutOrStdout(), "signature verified")
			}
			if usingTemp && objectURI != "" {
				_ = os.Remove(outPath)
			}
			return nil
		},
	}
	c.Flags().StringVar(&dbURL, "database-url", "", "Postgres URL (or DATABASE_URL)")
	c.Flags().StringVar(&out, "out", "", "Local file path for the tarball")
	c.Flags().StringVar(&s3URI, "s3", "", "s3://bucket/prefix destination uploaded with the AWS CLI")
	c.Flags().StringVar(&orgName, "org", "", "Org name to back up (default: only org)")
	c.Flags().StringVar(&orgID, "org-id", "", "Org UUID to back up")
	c.Flags().StringVar(&signKey, "sign-key", "", "PEM ed25519 private key for cosign-style signing")
	c.Flags().BoolVar(&signKeyless, "sign-keyless", false, "Use cosign keyless signing (Fulcio)")
	c.Flags().StringVar(&verifyKey, "verify-key", "", "Public key for verify-after-write")
	return c
}

func verifyCLIBackupAfterWrite(path string, mode backup.SignMode, verifyKey string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	manifestBytes, sig, cert, err := extractCLIManifestAndSig(f)
	if err != nil {
		return err
	}
	_, err = backup.Verify(manifestBytes, sig, cert, backup.VerifierOptions{Mode: mode, KeyPath: verifyKey})
	return err
}

func extractCLIManifestAndSig(r io.Reader) (manifest, sig, cert []byte, err error) {
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

func uploadCLIBackupToS3(ctx context.Context, dest, path, orgName string) (string, error) {
	uri, err := buildBackupS3URI(dest, orgName, time.Now().UTC())
	if err != nil {
		return "", err
	}
	if _, err := exec.LookPath("aws"); err != nil {
		return "", fmt.Errorf("aws CLI not in PATH")
	}
	cmd := exec.CommandContext(ctx, "aws", "s3", "cp", path, uri)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return uri, nil
}

func buildBackupS3URI(dest, orgName string, at time.Time) (string, error) {
	rest := strings.TrimPrefix(dest, "s3://")
	parts := strings.SplitN(rest, "/", 2)
	if rest == dest || parts[0] == "" {
		return "", fmt.Errorf("destination must be s3://bucket[/prefix]")
	}
	keyPrefix := ""
	if len(parts) == 2 {
		keyPrefix = strings.TrimSuffix(parts[1], "/") + "/"
	}
	stamp := at.UTC().Format(time.RFC3339)
	key := fmt.Sprintf("%sconstellation-backup-%s-%s.tar.gz", keyPrefix, orgName, stamp)
	return fmt.Sprintf("s3://%s/%s", parts[0], key), nil
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
				return listViaServer(cmd, server)
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
				return err
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
			fmt.Fprintf(cmd.OutOrStdout(), "%-36s %-12s %-10s %-10s %-12s %s\n", "ID", "MODE", "STATUS", "SIZE", "SIGNED", "WHEN")
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
				fmt.Fprintf(cmd.OutOrStdout(), "%-36s %-12s %-10s %-10d %-12s %s\n", id, mode, status, size, sgn, ts)
			}
			return nil
		},
	}
	c.Flags().StringVar(&dbURL, "database-url", "", "Postgres URL (or DATABASE_URL)")
	c.Flags().StringVar(&server, "server", "", "Constellation API URL (uses /api/v1/backups)")
	return c
}

func listViaServer(cmd *cobra.Command, server string) error {
	cfg, _ := loadConfig()
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(server, "/")+"/api/v1/backups", nil)
	if err != nil {
		return err
	}
	if cfg != nil && cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(cmd.OutOrStdout(), resp.Body)
	return nil
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
		RunE: func(cmd *cobra.Command, args []string) error {
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
			defer f.Close()
			pool, err := pgxpool.New(ctx, dbURL)
			if err != nil {
				return err
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
			fmt.Fprintf(cmd.OutOrStdout(), "Restored org=%s verified=%t signer=%s\n",
				res.Manifest.OrgName, res.Verified, res.SignerIdentity)
			for _, t := range res.Tables {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s: %d new / %d updated / %d skipped\n", t.Name, t.New, t.Updated, t.Skipped)
			}
			return nil
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
			if err := backup.GenerateEd25519Keypair(args[0], args[1]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (private, 0600) and %s (public, 0644)\n", args[0], args[1])
			return nil
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
