// constellation-restore applies a signed Constellation org-backup tarball to a Postgres
// instance.
//
// Typical usage:
//
//	constellation-restore --in=backup.tar.gz --database-url=postgres://... \
//	    --verify-key=cosign.pub --on-conflict=skip
//
// Modes for verification:
//   --verify-key=<pubkey.pem>  (static-key)
//   (default keyless)           when manifest.json.cert is present in the tarball;
//                               cosign must be on PATH.
//   --allow-unverified         to skip signature checks (DEV ONLY).
//
// Conflict policy:
//   --on-conflict=skip          (default) preserve existing rows.
//   --on-conflict=overwrite     update existing rows from the tarball.
//
// The restorer applies tables in dependency order: orgs -> clusters -> deployments / assets
// -> per-org tables (policies, groups, etc) -> audit_events_recent. FK columns are remapped
// to the destination org's UUID by (org_name) match; existing rows are detected via the
// table's natural-key UNIQUE constraint.
//
// Per-table progress is printed to stdout in the form:
//   clusters:  3 new / 0 updated / 2 skipped
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

func main() {
	inPath := flag.String("in", "", "Path to constellation-backup-*.tar.gz")
	dbURL := flag.String("database-url", os.Getenv("DATABASE_URL"), "Destination Postgres URL")
	server := flag.String("server", "", "Constellation API URL (alternative to --database-url; uploads + applies via API)")
	token := flag.String("token", os.Getenv("CONSTELLATION_TOKEN"), "Bearer token for --server mode")
	verifyKey := flag.String("verify-key", "", "PEM public key for static-key signature verification")
	allowUnverified := flag.Bool("allow-unverified", false, "DEV ONLY: skip signature verification")
	onConflict := flag.String("on-conflict", "skip", "skip | overwrite")
	flag.Parse()

	if *inPath == "" {
		fmt.Fprintln(os.Stderr, "--in required")
		os.Exit(2)
	}
	if *dbURL == "" && *server == "" {
		fmt.Fprintln(os.Stderr, "either --database-url or --server required")
		os.Exit(2)
	}
	policy := backup.ConflictPolicy(*onConflict)
	if policy != backup.ConflictSkip && policy != backup.ConflictOverwrite {
		fmt.Fprintln(os.Stderr, "invalid --on-conflict; want skip|overwrite")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if *server != "" {
		if err := runServerMode(*server, *token, *inPath); err != nil {
			fmt.Fprintln(os.Stderr, "server restore failed:", err)
			os.Exit(1)
		}
		return
	}

	if err := runLocalRestore(ctx, *dbURL, *inPath, *verifyKey, *allowUnverified, policy); err != nil {
		fmt.Fprintln(os.Stderr, "restore failed:", err)
		os.Exit(1)
	}
}

func runLocalRestore(ctx context.Context, dbURL, inPath, verifyKey string, allowUnverified bool, policy backup.ConflictPolicy) error {
	f, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", inPath, err)
	}
	defer f.Close()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("pg connect: %w", err)
	}
	defer pool.Close()

	verifierMode := backup.SignModeNone
	if verifyKey != "" {
		verifierMode = backup.SignModeStaticKey
	}
	// If verifyKey is empty and not allow-unverified, we'll let Restore auto-detect
	// keyless mode from the tarball contents and call cosign if available.

	res, err := backup.Restore(ctx, pool, backup.RestoreOptions{
		In:              f,
		Verify:          backup.VerifierOptions{Mode: verifierMode, KeyPath: verifyKey},
		AllowUnverified: allowUnverified,
		OnConflict:      policy,
	})
	if err != nil {
		return err
	}

	fmt.Printf("Restored backup of org %q (id=%s).\n", res.Manifest.OrgName, res.Manifest.OrgID)
	if res.Verified {
		fmt.Printf("Signature: OK (signer=%s)\n", res.SignerIdentity)
	} else if !allowUnverified {
		fmt.Println("Signature: NOT verified")
	} else {
		fmt.Println("Signature: skipped (--allow-unverified)")
	}
	fmt.Println("\nPer-table summary:")
	max := 0
	for _, t := range res.Tables {
		if len(t.Name) > max {
			max = len(t.Name)
		}
	}
	for _, t := range res.Tables {
		pad := strings.Repeat(" ", max-len(t.Name))
		fmt.Printf("  %s%s : %d new / %d updated / %d skipped\n", t.Name, pad, t.New, t.Updated, t.Skipped)
	}
	return nil
}

// runServerMode uploads the tarball to a running Constellation API and asks it to apply.
// Endpoint: POST /api/v1/backups/restore (multipart form). Used by `constellationctl backup
// restore` when DATABASE_URL isn't reachable from the operator's laptop.
func runServerMode(server, token, inPath string) error {
	f, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer f.Close()
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(server, "/")+"/api/v1/backups/restore", f)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	var out backup.RestoreResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	fmt.Printf("Restored on %s: org=%s\n", server, out.Manifest.OrgName)
	for _, t := range out.Tables {
		fmt.Printf("  %s: %d new / %d updated / %d skipped\n", t.Name, t.New, t.Updated, t.Skipped)
	}
	return nil
}
