package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	colcrypto "github.com/alphabravocompany/constellation/internal/crypto"
)

// adminCmd groups operator-only maintenance that talks to the database
// directly (no API): column-encryption key management.
func adminCmd() *cobra.Command {
	c := &cobra.Command{Use: "admin", Short: "Operator maintenance commands (direct database access)"}
	c.AddCommand(adminGenerateKeyCmd(), adminRotateKeysCmd())
	return c
}

func adminGenerateKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "generate-key",
		Short: "Mint a new age X25519 column-encryption key (prints the secret; the recipient is its key_id)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			secret, keyID, err := colcrypto.GenerateKey()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "# key_id: %s\n%s\n", keyID, secret)
			return nil
		},
	}
}

func adminRotateKeysCmd() *cobra.Command {
	var (
		databaseURL string
		dryRun      bool
		timeout     time.Duration
	)
	c := &cobra.Command{
		Use:   "rotate-keys",
		Short: "Re-seal every encrypted column under the current key (first key in CONSTELLATION_AGE_KEY/_FILE)",
		Long: `Reads the key set from CONSTELLATION_AGE_KEY or CONSTELLATION_AGE_KEY_FILE (current key
first, retired keys after it), finds rows whose key_id is not the current key, decrypts them
with the key their key_id names and re-encrypts them under the current key, one row per
transaction. Resumable: rerun until "rotated" is 0 for every table, then drop the retired
keys from the key set.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if databaseURL == "" {
				databaseURL = os.Getenv("DATABASE_URL")
			}
			if databaseURL == "" {
				return fmt.Errorf("--database-url or DATABASE_URL required")
			}
			enc, err := colcrypto.Default()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			pool, err := pgxpool.New(ctx, databaseURL)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer pool.Close()
			rep, err := colcrypto.Rotate(ctx, pool, enc, dryRun, slog.Default())
			for _, col := range colcrypto.Columns {
				fmt.Fprintf(cmd.OutOrStdout(), "%-22s rotated=%d skipped=%d failed=%d\n", col.Table, rep.Rotated[col.Table], rep.Skipped[col.Table], rep.Failed[col.Table])
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "current key_id: %s (dry_run=%v)\n", enc.KeyID(), dryRun)
			return nil
		},
	}
	c.Flags().StringVar(&databaseURL, "database-url", "", "Postgres DSN (default $DATABASE_URL)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "Report what would be re-sealed without writing")
	c.Flags().DurationVar(&timeout, "timeout", 30*time.Minute, "Overall deadline")
	return c
}
