//go:build e2etools

// Stand-alone audit-chain verifier. Calls pkg/audit.VerifyChain directly so we
// can demonstrate the chain-integrity story without depending on the running
// API binary (Wave H3 explicitly does not restart it). Prints "verified" or
// describes the first break.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

func main() {
	dburl := os.Getenv("DATABASE_URL")
	if dburl == "" {
		dburl = "postgres://constellation:constellation@localhost:5433/constellation?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dburl)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pool:", err)
		os.Exit(2)
	}
	defer pool.Close()

	br, err := audit.VerifyChain(ctx, pool)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if br == nil {
		_ = enc.Encode(map[string]any{"status": "verified"})
		return
	}
	_ = enc.Encode(map[string]any{
		"status":   "broken",
		"id":       br.ID,
		"reason":   br.Reason,
		"expected": br.Expected,
		"found":    br.Found,
	})
	os.Exit(1)
}
