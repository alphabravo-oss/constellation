// constellation-bootstrap creates the deployment organization. Human identities come from OIDC.
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		slog.Error("connect database")
		os.Exit(1)
	}
	defer pool.Close()
	org := os.Getenv("BOOTSTRAP_ORG")
	if org == "" {
		org = "default"
	}
	_, err = pool.Exec(ctx, `INSERT INTO orgs(name,display_name) VALUES($1,$1) ON CONFLICT(name) DO NOTHING`, org)
	if err != nil {
		slog.Error("create organization")
		os.Exit(1)
	}
}
