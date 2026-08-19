//go:build e2etools

// Persist a gitops.drift.detected audit row referencing the declared / observed
// SHA pair the drift comparator produced.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

func main() {
	dburl := os.Getenv("DATABASE_URL")
	if dburl == "" {
		dburl = "postgres://constellation:constellation@localhost:5433/constellation?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dburl)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pool:", err)
		os.Exit(1)
	}
	defer pool.Close()
	org := uuid.MustParse("2ebae049-35c7-464c-b4b0-50cf185e5975")
	id, hash, err := audit.New(pool).Log(ctx, audit.Event{
		OrgID:      &org,
		Action:     "gitops.drift.detected",
		TargetKind: "rolebinding",
		TargetID:   "platform/platform-readers",
		After: map[string]any{
			"source":       "argocd",
			"application":  "platform-rbac",
			"declared_sha": "404eb2766e735bb79cc95bb3d0fe9bb8e2a0413405a333a75254999ce9143170",
			"observed_sha": "ee4e566bc2ad33e08342db450eb9d78bc38f689161f9de787466dd22d425eefe",
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit.Log:", err)
		os.Exit(1)
	}
	fmt.Printf("audit_id=%d chain_hash=%s\n", id, hash)
}
