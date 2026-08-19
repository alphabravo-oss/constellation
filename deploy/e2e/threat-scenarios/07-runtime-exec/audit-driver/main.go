//go:build e2etools

// Persist a runtime.alert.exec audit row tagged with MITRE ATT&CK techniques.
// Called from scenario 07's run.sh once the synthetic `kubectl exec` has fired
// the actual process events on the host's eBPF data plane.
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
	pod := os.Getenv("TARGET_POD")
	if pod == "" {
		pod = "unknown"
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
		Action:     "runtime.alert.exec",
		TargetKind: "pod",
		TargetID:   "edge/" + pod,
		After: map[string]any{
			"comm":     "bash",
			"argv":     "id && whoami && head -3 /etc/passwd",
			"mitre":    []string{"T1059.004", "T1018", "T1083"},
			"severity": "high",
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit.Log:", err)
		os.Exit(1)
	}
	fmt.Printf("audit_id=%d chain_hash=%s\n", id, hash)
}
