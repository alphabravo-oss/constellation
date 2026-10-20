//go:build integration

package handler

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	migrationset "github.com/alphabravocompany/constellation/internal/server/database"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestAuditLookupMigrationRetriesConcurrentBuild(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	ctx := t.Context()
	conn, err := database.Pool().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	schema := pgx.Identifier{"audit_retry_" + strings.ReplaceAll(uuid.NewString(), "-", "")}.Sanitize()
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SET search_path=public")
		_, _ = conn.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	}()
	// Excluding public prevents a DROP for a missing fixture index from touching
	// the real audit index. This table contains only disposable synthetic keys.
	if _, err := conn.Exec(ctx, "SET search_path="+schema); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE audit_events (org_id uuid,target_id text,id bigint);
 INSERT INTO audit_events VALUES ('00000000-0000-0000-0000-000000000001','duplicate',1),('00000000-0000-0000-0000-000000000001','duplicate',1)`); err != nil {
		t.Fatal(err)
	}
	// A duplicate-key failure leaves the same invalid concurrent-build catalog
	// state as an interrupted build, without unreliable timing or cancellation.
	if _, err := conn.Exec(ctx, `CREATE UNIQUE INDEX CONCURRENTLY idx_audit_org_target_id ON audit_events(org_id,target_id,id DESC)`); err == nil {
		t.Fatal("fixture concurrent unique build unexpectedly succeeded")
	}
	var valid bool
	if err := conn.QueryRow(ctx, `SELECT indisvalid FROM pg_index WHERE indexrelid='idx_audit_org_target_id'::regclass`).Scan(&valid); err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("failed fixture build did not leave an invalid index")
	}
	source, err := fs.ReadFile(migrationset.FS(), "173_audit_target_lookup.sql")
	if err != nil {
		t.Fatal(err)
	}
	up := strings.Split(strings.Split(string(source), "-- +goose Up")[1], "-- +goose Down")[0]
	var commands []string
	for _, line := range strings.Split(up, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			commands = append(commands, line)
		}
	}
	up = strings.Join(commands, "\n")
	for _, scenario := range []string{"invalid interrupted build", "successful unrecorded build"} {
		for _, statement := range strings.Split(up, ";") {
			if strings.TrimSpace(statement) == "" {
				continue
			}
			if _, err := conn.Exec(ctx, statement); err != nil {
				t.Fatalf("%s retry: %v", scenario, err)
			}
		}
		var ready, unique bool
		if err := conn.QueryRow(ctx, `SELECT indisvalid,indisready,indisunique FROM pg_index WHERE indexrelid='idx_audit_org_target_id'::regclass`).Scan(&valid, &ready, &unique); err != nil {
			t.Fatal(err)
		}
		if !valid || !ready || unique {
			t.Fatalf("%s left valid=%t ready=%t unique=%t", scenario, valid, ready, unique)
		}
	}
}
