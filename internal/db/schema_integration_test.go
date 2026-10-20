//go:build integration

package db

import (
	"context"
	"testing"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"

	"github.com/alphabravocompany/constellation/internal/testutil/pgfixture"
)

func TestRequireSchemaHandlesMissingOldRolledBackAndCurrent(t *testing.T) {
	t.Parallel()
	base := pgtest.Pool(t)
	pool := pgfixture.Schema(t, base)
	database := NewFromPool(pool)
	if err := database.RequireSchema(t.Context()); err == nil {
		t.Fatal("missing migration table accepted")
	}
	if _, err := pool.Exec(t.Context(), `CREATE TABLE goose_db_version(id bigserial PRIMARY KEY,version_id bigint,is_applied boolean);
 INSERT INTO goose_db_version(version_id,is_applied) VALUES (0,true),(100,true)`); err != nil {
		t.Fatal(err)
	}
	if err := database.RequireSchema(t.Context()); err == nil {
		t.Fatal("old signing-key migration accepted")
	}
	for _, step := range []struct {
		version int64
		applied bool
		ready   bool
	}{
		{RequiredSchemaVersion, true, true},
		{RequiredSchemaVersion, false, false},
		{RequiredSchemaVersion, true, true},
		{RequiredSchemaVersion + 1, true, true},
		{RequiredSchemaVersion + 1, false, true},
	} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO goose_db_version(version_id,is_applied) VALUES ($1,$2)`, step.version, step.applied); err != nil {
			t.Fatal(err)
		}
		if err := database.RequireSchema(t.Context()); (err == nil) != step.ready {
			t.Fatalf("version=%d applied=%v ready=%v error=%v", step.version, step.applied, step.ready, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := database.RequireSchema(ctx); err == nil {
		t.Fatal("canceled startup check accepted")
	}
}
