//go:build integration

package database_test

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/server/database"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

func TestLatestVersionMatchesRequiredSchema(t *testing.T) {
	t.Parallel()
	if got := database.LatestVersion(); got != db.RequiredSchemaVersion {
		t.Fatalf("embedded set ends at %d but internal/db.RequiredSchemaVersion is %d", got, db.RequiredSchemaVersion)
	}
}

func TestMigrateFreshDatabaseIsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.FreshURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	first, err := database.MigratePool(ctx, pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Applied) == 0 || first.Version != database.LatestVersion() {
		t.Fatalf("first run applied=%d version=%d", len(first.Applied), first.Version)
	}
	second, err := database.MigratePool(ctx, pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Applied) != 0 || second.Version != first.Version {
		t.Fatalf("second run applied=%d version=%d", len(second.Applied), second.Version)
	}
	if err := db.NewFromPool(pool).RequireSchema(ctx); err != nil {
		t.Fatal(err)
	}
}

// Two replicas booting against the same fresh database: the advisory lock
// serialises them so exactly one applies the set and the other sees nothing
// pending.
func TestMigrateConcurrentRunnersApplyExactlyOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	url := pgtest.FreshURL(t)
	const runners = 4
	results := make([]database.Result, runners)
	errs := make([]error, runners)
	var wg sync.WaitGroup
	for i := range runners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pool, err := pgxpool.New(ctx, url)
			if err != nil {
				errs[i] = err
				return
			}
			defer pool.Close()
			results[i], errs[i] = database.MigratePool(ctx, pool, nil)
		}()
	}
	wg.Wait()
	appliers := 0
	for i := range runners {
		if errs[i] != nil {
			t.Fatalf("runner %d: %v", i, errs[i])
		}
		if results[i].Version != database.LatestVersion() {
			t.Fatalf("runner %d ended at version %d", i, results[i].Version)
		}
		if len(results[i].Applied) > 0 {
			appliers++
		}
	}
	if appliers != 1 {
		t.Fatalf("expected exactly one runner to apply migrations, got %d", appliers)
	}
}
