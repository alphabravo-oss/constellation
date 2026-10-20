//go:build integration

package findings

import (
	"testing"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

// openTestDB returns a *db.DB on this test's private, migrated database
// (internal/testutil/pgtest: one container per process, one clone per test).
func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	return db.NewFromPool(pgtest.Pool(t))
}
