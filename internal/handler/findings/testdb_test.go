package findings

import (
	"context"
	"os"
	"testing"

	"github.com/alphabravocompany/constellation/internal/db"
)

// openTestDB mirrors the package-internal helper in internal/handler; each
// sub-package owns its own copy so its tests are self-contained. Skips when no
// test database is reachable.
func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	url := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CONSTELLATION_TEST_DATABASE_URL not set; integration test")
	}
	d, err := db.Connect(context.Background(), url)
	if err != nil {
		t.Skipf("skipping: cannot reach test DB (%v)", err)
	}
	return d
}
