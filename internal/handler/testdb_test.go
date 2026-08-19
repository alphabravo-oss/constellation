package handler

import (
	"context"
	"os"
	"testing"

	"github.com/alphabravocompany/constellation/internal/db"
)

// openTestDB formerly lived in scanjobs_test.go (now relocated to the
// handler/scanning sub-package). It is restored here so the remaining
// package-handler tests keep their shared DB-connection helper. Skips when no
// test database is reachable.
func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	url := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if url == "" {
		url = "postgres://test:test@localhost:15433/constellation_test?sslmode=disable"
	}
	d, err := db.Connect(context.Background(), url)
	if err != nil {
		t.Skipf("skipping: cannot reach test DB (%v)", err)
	}
	return d
}
