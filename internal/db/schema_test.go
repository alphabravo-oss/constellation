package db

import (
	"testing"

	"github.com/alphabravocompany/constellation/internal/server/database"
)

// The API's startup gate must track the embedded migration set.
func TestRequiredSchemaMatchesMigrationInventory(t *testing.T) {
	t.Parallel()
	if latest := database.LatestVersion(); latest != RequiredSchemaVersion {
		t.Fatalf("API requires schema %d but latest migration is %d; update the startup gate", RequiredSchemaVersion, latest)
	}
}
