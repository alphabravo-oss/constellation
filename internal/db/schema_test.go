package db

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRequiredSchemaMatchesMigrationInventory(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "db", "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	var latest int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, _ := strings.Cut(entry.Name(), "_")
		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			t.Fatalf("invalid migration filename %s: %v", entry.Name(), err)
		}
		latest = max(latest, version)
	}
	if latest != RequiredSchemaVersion {
		t.Fatalf("API requires schema %d but latest migration is %d; update the startup gate", RequiredSchemaVersion, latest)
	}
}
