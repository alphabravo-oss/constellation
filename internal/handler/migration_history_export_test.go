package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type migrationExportWriter struct {
	*httptest.ResponseRecorder
	firstWrite func()
}

func (writer *migrationExportWriter) Write(data []byte) (int, error) {
	if writer.firstWrite != nil {
		callback := writer.firstWrite
		writer.firstWrite = nil
		callback()
	}
	return writer.ResponseRecorder.Write(data)
}

type migrationFailWriter struct {
	*httptest.ResponseRecorder
	writes int
}

func (writer *migrationFailWriter) Write(data []byte) (int, error) {
	writer.writes++
	if writer.writes > 1 {
		return 0, fmt.Errorf("interrupted export")
	}
	return writer.ResponseRecorder.Write(data)
}

func TestMigrationImportsExportAllHistorySnapshotAndRedaction(t *testing.T) {
	fixture := newMigrationRemainingFixture(t)
	ctx := context.Background()
	const secret = "migration-export-secret-sentinel"
	preview := fmt.Sprintf(`{"target_cluster_id":"%s","summary":{"source":"%s"},"password":"%s"}`, uuid.New(), secret, secret)
	unsupported := fmt.Sprintf(`[{"kind":"secret","reason":"%s","source":{"password":"%s"}}]`, secret, secret)
	for index := 0; index < 130; index++ {
		if _, err := fixture.d.Pool().Exec(ctx, `
INSERT INTO migration_imports (org_id, source, source_hash, preview_json, unsupported_json, error, created_at)
VALUES ($1, 'neuvector', $2, $3, $4, $5, '2026-09-26T00:00:00Z')`, fixture.org, fmt.Sprintf("export-%d", index), preview, unsupported, secret); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.d.Pool().Exec(ctx, `UPDATE migration_imports SET source=$3 WHERE org_id=$1 AND source_hash=$2`, fixture.org, "export-0", secret); err != nil {
		t.Fatal(err)
	}
	other := newMigrationRemainingFixture(t)
	if _, err := other.d.Pool().Exec(ctx, `INSERT INTO migration_imports (org_id, source, source_hash, preview_json) VALUES ($1,'neuvector','foreign','{}')`, other.org); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/migration/imports/export", nil)
	request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: fixture.org, UserID: fixture.user}))
	writer := &migrationExportWriter{ResponseRecorder: httptest.NewRecorder()}
	writer.firstWrite = func() {
		if _, err := fixture.d.Pool().Exec(ctx, `INSERT INTO migration_imports (org_id, source, source_hash, preview_json, created_at) VALUES ($1,'neuvector','late','{}',NOW())`, fixture.org); err != nil {
			t.Fatal(err)
		}
	}
	fixture.h.MigrationImportsExport(writer, request)
	if writer.Code != http.StatusOK || writer.Header().Get("Content-Type") != "application/x-ndjson" || writer.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("export status=%d headers=%v", writer.Code, writer.Header())
	}
	if strings.Contains(writer.Body.String(), secret) || strings.Contains(writer.Body.String(), "foreign") || strings.Contains(writer.Body.String(), "late") {
		t.Fatalf("export leaked secret or out-of-snapshot record: %s", writer.Body.String())
	}
	lines := strings.Split(strings.TrimSpace(writer.Body.String()), "\n")
	if len(lines) != 131 {
		t.Fatalf("export lines=%d, want 130 imports and completion", len(lines))
	}
	previousID := ""
	unknownSources := 0
	for index, line := range lines[:130] {
		var record migrationImportExportRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record.Source == "unknown" {
			unknownSources++
		}
		if record.Type != "import" || (record.Source != "neuvector" && record.Source != "unknown") || record.Status != "previewed" || record.UnsupportedCount == nil || *record.UnsupportedCount != 1 || record.TargetClusterID == "" {
			t.Fatalf("record %d: %+v", index, record)
		}
		if previousID != "" && previousID <= record.ID {
			t.Fatalf("tied timestamps not in descending ID order: %s then %s", previousID, record.ID)
		}
		previousID = record.ID
	}
	if unknownSources != 1 {
		t.Fatalf("untrusted source labels=%d, want 1 redacted", unknownSources)
	}
	var complete migrationImportExportRecord
	if err := json.Unmarshal([]byte(lines[130]), &complete); err != nil || complete.Type != "complete" || complete.Count == nil || *complete.Count != 130 {
		t.Fatalf("completion=%+v err=%v", complete, err)
	}
}

func TestMigrationImportsExportEmptyAndUnauthenticated(t *testing.T) {
	fixture := newMigrationRemainingFixture(t)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/migration/imports/export", nil)
	unauthenticated := httptest.NewRecorder()
	fixture.h.MigrationImportsExport(unauthenticated, request)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated export status=%d", unauthenticated.Code)
	}
	request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: fixture.org, UserID: fixture.user}))
	response := httptest.NewRecorder()
	fixture.h.MigrationImportsExport(response, request)
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"type":"complete","count":0}` {
		t.Fatalf("empty export status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestMigrationImportsExportInterruptedStreamHasNoCompletion(t *testing.T) {
	fixture := newMigrationRemainingFixture(t)
	if _, err := fixture.d.Pool().Exec(context.Background(), `INSERT INTO migration_imports (org_id, source, source_hash, preview_json) VALUES ($1,'neuvector','interrupted','{}')`, fixture.org); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/migration/imports/export", nil)
	request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: fixture.org, UserID: fixture.user}))
	writer := &migrationFailWriter{ResponseRecorder: httptest.NewRecorder()}
	fixture.h.MigrationImportsExport(writer, request)
	if writer.writes != 2 || strings.Contains(writer.Body.String(), `"type":"complete"`) {
		t.Fatalf("interrupted stream must lack completion: writes=%d body=%s", writer.writes, writer.Body.String())
	}
}
