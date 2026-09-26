package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type migrationImportExportRecord struct {
	Type             string `json:"type"`
	ID               string `json:"id,omitempty"`
	Source           string `json:"source,omitempty"`
	Status           string `json:"status,omitempty"`
	TargetClusterID  string `json:"target_cluster_id,omitempty"`
	UnsupportedCount *int   `json:"unsupported_count,omitempty"`
	CreatedAt        string `json:"created_at,omitempty"`
	AppliedAt        string `json:"applied_at,omitempty"`
	RolledBackAt     string `json:"rolled_back_at,omitempty"`
	Count            *int   `json:"count,omitempty"`
}

func (h *Enterprise) MigrationImportsExport(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	tx, err := h.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "migration export unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	rows, err := tx.Query(r.Context(), `
SELECT id, source, status, preview_json->>'target_cluster_id',
       CASE WHEN jsonb_typeof(unsupported_json)='array' THEN jsonb_array_length(unsupported_json) ELSE 0 END,
       created_at, applied_at, rolled_back_at
  FROM migration_imports
 WHERE org_id=$1
 ORDER BY created_at DESC, id DESC`, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "migration export unavailable")
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="migration-imports.ndjson"`)
	w.Header().Set("Cache-Control", "no-store")
	encoder := json.NewEncoder(w)
	count := 0
	for rows.Next() {
		var id uuid.UUID
		var source, status string
		var targetClusterID *string
		var unsupportedCount int
		var createdAt time.Time
		var appliedAt, rolledBackAt *time.Time
		if err := rows.Scan(&id, &source, &status, &targetClusterID, &unsupportedCount, &createdAt, &appliedAt, &rolledBackAt); err != nil {
			return
		}
		if source != "neuvector" && source != "aqua" && source != "prisma" && source != "stackrox" && source != "rhacs" {
			source = "unknown"
		}
		record := migrationImportExportRecord{
			Type: "import", ID: id.String(), Source: source, Status: status,
			UnsupportedCount: &unsupportedCount, CreatedAt: createdAt.UTC().Format(time.RFC3339Nano),
		}
		if targetClusterID != nil {
			if parsed, err := uuid.Parse(*targetClusterID); err == nil {
				record.TargetClusterID = parsed.String()
			}
		}
		if appliedAt != nil {
			record.AppliedAt = appliedAt.UTC().Format(time.RFC3339Nano)
		}
		if rolledBackAt != nil {
			record.RolledBackAt = rolledBackAt.UTC().Format(time.RFC3339Nano)
		}
		if err := encoder.Encode(record); err != nil {
			return
		}
		count++
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	if rows.Err() != nil {
		return
	}
	rows.Close()
	if err := tx.Commit(r.Context()); err != nil {
		return
	}
	_ = encoder.Encode(migrationImportExportRecord{Type: "complete", Count: &count})
}
