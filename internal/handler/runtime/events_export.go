package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/platformrole"
)

// EventsExport preserves the existing finding/threat NDJSON objects. Pages keep
// memory bounded without imposing an export cap, and metadata is resolved in
// the same read-only snapshot as its evidence.
type EventsExport struct{ db *pgxpool.Pool }

func NewEventsExport(db *pgxpool.Pool) *EventsExport { return &EventsExport{db: db} }

// Export handles GET /api/v1/events:export?hours=24. Default 24h, max 90 days.
func (e *EventsExport) Export(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	hours := 24
	if value, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && value > 0 && value <= 24*90 {
		hours = value
	}
	tx, err := e.db.BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "events export: "+err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	var after time.Time
	if err := tx.QueryRow(r.Context(), `SELECT NOW()-make_interval(hours=>$1)`, hours).Scan(&after); err != nil {
		jsonError(w, http.StatusInternalServerError, "events export: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	encoder := json.NewEncoder(w)
	started := false
	emit := func(kind string, data any) error {
		err := encoder.Encode(struct {
			Event string `json:"event"`
			Data  any    `json:"data"`
		}{kind, data})
		if err == nil {
			started = true
		}
		return err
	}
	fail := func(source string, err error) {
		if !started {
			w.WriteHeader(http.StatusInternalServerError)
		}
		_ = emit("error", source+": "+err.Error())
	}
	for _, source := range []string{"finding", "threat"} {
		if err := e.streamSource(r.Context(), tx, subj.OrgID, after, source, emit, w); err != nil {
			fail(source, err)
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		fail("events export", err)
	}
}

type exportedEvidence struct {
	raw      json.RawMessage
	at       time.Time
	id       uuid.UUID
	identity handler.PlatformWorkloadIdentity
}

func (e *EventsExport) streamSource(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, after time.Time, source string, emit func(string, any) error, w http.ResponseWriter) error {
	const pageSize = 250
	var before *time.Time
	var beforeID *uuid.UUID
	query := `SELECT to_jsonb(f) || jsonb_build_object('platform_role',` + platformrole.FindingPlatformRoleSQL("f") + `),f.first_seen_at,f.id FROM findings f
 WHERE f.org_id=$1 AND f.first_seen_at>$2
 AND ($3::timestamptz IS NULL OR (f.first_seen_at,f.id)<($3,$4::uuid))
 ORDER BY f.first_seen_at DESC,f.id DESC LIMIT 250`
	if source == "threat" {
		// Use the same at timestamp as threat List/Timeline; the schema has no created_at.
		query = `SELECT row_to_json(t),t.at,t.id,t.cluster_id,COALESCE(t.workload_id,''),COALESCE(t.namespace,'') FROM runtime_threats t
 WHERE t.org_id=$1 AND t.at>$2
 AND ($3::timestamptz IS NULL OR (t.at,t.id)<($3,$4::uuid))
 ORDER BY t.at DESC,t.id DESC LIMIT 250`
	}
	for {
		rows, err := tx.Query(ctx, query, orgID, after, before, beforeID)
		if err != nil {
			return err
		}
		page := make([]exportedEvidence, 0, pageSize)
		for rows.Next() {
			var record exportedEvidence
			if source == "threat" {
				err = rows.Scan(&record.raw, &record.at, &record.id, &record.identity.ClusterID, &record.identity.Workload, &record.identity.Namespace)
			} else {
				err = rows.Scan(&record.raw, &record.at, &record.id)
			}
			if err != nil {
				rows.Close()
				return err
			}
			page = append(page, record)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if source == "threat" {
			identities := make([]handler.PlatformWorkloadIdentity, len(page))
			for i := range page {
				identities[i] = page[i].identity
			}
			roles, err := handler.EvidencePlatformRoles(ctx, tx, orgID, identities)
			if err != nil {
				return err
			}
			for i := range page {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(page[i].raw, &fields); err != nil {
					return fmt.Errorf("threat metadata: %w", err)
				}
				role, err := json.Marshal(roles[i])
				if err != nil {
					return err
				}
				fields["platform_role"] = role
				page[i].raw, err = json.Marshal(fields)
				if err != nil {
					return err
				}
			}
		}
		for _, record := range page {
			if err := emit(source, record.raw); err != nil {
				return err
			}
		}
		if flusher, ok := w.(http.Flusher); ok && len(page) > 0 {
			flusher.Flush()
		}
		if len(page) < pageSize {
			return nil
		}
		last := page[len(page)-1]
		before, beforeID = &last.at, &last.id
	}
}
