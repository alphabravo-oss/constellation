package runtime

import (
	"net/http"
	"strconv"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EventsExport streams the org's findings and runtime threats as NDJSON (one
// JSON object per line), filtered to a recent time window — a SIEM/pipeline
// pull endpoint. row_to_json keeps it decoupled from the exact table columns.
type EventsExport struct{ db *pgxpool.Pool }

func NewEventsExport(db *pgxpool.Pool) *EventsExport { return &EventsExport{db: db} }

// Export handles GET /api/v1/events:export?hours=24 . Default 24h, max 90 days.
func (e *EventsExport) Export(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	hours := 24
	if h, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && h > 0 && h <= 24*90 {
		hours = h
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := w.(http.Flusher)

	stream := func(kind, query string) error {
		rows, err := e.db.Query(r.Context(), query, subj.OrgID, hours)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var data string
			if err := rows.Scan(&data); err != nil {
				return err
			}
			if _, err := w.Write([]byte(`{"event":"` + kind + `","data":` + data + "}\n")); err != nil {
				return err
			}
		}
		if flusher != nil {
			flusher.Flush()
		}
		return rows.Err()
	}

	if err := stream("finding", `SELECT row_to_json(f) FROM findings f
 WHERE f.org_id = $1 AND f.first_seen_at > now() - make_interval(hours => $2)
 ORDER BY f.first_seen_at DESC`); err != nil {
		http.Error(w, "events export (findings): "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := stream("threat", `SELECT row_to_json(t) FROM runtime_threats t
 WHERE t.org_id = $1 AND t.created_at > now() - make_interval(hours => $2)
 ORDER BY t.created_at DESC`); err != nil {
		// findings already streamed; can't change status now — end the stream.
		_, _ = w.Write([]byte(`{"event":"error","data":"` + "threats: " + err.Error() + `"}` + "\n"))
	}
}
