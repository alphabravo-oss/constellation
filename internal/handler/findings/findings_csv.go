// CSV export for findings.
//
//	GET /api/v1/findings.csv?kind=<>&lifecycle=<>&limit=<>
//
// Mirrors /api/v1/findings query params. Streams CSV directly so large exports don't blow
// up the API's memory budget; rows are written as they're read from the DB cursor.
package findings

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

type FindingsCSV struct {
	db *db.DB
}

func NewFindingsCSV(d *db.DB) *FindingsCSV { return &FindingsCSV{db: d} }

func (h *FindingsCSV) Stream(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	kind := r.URL.Query().Get("kind")
	lifecycle := r.URL.Query().Get("lifecycle")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100000 {
		limit = 10000
	}

	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, kind, COALESCE(external_id,'') AS external_id, title, severity, risk_score, lifecycle,
       asset_id, first_seen_at, last_seen_at, COALESCE(accepted_until, 'epoch'::timestamptz) AS accepted_until
  FROM findings
 WHERE org_id = $1
   AND ($2::text = '' OR kind = $2)
   AND ($3::text = '' OR lifecycle = $3)
 ORDER BY risk_score DESC, last_seen_at DESC
 LIMIT $4`, subj.OrgID, kind, lifecycle, limit)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="findings.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{
		"id", "kind", "external_id", "title", "severity", "risk_score", "lifecycle",
		"asset_id", "first_seen_at", "last_seen_at", "accepted_until",
	}); err != nil {
		return // client gone
	}

	var (
		id, kindCol, extID, title, severity, lifecycleCol string
		risk                                              int
		assetID                                           string
		firstSeen, lastSeen, acceptedUntil                time.Time
	)
	for rows.Next() {
		if err := rows.Scan(&id, &kindCol, &extID, &title, &severity, &risk, &lifecycleCol,
			&assetID, &firstSeen, &lastSeen, &acceptedUntil); err != nil {
			return
		}
		acc := ""
		if !acceptedUntil.IsZero() && acceptedUntil.Year() > 1971 {
			acc = acceptedUntil.UTC().Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			id, kindCol, extID, title, severity, fmt.Sprintf("%d", risk), lifecycleCol,
			assetID, firstSeen.UTC().Format(time.RFC3339), lastSeen.UTC().Format(time.RFC3339), acc,
		})
	}
}
