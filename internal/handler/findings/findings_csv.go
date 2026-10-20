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

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/platformrole"
)

type FindingsCSV struct {
	db *db.DB
}

func NewFindingsCSV(d *db.DB) *FindingsCSV { return &FindingsCSV{db: d} }

func (h *FindingsCSV) Stream(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		apiutil.WriteStatus(r.Context(), w, http.StatusUnauthorized, "no subject")
		return
	}
	values := r.URL.Query()
	limit, _ := strconv.Atoi(values.Get("limit"))
	if limit <= 0 || limit > 100000 {
		limit = 10000
	}
	where, args, err := findingFilter(subj.OrgID, values, true, true)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	order, err := findingOrder(values)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	args = append(args, limit, findingOffset(values))
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, kind, COALESCE(external_id,'') AS external_id, title, severity, risk_score, lifecycle,
       asset_id, first_seen_at, last_seen_at, COALESCE(accepted_until, 'epoch'::timestamptz) AS accepted_until, `+platformrole.FindingPlatformRoleSQL("findings")+`, revision::text,cluster_id::text,target_cluster_id::text
  FROM findings WHERE `+where+` ORDER BY `+order+`
 LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	w.Header().Set("X-Export-Limit", strconv.Itoa(limit))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="findings.csv"`)
	cw := csv.NewWriter(w)

	if err := cw.Write([]string{
		"id", "kind", "external_id", "title", "severity", "risk_score", "lifecycle",
		"asset_id", "first_seen_at", "last_seen_at", "accepted_until", "platform_role", "row_id", "revision", "source_cluster_id", "target_cluster_id",
	}); err != nil {
		return // client gone
	}

	var (
		id, kindCol, extID, title, severity, lifecycleCol string
		risk                                              int
		assetID, platformRole                             string
		firstSeen, lastSeen, acceptedUntil                time.Time
		revision                                          string
		sourceCluster, targetCluster                      *string
	)
	for rows.Next() {
		if err := rows.Scan(&id, &kindCol, &extID, &title, &severity, &risk, &lifecycleCol,
			&assetID, &firstSeen, &lastSeen, &acceptedUntil, &platformRole, &revision, &sourceCluster, &targetCluster); err != nil {
			panic(http.ErrAbortHandler) // Do not deliver a successful partial export.
		}
		acc := ""
		if !acceptedUntil.IsZero() && acceptedUntil.Year() > 1971 {
			acc = acceptedUntil.UTC().Format(time.RFC3339)
		}
		if err := cw.Write([]string{
			id, kindCol, extID, title, severity, fmt.Sprintf("%d", risk), lifecycleCol,
			assetID, firstSeen.UTC().Format(time.RFC3339Nano), lastSeen.UTC().Format(time.RFC3339), acc, platformRole, findingRowID(uuid.MustParse(id), firstSeen), revision, nullableCSV(sourceCluster), nullableCSV(targetCluster),
		}); err != nil {
			panic(http.ErrAbortHandler)
		}
	}
	if err := rows.Err(); err != nil {
		panic(http.ErrAbortHandler)
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		panic(http.ErrAbortHandler)
	}
}

func nullableCSV(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
