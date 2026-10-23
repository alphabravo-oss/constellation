package network

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"
	"github.com/alphabravocompany/constellation/internal/flowrollup"
)

func historyAvailable(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, from time.Time) bool {
	boundary, err := flowrollup.AvailableFrom(r.Context(), pool)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 500, "Historical flow availability could not be checked.")
		return false
	}
	w.Header().Set("X-History-Available-From", boundary.UTC().Format(time.RFC3339))
	if from.Before(boundary) {
		apiutil.WriteStatus(r.Context(), w, http.StatusGone, fmt.Sprintf("This range includes expired hourly flow history. Retained history starts at %s; choose a shorter range.", boundary.UTC().Format(time.RFC3339)))
		return false
	}
	return true
}
