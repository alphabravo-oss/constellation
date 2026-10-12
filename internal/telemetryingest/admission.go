package telemetryingest

import (
	"net/http"
	"sync"

	"github.com/google/uuid"
)

// Limits are per API process and shared by both ingestion streams. Admission is
// nonblocking: overload is retried from the node spool, never an unbounded queue
// of requests waiting for database connections. Scaling replicas multiplies caps.
var admission = struct {
	sync.Mutex
	total    int
	clusters map[[2]uuid.UUID]int
}{clusters: make(map[[2]uuid.UUID]int)}

func Admit(w http.ResponseWriter, org, cluster uuid.UUID) (func(), bool) {
	key := [2]uuid.UUID{org, cluster}
	admission.Lock()
	defer admission.Unlock()
	if admission.total >= 32 || admission.clusters[key] >= 2 {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "telemetry capacity busy", http.StatusTooManyRequests)
		return nil, false
	}
	admission.total++
	admission.clusters[key]++
	return func() {
		admission.Lock()
		defer admission.Unlock()
		admission.total--
		admission.clusters[key]--
		if admission.clusters[key] == 0 {
			delete(admission.clusters, key)
		}
	}, true
}
