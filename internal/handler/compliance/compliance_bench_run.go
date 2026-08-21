// CMP-RUN-31: on-demand host-benchmark runs.
//
// NeuVector exposes handlerKubeBenchRun/handlerDockerBenchRun which message the
// enforcer over gRPC to run kube-bench/docker-bench immediately. Constellation's
// runner (cmd/constellation-kube-bench-runner) is a thin CronJob with no inbound
// control channel, so on-demand parity is a small request queue instead:
//
//   - RunBench enqueues a pending row in compliance_bench_run_requests (the
//     "run requested" flag). This is the control-plane -> runner trigger.
//   - ClaimBenchRun is polled by the runner (in watch mode) to atomically claim
//     the oldest pending request for its cluster+profile; it then exec's the
//     benchmark and POSTs the report to /compliance/ingest, which is the fresh run.
//
// Unlike ComplianceSchedulesDB.RunNow (which only nudges the report renderer over
// already-ingested data), this actually causes a NEW benchmark execution.
//
// Routes (wire in internal/server/server.go alongside the other compliance routes):
//
//	r.Post("/api/v1/compliance/bench/run",   c.compliance.RunBench)    // UI/API trigger
//	r.Post("/api/v1/compliance/bench/claim", c.compliance.ClaimBenchRun) // runner drains
package compliance

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// BenchRunRequest is one queued on-demand host-benchmark run.
type BenchRunRequest struct {
	ID          string `json:"id"`
	ClusterID   string `json:"cluster_id,omitempty"`
	Profile     string `json:"profile"`
	Benchmark   string `json:"benchmark,omitempty"`
	Status      string `json:"status"`
	RequestedAt string `json:"requested_at,omitempty"`
}

// normalizeBenchProfile maps the accepted profile aliases onto the two canonical
// runner profiles, matching the Ingest handler's ?profile= switch.
func normalizeBenchProfile(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "kube-bench", "kubebench":
		return "kube-bench", true
	case "docker-bench", "docker":
		return "docker-bench", true
	default:
		return "", false
	}
}

// RunBench enqueues an on-demand kube-bench/docker-bench run for the caller's org
// (optionally scoped to a cluster). The runner services it out-of-band; this
// handler only writes the request row and returns it.
func (c *Compliance) RunBench(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())

	// Accept profile + benchmark from either the query string or a small JSON body.
	profileRaw := r.URL.Query().Get("profile")
	benchmark := strings.TrimSpace(r.URL.Query().Get("benchmark"))
	if r.Body != nil {
		if body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<10)); len(body) > 0 {
			var in struct {
				Profile   string `json:"profile"`
				Benchmark string `json:"benchmark"`
			}
			if err := json.Unmarshal(body, &in); err == nil {
				if profileRaw == "" {
					profileRaw = in.Profile
				}
				if benchmark == "" {
					benchmark = strings.TrimSpace(in.Benchmark)
				}
			}
		}
	}
	profile, ok := normalizeBenchProfile(profileRaw)
	if !ok {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown profile (want kube-bench or docker-bench)"})
		return
	}

	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	var req BenchRunRequest
	var clusterID *uuid.UUID
	var requestedAt time.Time
	if err := c.db.Pool().QueryRow(r.Context(), `
INSERT INTO compliance_bench_run_requests (org_id, cluster_id, profile, benchmark, requested_by)
VALUES ($1, $2, $3, $4, $5)
RETURNING id::text, cluster_id, profile, benchmark, status, requested_at`,
		subj.OrgID, clusterArg, profile, benchmark, subj.UserID,
	).Scan(&req.ID, &clusterID, &req.Profile, &req.Benchmark, &req.Status, &requestedAt); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	req.RequestedAt = requestedAt.UTC().Format(time.RFC3339)
	if clusterID != nil {
		req.ClusterID = clusterID.String()
	}

	if c.audit != nil {
		oid := subj.OrgID
		uid := subj.UserID
		_, _, _ = c.audit.Log(r.Context(), audit.Event{
			OrgID:      &oid,
			ActorID:    &uid,
			Action:     "compliance.bench.run_requested",
			TargetKind: "compliance_bench_run",
			TargetID:   req.ID,
		})
	}

	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"request": req,
		"queued":  true,
		"message": "bench run queued; the " + profile + " runner will pick it up and POST fresh results to /compliance/ingest",
	})
}

// ClaimBenchRun is polled by the runner to atomically claim the oldest pending
// request for its cluster + profile. A runner scoped to cluster X claims that
// cluster's requests plus org-wide (cluster_id IS NULL) requests. Returns 200
// with the claimed request, or 204 when the queue is empty.
func (c *Compliance) ClaimBenchRun(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())

	profile, ok := normalizeBenchProfile(r.URL.Query().Get("profile"))
	if !ok {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown profile (want kube-bench or docker-bench)"})
		return
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// FOR UPDATE SKIP LOCKED so two runners polling concurrently never claim the
	// same row. A NULL clusterArg (runner sent no cluster_id) matches any request.
	var req BenchRunRequest
	var clusterID *uuid.UUID
	var requestedAt time.Time
	err = c.db.Pool().QueryRow(r.Context(), `
UPDATE compliance_bench_run_requests
   SET status = 'claimed', claimed_at = NOW()
 WHERE id = (
     SELECT id FROM compliance_bench_run_requests
      WHERE org_id = $1
        AND status = 'pending'
        AND profile = $2
        AND ($3::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $3)
      ORDER BY requested_at
      FOR UPDATE SKIP LOCKED
      LIMIT 1)
RETURNING id::text, cluster_id, profile, benchmark, status, requested_at`,
		subj.OrgID, profile, clusterArg,
	).Scan(&req.ID, &clusterID, &req.Profile, &req.Benchmark, &req.Status, &requestedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	req.RequestedAt = requestedAt.UTC().Format(time.RFC3339)
	if clusterID != nil {
		req.ClusterID = clusterID.String()
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"request": req})
}
