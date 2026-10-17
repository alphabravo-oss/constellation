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

	"github.com/alphabravocompany/constellation/internal/handler/httpx"

	"github.com/alphabravocompany/constellation/pkg/audit"
	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
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
	return compliancepkg.NormalizeBenchProfile(raw)
}

// RunBench enqueues an on-demand kube-bench/docker-bench run for the caller's org
// (optionally scoped to a cluster). The runner services it out-of-band; this
// handler only writes the request row and returns it.
func (c *Compliance) RunBench(w http.ResponseWriter, r *http.Request) {
	scope, authorized := c.userWriteScope(w, r)
	if !authorized {
		return
	}

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

	if !compliancepkg.ValidBenchmarkID(benchmark) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid benchmark identifier"})
		return
	}
	ctx := r.Context()
	tx, err := c.db.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "enqueue unavailable"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if !scope.lockCluster(w, r, tx) {
		return
	}
	clusterArg := scope.clusterID
	var req BenchRunRequest
	var clusterID *uuid.UUID
	var requestedAt time.Time
	if err := tx.QueryRow(ctx, `
INSERT INTO compliance_bench_run_requests (org_id, cluster_id, profile, benchmark, requested_by)
SELECT $1, $2, $3, $4, $5 WHERE $2::uuid IS NULL OR EXISTS(SELECT 1 FROM clusters WHERE id=$2 AND org_id=$1)
RETURNING id::text, cluster_id, profile, benchmark, status, requested_at`,
		scope.orgID, clusterArg, profile, benchmark, scope.actorID,
	).Scan(&req.ID, &clusterID, &req.Profile, &req.Benchmark, &req.Status, &requestedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "cluster not found"})
			return
		}
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "enqueue unavailable"})
		return
	}
	req.RequestedAt = requestedAt.UTC().Format(time.RFC3339)
	if clusterID != nil {
		req.ClusterID = clusterID.String()
	}

	if c.audit != nil {
		_, _, err := c.audit.LogInTx(ctx, tx, audit.Event{OrgID: &scope.orgID, ActorID: scope.actorID, Action: "compliance.bench.run_requested", TargetKind: "compliance_bench_run", TargetID: req.ID, After: map[string]any{"cluster_id": scope.clusterID, "profile": profile, "benchmark": benchmark}})
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "enqueue unavailable"})
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "enqueue unavailable"})
		return
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
	scope, ok := c.userWriteScope(w, r)
	if ok {
		c.claimBenchRun(w, r, scope)
	}
}

func (c *Compliance) claimBenchRun(w http.ResponseWriter, r *http.Request, scope complianceWriteScope) {
	profile, ok := normalizeBenchProfile(r.URL.Query().Get("profile"))
	if !ok {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown profile (want kube-bench or docker-bench)"})
		return
	}
	ctx := r.Context()
	tx, err := c.db.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "claim unavailable"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if !scope.lockCluster(w, r, tx) {
		return
	}
	var req BenchRunRequest
	var clusterID *uuid.UUID
	var requestedAt time.Time
	var inherited bool
	err = tx.QueryRow(ctx, `WITH candidate AS (
 SELECT r.id,r.cluster_id FROM compliance_bench_run_requests r
 WHERE r.org_id=$1 AND r.status='pending' AND r.profile=$2
 AND ($3::uuid IS NULL OR r.cluster_id IS NULL OR r.cluster_id=$3)
 AND (r.cluster_id IS NULL OR EXISTS(SELECT 1 FROM clusters c WHERE c.id=r.cluster_id AND c.org_id=$1))
 ORDER BY r.requested_at,r.id FOR UPDATE SKIP LOCKED LIMIT 1)
 UPDATE compliance_bench_run_requests req SET status='claimed',claimed_at=NOW(),cluster_id=COALESCE(req.cluster_id,$3::uuid)
 FROM candidate WHERE req.id=candidate.id
 RETURNING req.id::text,req.cluster_id,req.profile,req.benchmark,req.status,req.requested_at,candidate.cluster_id IS NULL`,
		scope.orgID, profile, scope.clusterID).Scan(&req.ID, &clusterID, &req.Profile, &req.Benchmark, &req.Status, &requestedAt, &inherited)
	if errors.Is(err, pgx.ErrNoRows) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "claim unavailable"})
		return
	}
	if scope.clusterID == nil && clusterID != nil {
		selected := scope
		selected.clusterID = clusterID
		if !selected.lockCluster(w, r, tx) {
			return
		}
	}
	logger := c.audit
	if logger == nil {
		logger = audit.New(c.db.Pool())
	}
	_, _, err = logger.LogInTx(ctx, tx, audit.Event{OrgID: &scope.orgID, ActorID: scope.actorID, Action: "compliance.bench.claimed", TargetKind: "compliance_bench_run", TargetID: req.ID,
		Before: map[string]any{"org_wide": inherited}, After: map[string]any{"cluster_id": clusterID, "agent_token_id": scope.agentID, "profile": profile}})
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "claim unavailable"})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "claim unavailable"})
		return
	}
	req.RequestedAt = requestedAt.UTC().Format(time.RFC3339)
	if clusterID != nil {
		req.ClusterID = clusterID.String()
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"request": req})
}
