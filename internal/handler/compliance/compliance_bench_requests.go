package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
)

type benchCreateInput struct {
	RequestKey string `json:"request_key"`
	Profile    string `json:"profile"`
	Benchmark  string `json:"benchmark"`
}

func (c *Compliance) CreateBenchRequest(w http.ResponseWriter, r *http.Request) {
	scope, ok := c.userWriteScope(w, r)
	if !ok {
		return
	}
	var input benchCreateInput
	if !strictBenchBody(w, r, &input, 4096) || !validateBenchCreate(w, &input) {
		return
	}
	tx, ok := c.beginBenchWrite(w, r, scope)
	if !ok {
		return
	}
	defer rollbackBenchRequest(r.Context(), tx)
	req, err := c.createBenchRequest(r, tx, scope, input)
	if err != nil {
		benchRequestError(w, err)
		return
	}
	if req.ID == "" {
		benchReplyError(w, http.StatusConflict, "idempotency_conflict", "request key already identifies different benchmark selectors")
		return
	}
	if benchCommit(w, r, tx) {
		httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"request": req})
	}
}

func validateBenchCreate(w http.ResponseWriter, input *benchCreateInput) bool {
	_, validKey := benchUUID(input.RequestKey)
	profile, validProfile := normalizeBenchProfile(input.Profile)
	input.Benchmark = strings.TrimSpace(input.Benchmark)
	if !validKey || !validProfile || !compliancepkg.ValidBenchmarkID(input.Benchmark) {
		benchReplyError(w, http.StatusBadRequest, "invalid_request", "invalid benchmark selectors or request key")
		return false
	}
	if profile != "kube-bench" {
		benchReplyError(w, http.StatusUnprocessableEntity, "unsupported_profile", "durable docker-bench execution is unsupported: executable and configuration are not bundled")
		return false
	}
	input.Profile = profile
	return true
}

func (c *Compliance) createBenchRequest(r *http.Request, tx pgx.Tx, scope complianceWriteScope, input benchCreateInput) (compliancepkg.BenchExecutionRequest, error) {
	selectors, err := json.Marshal(struct {
		Input   benchCreateInput
		Cluster *uuid.UUID
	}{input, scope.clusterID})
	if err != nil {
		return compliancepkg.BenchExecutionRequest{}, err
	}
	digest := sha256.Sum256(selectors)
	hash := hex.EncodeToString(digest[:])
	var id uuid.UUID
	err = tx.QueryRow(r.Context(), `INSERT INTO compliance_bench_run_requests(org_id,cluster_id,requested_cluster_id,profile,benchmark,requested_by,protocol_version,status,request_key,request_hash)
VALUES($1,$2,$2,$3,$4,$5,2,'queued',$6,$7) ON CONFLICT(org_id,request_key) WHERE protocol_version=2 DO NOTHING RETURNING id`, scope.orgID, scope.clusterID, input.Profile, input.Benchmark, scope.actorID, input.RequestKey, hash).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		var existingHash string
		err = tx.QueryRow(r.Context(), `SELECT id,request_hash FROM compliance_bench_run_requests WHERE org_id=$1 AND request_key=$2 AND protocol_version=2`, scope.orgID, input.RequestKey).Scan(&id, &existingHash)
		if err != nil || hash != existingHash {
			return compliancepkg.BenchExecutionRequest{}, err
		}
	} else if err == nil {
		err = c.benchAudit(r.Context(), tx, scope, "compliance.bench.v2.requested", id.String(), map[string]any{"cluster_id": scope.clusterID, "profile": input.Profile, "benchmark": input.Benchmark})
	}
	if err != nil {
		return compliancepkg.BenchExecutionRequest{}, err
	}
	return loadBenchRequest(r.Context(), tx, scope.orgID, id, false)
}

func (c *Compliance) GetBenchRequest(w http.ResponseWriter, r *http.Request) {
	scope, ok := c.userWriteScope(w, r)
	if !ok {
		return
	}
	id, valid := benchUUID(chi.URLParam(r, "id"))
	if !valid {
		benchReplyError(w, http.StatusBadRequest, "invalid_id", "invalid benchmark request id")
		return
	}
	tx, err := c.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		benchRequestError(w, err)
		return
	}
	defer rollbackBenchRequest(r.Context(), tx)
	req, err := loadBenchRequest(r.Context(), tx, scope.orgID, id, false)
	if err == nil && !benchVisibleToScope(req, scope) {
		err = pgx.ErrNoRows
	}
	if err != nil {
		benchRequestError(w, err)
		return
	}
	attempts, err := benchAttemptHistory(r, tx, scope.orgID, id)
	if err != nil {
		benchRequestError(w, err)
		return
	}
	if benchCommit(w, r, tx) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"request": req, "attempts": attempts})
	}
}

func benchAttemptHistory(r *http.Request, tx pgx.Tx, org, request uuid.UUID) ([]compliancepkg.BenchExecutionAttempt, error) {
	rows, err := tx.Query(r.Context(), `SELECT id::text FROM compliance_bench_attempts WHERE org_id=$1 AND request_id=$2 ORDER BY attempt_no`, org, request)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := make([]compliancepkg.BenchExecutionAttempt, 0, len(ids))
	for _, id := range ids {
		a, _, err := loadBenchAttempt(r.Context(), tx, org, id)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (c *Compliance) ListBenchRequests(w http.ResponseWriter, r *http.Request) {
	scope, ok := c.userWriteScope(w, r)
	if !ok {
		return
	}
	limit, offset, valid := benchListPage(r)
	if !valid {
		benchReplyError(w, http.StatusBadRequest, "invalid_page", "invalid benchmark page")
		return
	}
	tx, err := c.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		benchRequestError(w, err)
		return
	}
	defer rollbackBenchRequest(r.Context(), tx)
	items, total, err := listBenchRequests(r, tx, scope, limit, offset)
	if err != nil {
		benchRequestError(w, err)
		return
	}
	if benchCommit(w, r, tx) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"requests": items, "total": total, "limit": limit, "offset": offset, "has_more": int64(offset)+int64(len(items)) < total, "source": "durable_v2_requests", "legacy_requests_included": false})
	}
}

func benchListPage(r *http.Request) (int, int, bool) {
	values, _, err := complianceWriteQuery(r)
	if err != nil || len(values["limit"]) > 1 || len(values["offset"]) > 1 {
		return 0, 0, false
	}
	limit, offset := 100, 0
	if raw := values.Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil {
			return 0, 0, false
		}
	}
	if raw := values.Get("offset"); raw != "" {
		offset, err = strconv.Atoi(raw)
	}
	return limit, offset, err == nil && limit >= 1 && limit <= 500 && offset >= 0 && offset <= 2147483647
}

func listBenchRequests(r *http.Request, tx pgx.Tx, scope complianceWriteScope, limit, offset int) ([]compliancepkg.BenchExecutionRequest, int64, error) {
	const where = ` WHERE protocol_version=2 AND org_id=$1 AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id=$2)`
	var total int64
	err := tx.QueryRow(r.Context(), `SELECT count(*) FROM compliance_bench_run_requests`+where, scope.orgID, scope.clusterID).Scan(&total)
	if err != nil {
		return nil, 0, err
	}
	rows, err := tx.Query(r.Context(), `SELECT id FROM compliance_bench_run_requests`+where+` ORDER BY requested_at DESC,id LIMIT $3 OFFSET $4`, scope.orgID, scope.clusterID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, 0, err
	}
	items := make([]compliancepkg.BenchExecutionRequest, 0, len(ids))
	for _, id := range ids {
		item, err := loadBenchRequest(r.Context(), tx, scope.orgID, id, false)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, total, nil
}
