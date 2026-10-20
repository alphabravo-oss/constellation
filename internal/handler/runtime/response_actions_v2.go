package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type processActionV2 struct {
	Version     int    `json:"protocol_version"`
	ID          string `json:"id"`
	ActionToken string `json:"action_token"`
	Type        string `json:"type"`
	Node        string `json:"node"`
	WorkloadID  string `json:"workload_id"`
	ContainerID string `json:"container_id"`
	PID         int    `json:"pid"`
	Comm        string `json:"comm"`
	BootID      string `json:"boot_id"`
	StartBootNS string `json:"start_boot_ns"`
	StartTicks  string `json:"process_start_ticks"`
}

type processResultV2 struct {
	Version     int       `json:"protocol_version"`
	ID          string    `json:"id"`
	ActionToken string    `json:"action_token"`
	Type        string    `json:"type"`
	Node        string    `json:"node"`
	Outcome     string    `json:"outcome"` // applied | refused | uncertain
	Reason      string    `json:"reason"`
	At          time.Time `json:"at"`
}

func (q *quarantineRuntime) enqueueProcessAction(ctx context.Context, workload, reason string) error {
	target := q.processTarget
	if target == nil || strings.TrimSpace(workload) == "" || workload != q.processWorkload || q.sourceAt.IsZero() {
		return errors.New("kill requires the original process event identity")
	}
	if len(target.Node) > 253 || len(workload) > 4096 || len(target.ContainerID) > 256 || len(target.Comm) > 16 {
		return errors.New("process target identity exceeds size limit")
	}
	start, nsErr := strconv.ParseUint(target.StartBootNS, 10, 64)
	ticks, err := strconv.ParseInt(target.StartTicks, 10, 64)
	if nsErr != nil || start == 0 || strconv.FormatUint(start, 10) != target.StartBootNS || strconv.FormatUint(start/uint64(time.Second/100), 10) != target.StartTicks || err != nil || ticks <= 0 || strconv.FormatInt(ticks, 10) != target.StartTicks {
		return errors.New("kill requires kernel process start identity")
	}
	boot, err := uuid.Parse(target.BootID)
	if err != nil || boot == uuid.Nil || target.PID <= 1 || target.PID > math.MaxInt32 || strings.TrimSpace(target.Node) == "" || strings.TrimSpace(target.Comm) == "" {
		return errors.New("kill requires complete process target identity")
	}
	tx, err := q.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var id uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO runtime_response_actions_v2(org_id,cluster_id,node,workload_id,container_id,pid,comm,boot_id,process_start_ticks,start_boot_ns,source_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::numeric,$11) RETURNING id`, q.orgID, q.clusterID, strings.TrimSpace(target.Node), workload, target.ContainerID, target.PID, strings.TrimSpace(target.Comm), boot, ticks, target.StartBootNS, q.sourceAt).Scan(&id)
	if err != nil {
		return err
	}
	_, _, err = audit.New(q.db.Pool()).LogInTx(ctx, tx, audit.Event{OrgID: &q.orgID, Action: "runtime.response_action.queued", TargetKind: "response_action", TargetID: id.String(), After: map[string]any{"cluster_id": q.clusterID, "node": target.Node, "workload_id": workload, "pid": target.PID, "process_start_ticks": target.StartTicks, "start_boot_ns": target.StartBootNS, "boot_id": boot, "reason": reason}})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *ResponseActions) processAgentScope(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, 401, "runtime-agent token required")
		return uuid.Nil, uuid.Nil, false
	}
	cluster, err := handler.ResolveAgentClusterID(r.Context(), h.db, tok)
	if errors.Is(err, handler.ErrAgentClusterScope) || err == nil && cluster == nil {
		jsonError(w, 403, "agent token cluster scope mismatch")
		return uuid.Nil, uuid.Nil, false
	}
	if err != nil {
		jsonError(w, 500, "resolve cluster failed")
		return uuid.Nil, uuid.Nil, false
	}
	return tok.OrgID, *cluster, true
}

// PendingV2 returns exact process requests only. The node selector is checked
// against each row; cluster tokens do not independently authenticate a node.
func (h *ResponseActions) PendingV2(w http.ResponseWriter, r *http.Request) {
	org, cluster, ok := h.processAgentScope(w, r)
	if !ok {
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(values["cluster_id"]) != 1 || len(values["node"]) != 1 {
		jsonError(w, 400, "cluster_id and node are required exactly once")
		return
	}
	requested, err := uuid.Parse(values.Get("cluster_id"))
	node := strings.TrimSpace(values.Get("node"))
	if err != nil || node == "" || len(node) > 253 {
		jsonError(w, 400, "cluster_id and node are required")
		return
	}
	if requested != cluster {
		jsonError(w, 403, "agent token cluster scope mismatch")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `SELECT id,action_token,node,workload_id,container_id,pid,comm,boot_id,process_start_ticks::text,start_boot_ns::text FROM runtime_response_actions_v2 WHERE org_id=$1 AND cluster_id=$2 AND node=$3 AND state='pending' ORDER BY created_at,id LIMIT 100`, org, cluster, node)
	if err != nil {
		jsonError(w, 500, "process actions unavailable")
		return
	}
	defer rows.Close()
	actions := []processActionV2{}
	encodedBytes := 0
	for rows.Next() {
		a := processActionV2{Version: 2, Type: "kill_process"}
		if err := rows.Scan(&a.ID, &a.ActionToken, &a.Node, &a.WorkloadID, &a.ContainerID, &a.PID, &a.Comm, &a.BootID, &a.StartTicks, &a.StartBootNS); err != nil {
			jsonError(w, 500, "process actions unavailable")
			return
		}
		encoded, err := json.Marshal(a)
		if err != nil {
			jsonError(w, 500, "process actions unavailable")
			return
		}
		// Bound escaped JSON, not just source string sizes. Leave ample room
		// for the scoped envelope, separators, and the encoder's final newline.
		if encodedBytes+len(encoded)+1 > (1<<20)-4096 {
			break
		}
		encodedBytes += len(encoded) + 1
		actions = append(actions, a)
	}
	if rows.Err() != nil {
		jsonError(w, 500, "process actions unavailable")
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"protocol_version": 2, "cluster_id": cluster, "node": node, "actions": actions})
}

func (h *ResponseActions) ResultV2(w http.ResponseWriter, r *http.Request) {
	org, cluster, ok := h.processAgentScope(w, r)
	if !ok {
		return
	}
	result, body, err := decodeProcessResult(w, r)
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	id, _ := uuid.Parse(result.ID)
	token, _ := uuid.Parse(result.ActionToken)
	ctx := r.Context()
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, 500, "process result unavailable")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var state, workload string
	var same bool
	err = tx.QueryRow(r.Context(), `SELECT state,workload_id,COALESCE(result_body=$6::jsonb,false) FROM runtime_response_actions_v2 WHERE id=$1 AND action_token=$2 AND org_id=$3 AND cluster_id=$4 AND node=$5 FOR UPDATE`, id, token, org, cluster, result.Node, body).Scan(&state, &workload, &same)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, 404, "process action not found")
		return
	}
	if err != nil {
		jsonError(w, 500, "process result unavailable")
		return
	}
	if state != "pending" && !same {
		jsonError(w, 409, "process action already has a different result")
		return
	}
	if state == "pending" {
		state = "failed"
		if result.Outcome == "applied" {
			state = "done"
		}
		if result.Outcome == "uncertain" {
			state = "uncertain"
		}
		if _, err = tx.Exec(r.Context(), `UPDATE runtime_response_actions_v2 SET state=$2,result_body=$3,completed_at=now() WHERE id=$1`, id, state, body); err != nil {
			jsonError(w, 500, "process result unavailable")
			return
		}
		_, _, err = audit.New(h.db.Pool()).LogInTx(r.Context(), tx, audit.Event{OrgID: &org, Action: "runtime.response_action.result", TargetKind: "response_action", TargetID: id.String(), After: map[string]any{"cluster_id": cluster, "node": result.Node, "workload_id": workload, "outcome": result.Outcome, "reason": result.Reason}})
		if err != nil {
			jsonError(w, 500, "process result unavailable")
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, 500, "process result unavailable")
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"acknowledged": true, "protocol_version": 2, "id": result.ID, "action_token": result.ActionToken, "node": result.Node, "outcome": result.Outcome, "state": state})
}

func decodeProcessResult(w http.ResponseWriter, r *http.Request) (processResultV2, []byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var result processResultV2
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return processResultV2{}, nil, errors.New("invalid process result")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return processResultV2{}, nil, errors.New("exactly one process result is required")
	}
	id, idErr := uuid.Parse(result.ID)
	token, tokenErr := uuid.Parse(result.ActionToken)
	if idErr != nil || tokenErr != nil || id == uuid.Nil || token == uuid.Nil || result.Version != 2 || result.Type != "kill_process" || strings.TrimSpace(result.Node) == "" || len(result.Node) > 253 || result.At.IsZero() || len(result.Reason) > 4096 || (result.Outcome != "applied" && result.Outcome != "refused" && result.Outcome != "uncertain") {
		return processResultV2{}, nil, errors.New("invalid process result identity or outcome")
	}
	body, err := json.Marshal(result)
	if err != nil {
		return processResultV2{}, nil, errors.New("invalid process result")
	}
	return result, body, nil
}
