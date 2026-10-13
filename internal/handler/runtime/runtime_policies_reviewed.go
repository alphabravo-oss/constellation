package runtime

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Distinct reviewed routes fail closed on old replicas rather than silently
// ignoring a precondition added to the legacy request body.
type reviewedPolicyRequest struct {
	UpdatePolicyRequest
	ClusterID       uuid.UUID `json:"cluster_id"`
	ExpectedVersion string    `json:"expected_version"`
}

func (h *RuntimePoliciesHTTP) ReviewedUpdate(w http.ResponseWriter, r *http.Request) {
	h.reviewedMutation(w, r, "update")
}
func (h *RuntimePoliciesHTTP) ReviewedPromote(w http.ResponseWriter, r *http.Request) {
	h.reviewedMutation(w, r, "promote")
}
func (h *RuntimePoliciesHTTP) ReviewedDemote(w http.ResponseWriter, r *http.Request) {
	h.reviewedMutation(w, r, "demote")
}
func (h *RuntimePoliciesHTTP) ReviewedDisable(w http.ResponseWriter, r *http.Request) {
	h.reviewedMutation(w, r, "disable")
}
func (h *RuntimePoliciesHTTP) ReviewedDelete(w http.ResponseWriter, r *http.Request) {
	h.reviewedMutation(w, r, "delete")
}

func (h *RuntimePoliciesHTTP) reviewedMutation(w http.ResponseWriter, r *http.Request, operation string) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, 401, "auth required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, 400, "invalid id")
		return
	}
	var req reviewedPolicyRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		jsonError(w, 400, "invalid body: "+err.Error())
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		jsonError(w, 400, "one JSON body required")
		return
	}
	if req.ClusterID == uuid.Nil {
		jsonError(w, 400, "cluster_id is required")
		return
	}
	if req.ExpectedVersion == "" {
		jsonError(w, 428, "expected_version is required")
		return
	}
	version, err := strconv.ParseInt(req.ExpectedVersion, 10, 64)
	if err != nil || version <= 0 || strconv.FormatInt(version, 10) != req.ExpectedVersion {
		jsonError(w, 400, "expected_version must be a positive decimal string")
		return
	}
	if operation != "update" && (req.Rules != nil || req.Name != nil || req.DefAction != nil || req.ApplyDir != nil) {
		jsonError(w, 400, "only cluster_id and expected_version are accepted for this action")
		return
	}
	if req.Name != nil && strings.TrimSpace(*req.Name) == "" {
		jsonError(w, 400, "name must not be empty")
		return
	}
	tx, err := h.store.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	var owned bool
	if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND org_id=$2)`, req.ClusterID, sub.OrgID).Scan(&owned); err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	if !owned {
		jsonError(w, 404, "cluster not found")
		return
	}
	before, err := scanPolicy(tx.QueryRow(r.Context(), `SELECT `+policySelectCols+` FROM runtime_policies WHERE id=$1 AND org_id=$2 AND cluster_id=$3 FOR UPDATE`, id, sub.OrgID, req.ClusterID))
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, 404, "policy not found in this cluster")
		return
	}
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	if before.Version != version {
		jsonError(w, 409, "policy changed; refresh and review its current configuration")
		return
	}
	after := *before
	action := audit.ActionPolicyUpdate
	switch operation {
	case "update":
		if req.Rules != nil {
			after.Rules = *req.Rules
		}
		if req.Name != nil {
			after.Name = *req.Name
		}
		if req.DefAction != nil {
			after.DefAction = *req.DefAction
		}
		if req.ApplyDir != nil {
			after.ApplyDir = *req.ApplyDir
		}
	case "promote":
		after.Mode = PolicyModeEnforce
		action = audit.ActionPolicyPromote
	case "demote":
		after.Mode = PolicyModeMonitor
		action = audit.ActionPolicyDemote
	case "disable":
		after.Mode = PolicyModeDisabled
		action = audit.ActionPolicyDisable
	case "delete":
		action = audit.ActionPolicyDelete
	}
	if operation == "delete" {
		tag, err := tx.Exec(r.Context(), `DELETE FROM runtime_policies WHERE id=$1 AND org_id=$2 AND cluster_id=$3 AND version=$4`, id, sub.OrgID, req.ClusterID, version)
		if err != nil {
			jsonError(w, 500, err.Error())
			return
		}
		if tag.RowsAffected() != 1 {
			jsonError(w, 409, "policy changed")
			return
		}
	} else {
		// The historic trigger omits name-only edits. Explicitly bumping once also
		// makes reviewed no-op/mode actions invalidate a previous review safely.
		got, err := scanPolicy(tx.QueryRow(r.Context(), `UPDATE runtime_policies SET rules=$1::jsonb,def_action=$2,apply_dir=$3,name=$4,mode=$5,updated_by=$6,version=version+1,updated_at=NOW() WHERE id=$7 AND org_id=$8 AND cluster_id=$9 AND version=$10 RETURNING `+policySelectCols, string(after.Rules), int16(after.DefAction), int16(after.ApplyDir), after.Name, string(after.Mode), sub.UserID, id, sub.OrgID, req.ClusterID, version))
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, 409, "policy changed")
			return
		}
		if err != nil {
			jsonError(w, 500, err.Error())
			return
		}
		after = *got
	}
	if h.store.auditLog != nil {
		// Preserve the action vocabulary while recording the exact owned cluster and
		// reviewed revision in the same transaction as the write.
		payload := func(p *RuntimePolicy) map[string]any {
			s := snapshot(p)
			return map[string]any{"id": s.ID, "cluster_id": p.ClusterID, "workload": s.Workload, "namespace": s.Namespace, "name": s.Name, "mode": s.Mode, "rule_count": s.RuleCount, "version": s.Version, "revision": p.Revision}
		}
		var afterAudit any
		if operation != "delete" {
			afterAudit = payload(&after)
		}
		if _, _, err := h.store.auditLog.LogInTx(r.Context(), tx, audit.Event{OrgID: &sub.OrgID, ActorID: &sub.UserID, Action: action, TargetKind: audit.TargetKindPolicy, TargetID: id.String(), Before: payload(before), After: afterAudit, RequestID: requestIDFrom(r)}); err != nil {
			jsonError(w, 500, err.Error())
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	if operation == "delete" {
		httpx.WriteJSON(w, 200, map[string]any{"deleted": id, "id": id, "cluster_id": before.ClusterID, "workload": before.Workload, "revision": before.Revision})
		return
	}
	httpx.WriteJSON(w, 200, &after)
}
