package policy

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/notify"
)

// Delete removes a policy by id, scoped to the caller's org.
func (p *Policies) Delete(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad id")
		return
	}
	// Capture the name (and fed status) before deleting so we can both reject local
	// deletes of fed rows and emit a delete tombstone for master-owned rows.
	var name, cfgType string
	if err := p.db.Pool().QueryRow(r.Context(),
		`SELECT name, cfg_type FROM policies WHERE id = $1 AND org_id = $2`, id, subj.OrgID).
		Scan(&name, &cfgType); err != nil {
		jsonError(w, http.StatusNotFound, "policy not found")
		return
	}
	if cfgType == "fed" {
		jsonError(w, http.StatusForbidden, handler.ErrFedReadOnly().Error())
		return
	}
	tag, err := p.db.Pool().Exec(r.Context(),
		`DELETE FROM policies WHERE id = $1 AND org_id = $2`, id, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "policy not found")
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	// G3a: propagate the deletion to joints via a tombstone revision (master only).
	handler.LogFedRevision(r.Context(), p.db.Pool(), oid, "policy_delete", id.String(), handler.FedSyncPayload{OrgID: oid, Name: name})
	if p.auditLog != nil {
		_, _, _ = p.auditLog.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "policy.delete",
			TargetKind: "policy", TargetID: id.String(),
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

type bulkPolicyOp struct {
	Op   string          `json:"op"` // create | update | delete | enable | disable
	ID   *uuid.UUID      `json:"id,omitempty"`
	Body json.RawMessage `json:"body,omitempty"`
}

type bulkPolicyRequest struct {
	Operations []bulkPolicyOp `json:"operations"`
}

type bulkPolicyResult struct {
	Op     string `json:"op"`
	ID     string `json:"id,omitempty"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Bulk applies a sequence of policy operations in a single transaction. All-or-nothing:
// any error in any op rolls back the whole batch. Audit envelopes are written per-op
// after commit so the chain reflects what actually persisted.
func (p *Policies) Bulk(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var req bulkPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Operations) == 0 {
		jsonError(w, http.StatusBadRequest, "operations required")
		return
	}
	if len(req.Operations) > 200 {
		jsonError(w, http.StatusBadRequest, "max 200 operations per batch")
		return
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	tx, err := p.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	var lockedOrgID uuid.UUID
	if err := tx.QueryRow(r.Context(), `SELECT id FROM orgs WHERE id=$1 FOR KEY SHARE`, subj.OrgID).Scan(&lockedOrgID); err != nil {
		jsonError(w, http.StatusInternalServerError, "org: "+err.Error())
		return
	}
	if _, err := tx.Exec(r.Context(), `LOCK TABLE policies IN ROW EXCLUSIVE MODE`); err != nil {
		jsonError(w, http.StatusInternalServerError, "policies: "+err.Error())
		return
	}
	if clusterArg != nil {
		var clusterID uuid.UUID
		if err := tx.QueryRow(r.Context(), `SELECT id FROM clusters WHERE id=$1 AND org_id=$2 FOR KEY SHARE`, clusterArg, subj.OrgID).Scan(&clusterID); err != nil {
			if err == pgx.ErrNoRows {
				jsonError(w, http.StatusBadRequest, "cluster not found")
			} else {
				jsonError(w, http.StatusInternalServerError, "cluster: "+err.Error())
			}
			return
		}
	}

	// fedRevisions collects one revision intent per persisted op; emitted after the
	// tx commits (recordFedRevision is a no-op unless this org is a master). Kept
	// out of the tx because revision numbering reads other committed rows.
	type fedRev struct {
		kind, ruleID string
		payload      handler.FedSyncPayload
	}
	var fedRevisions []fedRev

	// Lock the current row before checking its resulting admission selectors.
	policyTx := func(id uuid.UUID) (string, string, *uuid.UUID, string, error) {
		var cfg, engine, specYAML string
		var clusterID *uuid.UUID
		err := tx.QueryRow(r.Context(),
			`SELECT cfg_type, engine, spec_yaml, cluster_id FROM policies WHERE id=$1 AND org_id=$2 FOR UPDATE`, id, subj.OrgID).
			Scan(&cfg, &engine, &specYAML, &clusterID)
		return cfg, engine, clusterID, specYAML, err
	}
	lockGroups := func(engine, specYAML string, clusterID any) bool {
		if err := p.lockAdmissionPolicyGroups(r.Context(), tx, subj.OrgID, clusterID, admissionPolicyGroupSelectors(engine, specYAML)); err != nil {
			if err == pgx.ErrNoRows {
				jsonError(w, http.StatusBadRequest, "group not found")
			} else {
				jsonError(w, http.StatusInternalServerError, "group: "+err.Error())
			}
			return false
		}
		return true
	}

	results := make([]bulkPolicyResult, 0, len(req.Operations))
	for _, op := range req.Operations {
		res := bulkPolicyResult{Op: op.Op}
		switch op.Op {
		case "create":
			var body createPolicyBody
			if err := json.Unmarshal(op.Body, &body); err != nil {
				jsonError(w, http.StatusBadRequest, "bad create body: "+err.Error())
				return
			}
			if body.Mode == "" {
				body.Mode = "monitor"
			}
			if !lockGroups(body.Engine, body.SpecYAML, clusterArg) {
				return
			}
			id := uuid.New()
			if _, err := tx.Exec(r.Context(), `
INSERT INTO policies (id, org_id, cluster_id, name, description, engine, category, spec_yaml, enabled, mode)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
				id, subj.OrgID, clusterArg, body.Name, body.Description, body.Engine, body.Category,
				body.SpecYAML, body.Enabled, body.Mode); err != nil {
				jsonError(w, http.StatusInternalServerError, "create: "+err.Error())
				return
			}
			res.ID = id.String()
			res.Status = "created"
			fedRevisions = append(fedRevisions, fedRev{kind: "policy", ruleID: id.String(), payload: handler.FedSyncPayload{
				OrgID: subj.OrgID, Name: body.Name, Description: body.Description, Engine: body.Engine,
				Category: body.Category, SpecYAML: body.SpecYAML, Mode: body.Mode, Enabled: body.Enabled}})
		case "update":
			if op.ID == nil {
				jsonError(w, http.StatusBadRequest, "update requires id")
				return
			}
			cfg, engine, policyClusterID, specYAML, err := policyTx(*op.ID)
			if err != nil {
				jsonError(w, http.StatusNotFound, "update: policy not found")
				return
			} else if cfg == "fed" {
				jsonError(w, http.StatusForbidden, "update: "+handler.ErrFedReadOnly().Error())
				return
			}
			var body updatePolicyBody
			if err := json.Unmarshal(op.Body, &body); err != nil {
				jsonError(w, http.StatusBadRequest, "bad update body: "+err.Error())
				return
			}
			if body.SpecYAML != nil {
				specYAML = *body.SpecYAML
			}
			if !lockGroups(engine, specYAML, policyClusterID) {
				return
			}
			if _, err := tx.Exec(r.Context(), `
UPDATE policies SET
  enabled   = COALESCE($3, enabled),
  mode      = COALESCE($4, mode),
  spec_yaml = COALESCE($5, spec_yaml),
  updated_at = NOW()
 WHERE id = $1 AND org_id = $2`,
				*op.ID, subj.OrgID, body.Enabled, body.Mode, body.SpecYAML); err != nil {
				jsonError(w, http.StatusInternalServerError, "update: "+err.Error())
				return
			}
			res.ID = op.ID.String()
			res.Status = "updated"
			// Read back the post-update row so the revision carries the full body.
			var pl handler.FedSyncPayload
			if err := tx.QueryRow(r.Context(),
				`SELECT name, COALESCE(description,''), engine, category, spec_yaml, mode, enabled
				   FROM policies WHERE id=$1 AND org_id=$2`, *op.ID, subj.OrgID).
				Scan(&pl.Name, &pl.Description, &pl.Engine, &pl.Category, &pl.SpecYAML, &pl.Mode, &pl.Enabled); err == nil {
				pl.OrgID = subj.OrgID
				fedRevisions = append(fedRevisions, fedRev{kind: "policy", ruleID: op.ID.String(), payload: pl})
			}
		case "delete":
			if op.ID == nil {
				jsonError(w, http.StatusBadRequest, "delete requires id")
				return
			}
			var name, cfg string
			if err := tx.QueryRow(r.Context(),
				`SELECT name, cfg_type FROM policies WHERE id=$1 AND org_id=$2 FOR UPDATE`, *op.ID, subj.OrgID).
				Scan(&name, &cfg); err != nil {
				jsonError(w, http.StatusNotFound, "delete: policy not found")
				return
			}
			if cfg == "fed" {
				jsonError(w, http.StatusForbidden, "delete: "+handler.ErrFedReadOnly().Error())
				return
			}
			if _, err := tx.Exec(r.Context(),
				`DELETE FROM policies WHERE id = $1 AND org_id = $2`, *op.ID, subj.OrgID); err != nil {
				jsonError(w, http.StatusInternalServerError, "delete: "+err.Error())
				return
			}
			res.ID = op.ID.String()
			res.Status = "deleted"
			fedRevisions = append(fedRevisions, fedRev{kind: "policy_delete", ruleID: op.ID.String(),
				payload: handler.FedSyncPayload{OrgID: subj.OrgID, Name: name}})
		case "enable", "disable":
			if op.ID == nil {
				jsonError(w, http.StatusBadRequest, op.Op+" requires id")
				return
			}
			cfg, engine, policyClusterID, specYAML, err := policyTx(*op.ID)
			if err != nil {
				jsonError(w, http.StatusNotFound, op.Op+": policy not found")
				return
			} else if cfg == "fed" {
				jsonError(w, http.StatusForbidden, op.Op+": "+handler.ErrFedReadOnly().Error())
				return
			}
			if !lockGroups(engine, specYAML, policyClusterID) {
				return
			}
			enabled := op.Op == "enable"
			if _, err := tx.Exec(r.Context(),
				`UPDATE policies SET enabled = $1, updated_at = NOW() WHERE id = $2 AND org_id = $3`,
				enabled, *op.ID, subj.OrgID); err != nil {
				jsonError(w, http.StatusInternalServerError, op.Op+": "+err.Error())
				return
			}
			res.ID = op.ID.String()
			res.Status = op.Op + "d"
			var pl handler.FedSyncPayload
			if err := tx.QueryRow(r.Context(),
				`SELECT name, COALESCE(description,''), engine, category, spec_yaml, mode, enabled
				   FROM policies WHERE id=$1 AND org_id=$2`, *op.ID, subj.OrgID).
				Scan(&pl.Name, &pl.Description, &pl.Engine, &pl.Category, &pl.SpecYAML, &pl.Mode, &pl.Enabled); err == nil {
				pl.OrgID = subj.OrgID
				fedRevisions = append(fedRevisions, fedRev{kind: "policy", ruleID: op.ID.String(), payload: pl})
			}
		default:
			jsonError(w, http.StatusBadRequest, "unknown op: "+op.Op)
			return
		}
		results = append(results, res)
	}

	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit: "+err.Error())
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	// G3a: record one fed revision per persisted op (master only, best-effort).
	for _, fr := range fedRevisions {
		handler.LogFedRevision(r.Context(), p.db.Pool(), oid, fr.kind, fr.ruleID, fr.payload)
	}
	if p.auditLog != nil {
		_, _, _ = p.auditLog.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "policy.bulk",
			TargetKind: "policy", TargetID: "batch",
			After: map[string]any{"count": len(results), "results": results},
		})
	}
	if p.dispatcher != nil {
		_, _ = p.dispatcher.Dispatch(r.Context(), notify.Event{
			Kind: "policy.bulk", OrgID: oid, Severity: "info",
			Title:   "Policy bulk batch applied",
			Labels:  map[string]string{"lifecycle": "policy.bulk"},
			Payload: map[string]any{"count": len(results), "results": results},
			URL:     "/policies",
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"results": results})
}
