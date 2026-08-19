package policy

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"

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
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
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

	tx, err := p.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// fedRevisions collects one revision intent per persisted op; emitted after the
	// tx commits (recordFedRevision is a no-op unless this org is a master). Kept
	// out of the tx because revision numbering reads other committed rows.
	type fedRev struct {
		kind, ruleID string
		payload      handler.FedSyncPayload
	}
	var fedRevisions []fedRev

	// isFedTx reports whether a policy row is fed (read-only) within the tx, so a
	// bulk op cannot smuggle a local mutation past the single-handler guard.
	isFedTx := func(id uuid.UUID) (bool, error) {
		var cfg string
		err := tx.QueryRow(r.Context(),
			`SELECT cfg_type FROM policies WHERE id=$1 AND org_id=$2`, id, subj.OrgID).Scan(&cfg)
		if err != nil {
			return false, err
		}
		return cfg == "fed", nil
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
			id := uuid.New()
			if _, err := tx.Exec(r.Context(), `
INSERT INTO policies (id, org_id, name, description, engine, category, spec_yaml, enabled, mode)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
				id, subj.OrgID, body.Name, body.Description, body.Engine, body.Category,
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
			if isFed, err := isFedTx(*op.ID); err != nil {
				jsonError(w, http.StatusInternalServerError, "update: "+err.Error())
				return
			} else if isFed {
				jsonError(w, http.StatusForbidden, "update: "+handler.ErrFedReadOnly().Error())
				return
			}
			var body updatePolicyBody
			if err := json.Unmarshal(op.Body, &body); err != nil {
				jsonError(w, http.StatusBadRequest, "bad update body: "+err.Error())
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
				`SELECT name, cfg_type FROM policies WHERE id=$1 AND org_id=$2`, *op.ID, subj.OrgID).
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
			if isFed, err := isFedTx(*op.ID); err != nil {
				jsonError(w, http.StatusInternalServerError, op.Op+": "+err.Error())
				return
			} else if isFed {
				jsonError(w, http.StatusForbidden, op.Op+": "+handler.ErrFedReadOnly().Error())
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
