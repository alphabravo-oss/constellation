package findings

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/risk"
)

// reachabilityBody is the inbound payload for POST /api/v1/findings/{id}/reachability.
//
// Two forms are accepted:
//
//	{"runtime_confirmed": true, "source": "uprobe", "container_id": "...", "pid": 1234}
//	{"static_only": true, "symbol": "pkg.Foo", "module": "pkg", "call_stack": ["a","b"]}
//
// The static_only form is what pkg/reachability/golang produces; the runtime_confirmed
// form is what the runtime Confirmer produces. Both update findings.risk_inputs
// in-place so downstream scoring picks up reachable_static / reachable_runtime.
type reachabilityBody struct {
	RuntimeConfirmed bool     `json:"runtime_confirmed"`
	StaticOnly       bool     `json:"static_only"`
	Source           string   `json:"source"` // "uprobe" | "libload" | "process" | "static"
	ContainerID      string   `json:"container_id"`
	PID              uint32   `json:"pid"`
	Symbol           string   `json:"symbol"`
	Module           string   `json:"module"`
	CallStack        []string `json:"call_stack"`
}

// Reachability handles POST /api/v1/findings/{id}/reachability. Updates the finding's
// risk_inputs.reachable_{static,runtime} fields and re-stamps last_seen_at. Returns
// the updated runtime-reachability subdocument.
func (f *Findings) Reachability(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	var body reachabilityBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request: " + err.Error()})
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())

	// Read current risk_inputs.
	var existing []byte
	if err := f.db.Pool().QueryRow(r.Context(),
		`SELECT COALESCE(risk_inputs, '{}'::jsonb) FROM findings WHERE id = $1 AND org_id = $2`,
		id, subj.OrgID).Scan(&existing); err != nil {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "finding not found"})
		return
	}
	merged := map[string]any{}
	if len(existing) > 0 {
		_ = json.Unmarshal(existing, &merged)
	}
	now := time.Now().UTC()
	switch {
	case body.RuntimeConfirmed:
		merged["reachable_runtime"] = true
		merged["reachable_runtime_at"] = now.Format(time.RFC3339)
		merged["reachable_runtime_source"] = body.Source
		if body.ContainerID != "" {
			merged["reachable_runtime_container_id"] = body.ContainerID
		}
		if body.PID != 0 {
			merged["reachable_runtime_pid"] = body.PID
		}
	case body.StaticOnly:
		merged["reachable_static"] = true
		merged["reachable_static_at"] = now.Format(time.RFC3339)
		merged["reachable_symbol"] = body.Symbol
		merged["reachable_module"] = body.Module
		if len(body.CallStack) > 0 {
			merged["reachable_call_stack"] = body.CallStack
		}
	default:
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "must set runtime_confirmed or static_only"})
		return
	}

	out, err := json.Marshal(merged)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Recompute risk_score from the updated risk_inputs so the 0.15 reachability weight actually
	// moves the stored score (and the risk_score DESC ordering / risk: filter). Without this the
	// score is frozen at its severity-only value and a runtime-confirmed CVE never rises, while the
	// Get detail view's on-the-fly breakdown (risk.Decompose, whose Composite == risk.Compute)
	// would disagree with the stored number.
	var ri struct {
		CVSSBase         float64 `json:"cvss_base"`
		KEVListed        bool    `json:"kev_listed"`
		EPSSProbability  float64 `json:"epss_probability"`
		ReachableStatic  bool    `json:"reachable_static"`
		ReachableRuntime bool    `json:"reachable_runtime"`
		AssetCriticality string  `json:"asset_criticality"`
		Override         bool    `json:"override"`
		OverrideScore    int     `json:"override_score"`
	}
	_ = json.Unmarshal(out, &ri)
	newScore := risk.Compute(risk.Inputs{
		CVSSBase:         ri.CVSSBase,
		KEVListed:        ri.KEVListed,
		EPSSProbability:  ri.EPSSProbability,
		ReachableStatic:  ri.ReachableStatic,
		ReachableRuntime: ri.ReachableRuntime,
		AssetCriticality: ri.AssetCriticality,
		Override:         ri.Override,
		OverrideScore:    ri.OverrideScore,
	})

	if _, err := f.db.Pool().Exec(r.Context(),
		`UPDATE findings SET risk_inputs = $2, risk_score = $4, last_seen_at = NOW() WHERE id = $1 AND org_id = $3`,
		id, out, subj.OrgID, newScore); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	uid := subj.UserID
	oid := subj.OrgID
	action := "finding.reachability.static"
	if body.RuntimeConfirmed {
		action = "finding.reachability.runtime"
	}
	_, _, _ = f.auditLog.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action: action, TargetKind: "finding", TargetID: id.String(),
		After: body,
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok", "risk_inputs": merged, "risk_score": newScore})
}
