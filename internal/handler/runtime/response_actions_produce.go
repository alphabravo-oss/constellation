// RT-KILL-02 server producer: the response-action queue's read + result endpoints.
//
// A response RULE with a kill action enqueues a runtime_response_actions row (see
// quarantineRuntime.Kill). The runtime-agent's responder (cmd/constellation-runtime-agent/
// response_actions.go) drives two endpoints against this producer:
//
//	GET  /api/v1/runtime/response-actions:pending?cluster_id=<id>&node=<node>  (runtime-agent token)
//	POST /api/v1/runtime/response-actions:result                               (runtime-agent token)
//
// Wire these in internal/server/server.go inside the runtime-agent-token group
// (r.Use(handler.RuntimeAgentTokenMiddleware(s.db.Pool()))), next to the other
// agent bundles (:bundle / :sync), EXACTLY as:
//
//	rap := runtime.NewResponseActions(s.db)
//	r.Get("/runtime/response-actions:pending", rap.Pending)
//	r.Post("/runtime/response-actions:result", rap.Result)
//
// The GET returns pending rows for the calling node's cluster, org-scoped by the token,
// marshalled as the responseAction wire shape the responder decodes. The POST is the
// result sink: it flips a row to done|failed and records result/error + completed_at.
package runtime

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// ResponseActions is the server-side producer for runtime kill_process / kill_session
// response actions consumed by the runtime-agent responder.
type ResponseActions struct {
	db *db.DB
}

// NewResponseActions constructs the producer handler.
func NewResponseActions(d *db.DB) *ResponseActions { return &ResponseActions{db: d} }

// responseActionWire is one pending action as the agent decodes it. Field names + types
// MUST stay byte-for-byte identical to responseAction in the agent's response_actions.go —
// that struct is the only consumer.
type responseActionWire struct {
	ID          string `json:"id"`
	Type        string `json:"type"` // "kill_process" | "kill_session"
	WorkloadID  string `json:"workload_id,omitempty"`
	ContainerID string `json:"container_id,omitempty"`

	PID  int    `json:"pid,omitempty"`
	Comm string `json:"comm,omitempty"`

	Protocol string `json:"protocol,omitempty"`
	SrcIP    string `json:"src_ip,omitempty"`
	SrcPort  int    `json:"src_port,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	DstPort  int    `json:"dst_port,omitempty"`
}

// responseActionsEnvelope wraps the pending list; the agent decodes {"actions":[...]}.
type responseActionsEnvelope struct {
	Actions []responseActionWire `json:"actions"`
}

// responseActionResultWire is the agent's report shape (matches responseActionResult in the
// agent's response_actions.go).
type responseActionResultWire struct {
	ID      string    `json:"id"`
	Type    string    `json:"type"`
	Node    string    `json:"node,omitempty"`
	Applied bool      `json:"applied"`
	Reason  string    `json:"reason,omitempty"`
	At      time.Time `json:"at"`
}

// Pending returns the pending response actions for the calling node's cluster, org-scoped
// by the runtime-agent token so a token for org A can never read org B's queue even with a
// guessed cluster_id. Rows with an empty node are offered to every node in the cluster.
func (h *ResponseActions) Pending(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	clusterID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	node := strings.TrimSpace(r.URL.Query().Get("node"))

	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, type, workload_id, container_id, pid, comm,
       protocol, src_ip, src_port, dst_ip, dst_port
  FROM runtime_response_actions
 WHERE org_id = $1
   AND cluster_id = $2
   AND state = 'pending'
   AND (node = $3 OR node = '')
 ORDER BY created_at`,
		tok.OrgID, clusterID, node)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	out := responseActionsEnvelope{Actions: []responseActionWire{}}
	for rows.Next() {
		var a responseActionWire
		if err := rows.Scan(&a.ID, &a.Type, &a.WorkloadID, &a.ContainerID, &a.PID, &a.Comm,
			&a.Protocol, &a.SrcIP, &a.SrcPort, &a.DstIP, &a.DstPort); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out.Actions = append(out.Actions, a)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// Result is the sink for a completed action. It flips the row to done (Applied) or failed
// (not Applied), records the agent's reason into result/error, and stamps completed_at.
// Org-scoped by the token so an agent can only complete its own org's rows. Terminal rows
// aren't re-touched (state = 'pending' guard), so a duplicate report is a harmless no-op.
func (h *ResponseActions) Result(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var res responseActionResultWire
	if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(res.ID))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "id is required")
		return
	}

	state := "failed"
	result, errText := "", res.Reason
	if res.Applied {
		state, result, errText = "done", res.Reason, ""
	}
	tag, err := h.db.Pool().Exec(r.Context(), `
UPDATE runtime_response_actions
   SET state = $1, result = $2, error = $3, completed_at = NOW()
 WHERE id = $4 AND org_id = $5 AND state = 'pending'`,
		state, result, errText, id, tok.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// A zero-row update means the id is unknown, cross-org, or already terminal — all
	// benign for an at-least-once reporter, so ack rather than error.
	_ = tag
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
