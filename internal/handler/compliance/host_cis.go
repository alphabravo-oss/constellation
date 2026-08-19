// Host CIS benchmark ingest + read endpoints (Slice E).
//
//	POST /api/v1/host-cis:report   — runtime-agent upsert (auth: runtime-agent-token)
//	GET  /api/v1/host-cis          — list latest per node for caller's org (auth: user JWT)
//	GET  /api/v1/host-cis/{node}   — single snapshot lookup (auth: user JWT)
package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/notify"
	"github.com/alphabravocompany/constellation/pkg/response"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

type HostCISPayload struct {
	Node       string         `json:"node"`
	ObservedAt time.Time      `json:"observed_at"`
	Profile    string         `json:"profile,omitempty"`
	Passed     int            `json:"passed"`
	Failed     int            `json:"failed"`
	Warned     int            `json:"warned"`
	Skipped    int            `json:"skipped"`
	Checks     []HostCISCheck `json:"checks"`
}

type HostCISCheck struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
}

type HostCISHandler struct {
	db     *db.DB
	alerts complianceResponder
}

func NewHostCIS(d *db.DB) *HostCISHandler {
	return &HostCISHandler{db: d}
}

// WithResponseAlerts wires the RT-2 response hook, the E1 declarative evaluator, and
// the notify dispatcher so failed host-CIS controls fire response rules, webhooks, and
// the syslog mirror (P1-16). Any argument may be nil. Returns the receiver for chaining.
func (h *HostCISHandler) WithResponseAlerts(
	respond func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event),
	eval func(ctx context.Context, orgID uuid.UUID, ev *responserule.Event) ([]responserule.Action, error),
	dispatcher *notify.Dispatcher,
) *HostCISHandler {
	h.alerts = complianceResponder{respond: respond, evalRules: eval, dispatcher: dispatcher}
	return h
}

func (h *HostCISHandler) Report(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB — checks are small

	var body HostCISPayload
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if strings.TrimSpace(body.Node) == "" {
		jsonError(w, http.StatusBadRequest, "node is required")
		return
	}
	if body.ObservedAt.IsZero() {
		body.ObservedAt = time.Now().UTC()
	}
	raw, err := json.Marshal(&body)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "re-encode: "+err.Error())
		return
	}

	// Attribute to the cluster the agent token was minted for (init-bundle),
	// not the org's oldest cluster. clusterID is nil only for a token with no
	// bundle mapping; the upsert stays NULL-safe (dedups on (org_id, node)).
	clusterID, err := handler.ResolveAgentClusterID(r.Context(), h.db, tok)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "resolve cluster: "+err.Error())
		return
	}

	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO host_cis (
    org_id, cluster_id, node, profile, passed, failed, warned, skipped,
    payload, observed_at, updated_at
) VALUES ($1, $2, $3, NULLIF($4,''), $5, $6, $7, $8, $9, $10, NOW())
ON CONFLICT (org_id, COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid), node) DO UPDATE SET
    profile     = EXCLUDED.profile,
    passed      = EXCLUDED.passed,
    failed      = EXCLUDED.failed,
    warned      = EXCLUDED.warned,
    skipped     = EXCLUDED.skipped,
    payload     = EXCLUDED.payload,
    observed_at = EXCLUDED.observed_at,
    updated_at  = NOW()
`,
		tok.OrgID, clusterID, body.Node, body.Profile,
		body.Passed, body.Failed, body.Warned, body.Skipped,
		raw, body.ObservedAt,
	); err != nil {
		jsonError(w, http.StatusInternalServerError, "insert: "+err.Error())
		return
	}

	// Close the compliance->response loop for host-CIS: each failed control fires
	// response rules, webhooks, and the syslog mirror (P1-16). clusterID may be nil
	// (token with no bundle mapping), which loads the org-scoped response rules.
	var failures []complianceFailure
	for _, ck := range body.Checks {
		if !strings.EqualFold(ck.Result, "fail") {
			continue
		}
		failures = append(failures, complianceFailure{
			CheckID: ck.ID,
			Title:   ck.Title,
			Node:    body.Node,
			Detail:  ck.Detail,
		})
	}
	cid := uuid.Nil
	if clusterID != nil {
		cid = *clusterID
	}
	h.alerts.fire(r.Context(), tok.OrgID, cid, failures)

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type HostCISRow struct {
	Node       string          `json:"node"`
	ClusterID  *uuid.UUID      `json:"cluster_id,omitempty"`
	Profile    string          `json:"profile,omitempty"`
	Passed     int             `json:"passed"`
	Failed     int             `json:"failed"`
	Warned     int             `json:"warned"`
	Skipped    int             `json:"skipped"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	ObservedAt time.Time       `json:"observed_at"`
}

func (h *HostCISHandler) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT node, cluster_id, COALESCE(profile,''), passed, failed, warned, skipped,
       payload, observed_at
  FROM host_cis
 WHERE org_id = $1
 ORDER BY observed_at DESC
 LIMIT 500`, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()
	out := make([]HostCISRow, 0)
	for rows.Next() {
		var rrow HostCISRow
		if err := rows.Scan(&rrow.Node, &rrow.ClusterID, &rrow.Profile,
			&rrow.Passed, &rrow.Failed, &rrow.Warned, &rrow.Skipped,
			&rrow.Payload, &rrow.ObservedAt,
		); err != nil {
			jsonError(w, http.StatusInternalServerError, "scan: "+err.Error())
			return
		}
		out = append(out, rrow)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *HostCISHandler) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	node := chi.URLParam(r, "node")
	if node == "" {
		jsonError(w, http.StatusBadRequest, "node required")
		return
	}
	var rrow HostCISRow
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT node, cluster_id, COALESCE(profile,''), passed, failed, warned, skipped,
       payload, observed_at
  FROM host_cis
 WHERE org_id = $1 AND node = $2
 ORDER BY observed_at DESC
 LIMIT 1`, subj.OrgID, node).Scan(
		&rrow.Node, &rrow.ClusterID, &rrow.Profile,
		&rrow.Passed, &rrow.Failed, &rrow.Warned, &rrow.Skipped,
		&rrow.Payload, &rrow.ObservedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "no host-cis for node")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rrow)
}
