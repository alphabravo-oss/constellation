// Host-process snapshot ingest + read endpoints.
//
//	POST /api/v1/host-processes:report   — runtime-agent upsert (auth: runtime-agent-token)
//	GET  /api/v1/host-processes          — list latest per node for caller's org (auth: user JWT, verb=read-findings)
//	GET  /api/v1/host-processes/{node}   — single snapshot lookup (auth: user JWT, verb=read-findings)
//
// Storage: host_processes (migration 049) — one row per (cluster_id, node);
// the agent upserts each interval so reads see the latest snapshot.
package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
)

// HostProcessesPayload is the wire shape the runtime-agent POSTs.
type HostProcessesPayload struct {
	Node       string            `json:"node"`
	ObservedAt time.Time         `json:"observed_at"`
	Count      int               `json:"count"`
	Items      []HostProcessItem `json:"items"`
}

// HostProcessItem mirrors hostscan.Process; duplicated here to keep
// handler decoupled from the agent's internal package.
type HostProcessItem struct {
	PID       int32  `json:"pid"`
	PPID      int32  `json:"ppid"`
	UID       int32  `json:"uid"`
	Comm      string `json:"comm"`
	Cmdline   string `json:"cmdline,omitempty"`
	StartTime int64  `json:"start_time,omitempty"`
	State     string `json:"state,omitempty"`
}

// HostProcessesHandler exposes the POST + GET endpoints.
type HostProcessesHandler struct {
	db *db.DB
}

func NewHostProcesses(d *db.DB) *HostProcessesHandler {
	return &HostProcessesHandler{db: d}
}

func (h *HostProcessesHandler) Report(w http.ResponseWriter, r *http.Request) {
	tok, ok := runtimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	// 4 MiB cap covers a 1000-process snapshot with cmdline cap 2048
	// (~256 bytes/process JSON-encoded × 1000 ≈ 256 KiB, headroom × 16).
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)

	var body HostProcessesPayload
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
	clusterID, err := ResolveAgentClusterID(r.Context(), h.db, tok)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "resolve cluster: "+err.Error())
		return
	}

	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO host_processes (
    org_id, cluster_id, node, process_count, items_count,
    payload, observed_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
ON CONFLICT (org_id, COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid), node) DO UPDATE SET
    process_count = EXCLUDED.process_count,
    items_count   = EXCLUDED.items_count,
    payload       = EXCLUDED.payload,
    observed_at   = EXCLUDED.observed_at,
    updated_at    = NOW()
`,
		tok.OrgID, clusterID, body.Node, body.Count, len(body.Items),
		raw, body.ObservedAt,
	); err != nil {
		jsonError(w, http.StatusInternalServerError, "insert: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// HostProcessesRow is one row in a list/get response.
type HostProcessesRow struct {
	Node         string          `json:"node"`
	ClusterID    *uuid.UUID      `json:"cluster_id,omitempty"`
	ProcessCount int             `json:"process_count"`
	ItemsCount   int             `json:"items_count"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	ObservedAt   time.Time       `json:"observed_at"`
}

func (h *HostProcessesHandler) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT node, cluster_id, process_count, items_count, payload, observed_at
  FROM host_processes
 WHERE org_id = $1
 ORDER BY observed_at DESC
 LIMIT 500`, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()
	out := make([]HostProcessesRow, 0)
	for rows.Next() {
		var rrow HostProcessesRow
		if err := rows.Scan(&rrow.Node, &rrow.ClusterID, &rrow.ProcessCount,
			&rrow.ItemsCount, &rrow.Payload, &rrow.ObservedAt,
		); err != nil {
			jsonError(w, http.StatusInternalServerError, "scan: "+err.Error())
			return
		}
		out = append(out, rrow)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *HostProcessesHandler) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	node := chi.URLParam(r, "node")
	if node == "" {
		jsonError(w, http.StatusBadRequest, "node required")
		return
	}
	var rrow HostProcessesRow
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT node, cluster_id, process_count, items_count, payload, observed_at
  FROM host_processes
 WHERE org_id = $1 AND node = $2
 ORDER BY observed_at DESC
 LIMIT 1`, subj.OrgID, node).Scan(
		&rrow.Node, &rrow.ClusterID, &rrow.ProcessCount,
		&rrow.ItemsCount, &rrow.Payload, &rrow.ObservedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "no host-processes for node")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rrow)
}
