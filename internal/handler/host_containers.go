// Host-container snapshot ingest + read endpoints.
//
//	POST /api/v1/host-containers:report   — runtime-agent upsert (auth: runtime-agent-token)
//	GET  /api/v1/host-containers          — list latest per node for caller's org (auth: user JWT)
//	GET  /api/v1/host-containers/{node}   — single snapshot lookup (auth: user JWT)
//
// Storage: host_containers (migration 050) — one row per (cluster_id, node).
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

type HostContainersPayload struct {
	Node       string              `json:"node"`
	ObservedAt time.Time           `json:"observed_at"`
	Runtime    string              `json:"runtime,omitempty"`
	Socket     string              `json:"socket,omitempty"`
	Count      int                 `json:"count"`
	Items      []HostContainerItem `json:"items"`
}

type HostContainerItem struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Image     string            `json:"image"`
	ImageRef  string            `json:"image_ref,omitempty"`
	State     string            `json:"state"`
	PodName   string            `json:"pod_name,omitempty"`
	PodNS     string            `json:"pod_namespace,omitempty"`
	PodUID    string            `json:"pod_uid,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt int64             `json:"created_at,omitempty"`
}

type HostContainersHandler struct {
	db *db.DB
}

func NewHostContainers(d *db.DB) *HostContainersHandler {
	return &HostContainersHandler{db: d}
}

func (h *HostContainersHandler) Report(w http.ResponseWriter, r *http.Request) {
	tok, ok := runtimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	// 4 MiB cap: ~500 containers × 4 KiB JSON each = 2 MiB, headroom × 2.
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)

	var body HostContainersPayload
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
INSERT INTO host_containers (
    org_id, cluster_id, node, container_count,
    runtime, socket, payload, observed_at, updated_at
) VALUES ($1, $2, $3, $4, NULLIF($5,''), NULLIF($6,''), $7, $8, NOW())
ON CONFLICT (org_id, COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid), node) DO UPDATE SET
    container_count = EXCLUDED.container_count,
    runtime         = EXCLUDED.runtime,
    socket          = EXCLUDED.socket,
    payload         = EXCLUDED.payload,
    observed_at     = EXCLUDED.observed_at,
    updated_at      = NOW()
`,
		tok.OrgID, clusterID, body.Node, body.Count,
		body.Runtime, body.Socket, raw, body.ObservedAt,
	); err != nil {
		jsonError(w, http.StatusInternalServerError, "insert: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type HostContainersRow struct {
	Node           string          `json:"node"`
	ClusterID      *uuid.UUID      `json:"cluster_id,omitempty"`
	ContainerCount int             `json:"container_count"`
	Runtime        string          `json:"runtime,omitempty"`
	Socket         string          `json:"socket,omitempty"`
	Payload        json.RawMessage `json:"payload,omitempty"`
	ObservedAt     time.Time       `json:"observed_at"`
}

func (h *HostContainersHandler) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT node, cluster_id, container_count, COALESCE(runtime,''),
       COALESCE(socket,''), payload, observed_at
  FROM host_containers
 WHERE org_id = $1
 ORDER BY observed_at DESC
 LIMIT 500`, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()
	out := make([]HostContainersRow, 0)
	for rows.Next() {
		var rrow HostContainersRow
		if err := rows.Scan(&rrow.Node, &rrow.ClusterID, &rrow.ContainerCount,
			&rrow.Runtime, &rrow.Socket, &rrow.Payload, &rrow.ObservedAt,
		); err != nil {
			jsonError(w, http.StatusInternalServerError, "scan: "+err.Error())
			return
		}
		out = append(out, rrow)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *HostContainersHandler) Get(w http.ResponseWriter, r *http.Request) {
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
	var rrow HostContainersRow
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT node, cluster_id, container_count, COALESCE(runtime,''),
       COALESCE(socket,''), payload, observed_at
  FROM host_containers
 WHERE org_id = $1 AND node = $2
 ORDER BY observed_at DESC
 LIMIT 1`, subj.OrgID, node).Scan(
		&rrow.Node, &rrow.ClusterID, &rrow.ContainerCount,
		&rrow.Runtime, &rrow.Socket, &rrow.Payload, &rrow.ObservedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "no host-containers for node")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rrow)
}
