// Host-facts ingest + read endpoints.
//
//	POST /api/v1/host-facts:report   — runtime-agent upsert one snapshot (auth: runtime-agent-token)
//	GET  /api/v1/host-facts          — list latest snapshots for the caller's org (auth: user JWT, verb=read-findings)
//	GET  /api/v1/host-facts/{node}   — single snapshot for the caller's org (auth: user JWT, verb=read-findings)
//
// Mirrors what NeuVector's enforcer ships in share/system/system_linux.go
// (kernel / distro / cgroups / modules / CNI / CRI), plus the BTF and
// nfqueue-safe bits constellation specifically cares about for its
// eBPF + NFQUEUE enforcement path. The agent gathers Facts via
// internal/runtime/hostscan and posts every CONSTELLATION_HOSTSCAN_INTERVAL.
//
// Storage: host_facts (migration 048) — one row per (cluster_id, node);
// the agent upserts, so reads always see the latest snapshot.
package handler

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
)

// HostFacts is the wire shape the runtime-agent POSTs.
// It's deliberately permissive: extra keys go into the JSONB column
// untouched, so adding fields on the agent side doesn't require an
// API change.
type HostFacts struct {
	Node         string          `json:"node"`
	ObservedAt   time.Time       `json:"observed_at"`
	AgentVersion string          `json:"agent_version,omitempty"`

	OS       hostFactsOS       `json:"os,omitempty"`
	Kernel   hostFactsKernel   `json:"kernel,omitempty"`
	CGroup   hostFactsCGroup   `json:"cgroup,omitempty"`
	BPF      hostFactsBPF      `json:"bpf,omitempty"`
	Net      hostFactsNet      `json:"net,omitempty"`
	CNI      hostFactsCNI      `json:"cni,omitempty"`
	CRI      hostFactsCRI      `json:"cri,omitempty"`
	Hardware hostFactsHardware `json:"hardware,omitempty"`
	Caps     []string          `json:"capabilities,omitempty"`

	// Raw is the whole document as-received, persisted to host_facts.facts.
	// Set by the handler before insert.
	Raw json.RawMessage `json:"-"`
}

type hostFactsOS struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	PrettyName string `json:"pretty_name,omitempty"`
	Version    string `json:"version,omitempty"`
	VersionID  string `json:"version_id,omitempty"`
}

type hostFactsHardware struct {
	CPUCount    int   `json:"cpu_count,omitempty"`
	MemoryBytes int64 `json:"memory_bytes,omitempty"`
}

type hostFactsKernel struct {
	Release string `json:"release,omitempty"`
	Arch    string `json:"arch,omitempty"`
}

type hostFactsCGroup struct {
	Version int `json:"version"`
}

type hostFactsBPF struct {
	FSMounted  bool `json:"fs_mounted"`
	BTFPresent bool `json:"btf_present"`
}

type hostFactsNet struct {
	NFQueueLoaded   bool `json:"nfqueue_loaded"`
	NFQueueOnDisk   bool `json:"nfqueue_on_disk"`
	NetfilterDir    bool `json:"netfilter_dir"`
	IPTablesNFQueue bool `json:"iptables_nfqueue"`
}

type hostFactsCNI struct {
	Name        string `json:"name,omitempty"`
	NFQueueSafe bool   `json:"nfqueue_safe"`
}

type hostFactsCRI struct {
	Runtime string `json:"runtime,omitempty"`
	Socket  string `json:"socket,omitempty"`
}

// HostFactsHandler exposes the POST + GET endpoints.
type HostFactsHandler struct {
	db *db.DB
}

func NewHostFacts(d *db.DB) *HostFactsHandler {
	return &HostFactsHandler{db: d}
}

// Report handles POST /api/v1/host-facts:report. Upserts one row per
// (cluster_id, node). The full body becomes host_facts.facts; the few
// columns we lift out are pulled from the parsed body so cheap UI
// filters work without jsonb digging.
func (h *HostFactsHandler) Report(w http.ResponseWriter, r *http.Request) {
	tok, ok := runtimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10) // 256 KiB cap — bigger than any plausible single-node snapshot

	var body HostFacts
	dec := json.NewDecoder(r.Body)
	// Don't DisallowUnknownFields — extra keys are tolerated and pass
	// through into the JSONB column via the Raw re-encode below.
	if err := dec.Decode(&body); err != nil {
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
	// Re-encode to canonicalize what we store. We could keep the raw
	// bytes off the wire but re-encoding keeps the column compact and
	// well-formed (Go's encoder strips whitespace).
	raw, err := json.Marshal(&body)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "re-encode: "+err.Error())
		return
	}

	// Attribute this snapshot to the cluster the reporting agent's token
	// was minted for (see ResolveAgentClusterID). This replaces the old
	// "oldest cluster in the org" heuristic, which collapsed every node of
	// every cluster onto a single cluster and overwrote same-named nodes
	// across clusters. clusterID is nil only for a token with no init-bundle
	// mapping; the NULL-safe upsert below then dedups on (org_id, node).
	clusterID, err := ResolveAgentClusterID(r.Context(), h.db, tok)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "resolve cluster: "+err.Error())
		return
	}

	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO host_facts (
    org_id, cluster_id, node,
    os_id, os_version_id, kernel_release, arch,
    btf_present, cgroup_version, nfqueue_capable,
    cni_name, cri_runtime,
    facts, observed_at, updated_at
) VALUES (
    $1, $2, $3,
    NULLIF($4,''), NULLIF($5,''), NULLIF($6,''), NULLIF($7,''),
    $8, $9, $10,
    NULLIF($11,''), NULLIF($12,''),
    $13, $14, NOW()
)
ON CONFLICT (org_id, COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid), node) DO UPDATE SET
    os_id           = EXCLUDED.os_id,
    os_version_id   = EXCLUDED.os_version_id,
    kernel_release  = EXCLUDED.kernel_release,
    arch            = EXCLUDED.arch,
    btf_present     = EXCLUDED.btf_present,
    cgroup_version  = EXCLUDED.cgroup_version,
    nfqueue_capable = EXCLUDED.nfqueue_capable,
    cni_name        = EXCLUDED.cni_name,
    cri_runtime     = EXCLUDED.cri_runtime,
    facts           = EXCLUDED.facts,
    observed_at     = EXCLUDED.observed_at,
    updated_at      = NOW()
`,
		tok.OrgID, clusterID, body.Node,
		body.OS.ID, body.OS.VersionID, body.Kernel.Release, body.Kernel.Arch,
		body.BPF.BTFPresent, body.CGroup.Version, body.Net.IPTablesNFQueue,
		body.CNI.Name, body.CRI.Runtime,
		raw, body.ObservedAt,
	); err != nil {
		jsonError(w, http.StatusInternalServerError, "insert: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ResolveAgentClusterID returns the cluster_id that a runtime-agent token was
// minted for, by following the cluster init-bundle that issued it
// (cluster_init_bundles.runtime_agent_token_id, whose cluster_id is NOT NULL).
//
// This is the correct per-node attribution for host_* snapshot ingest: every
// real agent token is issued by exactly one init-bundle for exactly one
// cluster, so nodes in different clusters carry different tokens and resolve to
// different clusters. It replaces the previous "oldest cluster in the org"
// heuristic, which mis-attributed every node to one cluster and let same-named
// nodes in different clusters overwrite each other.
//
// Returns (nil, nil) when the token has no init-bundle mapping (e.g. a token
// created outside the bundle flow). Callers MUST keep their upsert NULL-safe in
// that case — the host_* tables use a COALESCE(cluster_id, nil-uuid)-based
// unique index (migration 111) so a NULL cluster_id dedups on (org_id, node)
// instead of inserting unbounded duplicates.
func ResolveAgentClusterID(ctx context.Context, d *db.DB, tok *RuntimeAgentToken) (*uuid.UUID, error) {
	var cid uuid.UUID
	err := d.Pool().QueryRow(ctx, `
SELECT cluster_id
  FROM cluster_init_bundles
 WHERE runtime_agent_token_id = $1
 ORDER BY created_at DESC
 LIMIT 1`, tok.ID).Scan(&cid)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &cid, nil
}

// HostFactsRow is one row in the GET /api/v1/host-facts response.
type HostFactsRow struct {
	Node           string          `json:"node"`
	ClusterID      *uuid.UUID      `json:"cluster_id,omitempty"`
	OSID           string          `json:"os_id,omitempty"`
	OSVersionID    string          `json:"os_version_id,omitempty"`
	KernelRelease  string          `json:"kernel_release,omitempty"`
	Arch           string          `json:"arch,omitempty"`
	BTFPresent     *bool           `json:"btf_present,omitempty"`
	CGroupVersion  *int            `json:"cgroup_version,omitempty"`
	NFQueueCapable *bool           `json:"nfqueue_capable,omitempty"`
	CNIName        string          `json:"cni_name,omitempty"`
	CRIRuntime     string          `json:"cri_runtime,omitempty"`
	Facts          json.RawMessage `json:"facts,omitempty"`
	ObservedAt     time.Time       `json:"observed_at"`
}

// List handles GET /api/v1/host-facts — latest snapshot for every node
// in the caller's org, ordered by observed_at desc.
func (h *HostFactsHandler) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT node, cluster_id, COALESCE(os_id,''), COALESCE(os_version_id,''),
       COALESCE(kernel_release,''), COALESCE(arch,''),
       btf_present, cgroup_version, nfqueue_capable,
       COALESCE(cni_name,''), COALESCE(cri_runtime,''),
       facts, observed_at
  FROM host_facts
 WHERE org_id = $1
 ORDER BY observed_at DESC
 LIMIT 500`, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()
	out := make([]HostFactsRow, 0)
	for rows.Next() {
		var rrow HostFactsRow
		if err := rows.Scan(&rrow.Node, &rrow.ClusterID, &rrow.OSID, &rrow.OSVersionID,
			&rrow.KernelRelease, &rrow.Arch, &rrow.BTFPresent, &rrow.CGroupVersion,
			&rrow.NFQueueCapable, &rrow.CNIName, &rrow.CRIRuntime,
			&rrow.Facts, &rrow.ObservedAt,
		); err != nil {
			jsonError(w, http.StatusInternalServerError, "scan: "+err.Error())
			return
		}
		out = append(out, rrow)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// Get handles GET /api/v1/host-facts/{node} — single snapshot lookup.
func (h *HostFactsHandler) Get(w http.ResponseWriter, r *http.Request) {
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
	var rrow HostFactsRow
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT node, cluster_id, COALESCE(os_id,''), COALESCE(os_version_id,''),
       COALESCE(kernel_release,''), COALESCE(arch,''),
       btf_present, cgroup_version, nfqueue_capable,
       COALESCE(cni_name,''), COALESCE(cri_runtime,''),
       facts, observed_at
  FROM host_facts
 WHERE org_id = $1 AND node = $2
 ORDER BY observed_at DESC
 LIMIT 1`, subj.OrgID, node).Scan(
		&rrow.Node, &rrow.ClusterID, &rrow.OSID, &rrow.OSVersionID,
		&rrow.KernelRelease, &rrow.Arch, &rrow.BTFPresent, &rrow.CGroupVersion,
		&rrow.NFQueueCapable, &rrow.CNIName, &rrow.CRIRuntime,
		&rrow.Facts, &rrow.ObservedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "no host-facts for node")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rrow)
}
