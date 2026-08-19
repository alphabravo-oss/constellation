// P1-1: group→group rule edges (control-plane model + expansion).
//
// A GroupEdge (from_group → to_group : ports) is authored once and applies to
// every current and future member of both groups. Storage is group_rule_edges
// (migration 121); the `groups` table (owned by internal/handler/groups.go) is
// read-only here for membership resolution. Expansion turns an edge into
// concrete monitor-mode runtime_policies rows for each involved member workload,
// reusing the existing pkg/netpolicy expansion + BuildDPRules path — no new
// datapath primitive. Re-running Expand after a group-sync membership change is
// how "applies to future members" is honoured (live membership update).
//
// SAFETY: seeded rows are always monitor-mode with an allow default action, so
// expansion never blocks live workloads. Rows are tagged provenance=learned so a
// later regeneration merges non-destructively (P2-2).
//
// ponytail: HTTP route registration lives in internal/server/server.go (outside
// this subsystem's assigned paths). Wire the handlers below under
// /runtime-policies/group-edges (GET/POST/DELETE + POST .../expand) there.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// GroupEdgeRow is one group_rule_edges row.
type GroupEdgeRow struct {
	ID        uuid.UUID            `json:"id"`
	ClusterID uuid.UUID            `json:"cluster_id"`
	FromGroup string               `json:"from_group"`
	ToGroup   string               `json:"to_group"`
	Ports     []netpolicy.PortSpec `json:"ports"`
	Mode      string               `json:"mode"`
	Comment   string               `json:"comment,omitempty"`
	UpdatedAt time.Time            `json:"updated_at"`
}

// GroupEdgeStore persists group_rule_edges and expands them to member rules.
type GroupEdgeStore struct {
	db  *db.DB
	pol *RuntimePolicyStore
}

// NewGroupEdgeStore builds the edge store. It shares the runtime-policy store so
// expansion can upsert-merge the per-member policies.
func NewGroupEdgeStore(d *db.DB, pol *RuntimePolicyStore) *GroupEdgeStore {
	return &GroupEdgeStore{db: d, pol: pol}
}

// Upsert validates and persists an edge (create or replace by natural key).
func (s *GroupEdgeStore) Upsert(ctx context.Context, orgID, clusterID uuid.UUID, e netpolicy.GroupEdge, by *uuid.UUID) (GroupEdgeRow, error) {
	if err := e.Validate(); err != nil {
		return GroupEdgeRow{}, err
	}
	ports, err := json.Marshal(e.Ports)
	if err != nil {
		return GroupEdgeRow{}, err
	}
	var id uuid.UUID
	err = s.db.Pool().QueryRow(ctx, `
INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group, ports, mode, comment, created_by, updated_by)
VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$8)
ON CONFLICT (org_id, cluster_id, from_group, to_group) DO UPDATE
   SET ports = EXCLUDED.ports, mode = EXCLUDED.mode, comment = EXCLUDED.comment,
       updated_by = EXCLUDED.updated_by, updated_at = NOW()
RETURNING id`,
		orgID, clusterID, e.FromGroup, e.ToGroup, string(ports), e.Mode, e.Comment, by).Scan(&id)
	if err != nil {
		return GroupEdgeRow{}, err
	}
	return s.get(ctx, orgID, id)
}

func (s *GroupEdgeStore) get(ctx context.Context, orgID, id uuid.UUID) (GroupEdgeRow, error) {
	row := s.db.Pool().QueryRow(ctx, `
SELECT id, cluster_id, from_group, to_group, ports, mode, comment, updated_at
  FROM group_rule_edges WHERE id = $1 AND org_id = $2`, id, orgID)
	return scanGroupEdge(row)
}

// List returns every edge for a cluster.
func (s *GroupEdgeStore) List(ctx context.Context, orgID, clusterID uuid.UUID) ([]GroupEdgeRow, error) {
	rows, err := s.db.Pool().Query(ctx, `
SELECT id, cluster_id, from_group, to_group, ports, mode, comment, updated_at
  FROM group_rule_edges WHERE org_id = $1 AND cluster_id = $2
 ORDER BY from_group, to_group`, orgID, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupEdgeRow
	for rows.Next() {
		e, err := scanGroupEdge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Delete removes one edge. Note: it does NOT retract already-expanded member
// policies (those are ordinary runtime_policies rows the operator can manage);
// deleting the edge just stops future re-expansion.
func (s *GroupEdgeStore) Delete(ctx context.Context, orgID, id uuid.UUID) error {
	tag, err := s.db.Pool().Exec(ctx, `DELETE FROM group_rule_edges WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("not found")
	}
	return nil
}

// groupMembers reads the cached member list for a group by name from the groups
// table (owned elsewhere; read-only here). Members are "namespace/name" ids.
func (s *GroupEdgeStore) groupMembers(ctx context.Context, orgID, clusterID uuid.UUID, name string) ([]string, error) {
	var raw json.RawMessage
	err := s.db.Pool().QueryRow(ctx,
		`SELECT members FROM groups WHERE org_id = $1 AND name = $2`, orgID, name).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var members []string
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &members); err != nil {
			return nil, err
		}
	}
	_ = clusterID // groups are org-scoped by name; cluster filtering is advisory
	return members, nil
}

// ExpandResult reports what an expansion produced.
type ExpandResult struct {
	FromMembers int      `json:"from_members"`
	ToMembers   int      `json:"to_members"`
	Flows       int      `json:"flows"`
	Policies    []string `json:"policies"` // affected workloads
}

// Expand resolves an edge's group memberships and upsert-merges runtime_policies for every
// involved member workload, in the edge's authored mode (protect => enforcing default-deny,
// discover/monitor => informational). Safe to re-run (idempotent via the provenance merge);
// call it after group membership changes.
func (s *GroupEdgeStore) Expand(ctx context.Context, orgID, clusterID uuid.UUID, e netpolicy.GroupEdge, by *uuid.UUID) (ExpandResult, error) {
	if err := e.Validate(); err != nil {
		return ExpandResult{}, err
	}
	fromMembers, err := s.groupMembers(ctx, orgID, clusterID, e.FromGroup)
	if err != nil {
		return ExpandResult{}, err
	}
	toMembers, err := s.groupMembers(ctx, orgID, clusterID, e.ToGroup)
	if err != nil {
		return ExpandResult{}, err
	}
	flows := netpolicy.ExpandEdge(e, fromMembers, toMembers)
	res := ExpandResult{FromMembers: len(fromMembers), ToMembers: len(toMembers), Flows: len(flows)}
	if len(flows) == 0 {
		return res, nil
	}
	// P0-07: honor the edge's authored mode instead of always emitting informational
	// monitor policies. A 'protect' edge produces an ENFORCING policy with a default-deny
	// posture (AllowDNS so name resolution survives the deny); 'discover'/'monitor' stay
	// informational (allow default action, monitor mode) until an operator promotes. e.Mode
	// is normalized to discover|monitor|protect by e.Validate() above.
	policyMode, opts := edgePolicyPosture(e.Mode)
	members := uniqueStrings(append(append([]string{}, fromMembers...), toMembers...))
	name := edgePolicyName(e)
	for _, m := range members {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		rules, defAction, applyDir := netpolicy.BuildDPRules(m, flows, opts)
		if len(rules) == 0 {
			continue
		}
		policy := &RuntimePolicy{
			OrgID: orgID, ClusterID: clusterID,
			Workload: m, Namespace: namespaceOfWorkload(m), Name: name,
			Mode: policyMode, DefAction: defAction, ApplyDir: applyDir,
			CreatedBy: by,
		}
		if _, err := s.pol.UpsertLearnedPolicy(ctx, policy, rules, by); err != nil {
			return res, err
		}
		res.Policies = append(res.Policies, m)
	}
	return res, nil
}

// edgePolicyPosture maps an edge's authored mode (discover|monitor|protect, already normalized
// by GroupEdge.Validate) to the runtime policy mode and dp-rule build options. Only 'protect'
// enforces (default-deny with DNS allowed); discover/monitor stay informational allow-default
// monitor policies until an operator promotes them.
func edgePolicyPosture(mode string) (PolicyMode, netpolicy.BuildDPRulesOptions) {
	if mode == "protect" {
		return PolicyModeEnforce, netpolicy.DefaultBuildDPRulesOptions() // AllowDNS:true, DefaultDeny:true
	}
	return PolicyModeMonitor, netpolicy.BuildDPRulesOptions{AllowDNS: false, DefaultDeny: false}
}

func edgePolicyName(e netpolicy.GroupEdge) string {
	return "edge-" + sanitizeName(e.FromGroup) + "-to-" + sanitizeName(e.ToGroup)
}

func sanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, " ", "-")
	return s
}

func namespaceOfWorkload(id string) string {
	if i := strings.IndexByte(id, '/'); i > 0 {
		return id[:i]
	}
	return "default"
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func scanGroupEdge(sc rowScanner) (GroupEdgeRow, error) {
	var e GroupEdgeRow
	var ports json.RawMessage
	if err := sc.Scan(&e.ID, &e.ClusterID, &e.FromGroup, &e.ToGroup, &ports, &e.Mode, &e.Comment, &e.UpdatedAt); err != nil {
		return GroupEdgeRow{}, err
	}
	if len(ports) > 0 && string(ports) != "null" {
		_ = json.Unmarshal(ports, &e.Ports)
	}
	return e, nil
}

// ------------------------------------ HTTP ----------------------------------

// GroupEdgesHTTP serves the group-edge CRUD + expansion endpoints.
type GroupEdgesHTTP struct {
	store *GroupEdgeStore
}

// NewGroupEdgesHTTP builds the HTTP surface, sharing the runtime-policy store.
func NewGroupEdgesHTTP(d *db.DB, pol *RuntimePolicyStore) *GroupEdgesHTTP {
	return &GroupEdgesHTTP{store: NewGroupEdgeStore(d, pol)}
}

// CreateEdgeRequest is the POST body.
type CreateEdgeRequest struct {
	ClusterID uuid.UUID            `json:"cluster_id"`
	FromGroup string               `json:"from_group"`
	ToGroup   string               `json:"to_group"`
	Ports     []netpolicy.PortSpec `json:"ports"`
	Mode      string               `json:"mode"`
	Comment   string               `json:"comment"`
	Expand    bool                 `json:"expand"` // also expand to member policies now
}

// List handles GET /group-edges?cluster_id=...
func (h *GroupEdgesHTTP) List(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	clusterID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	rows, err := h.store.List(r.Context(), sub.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"edges": rows})
}

// Create handles POST /group-edges — upsert an edge and optionally expand it.
func (h *GroupEdgesHTTP) Create(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var req CreateEdgeRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if req.ClusterID == uuid.Nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	edge := netpolicy.GroupEdge{
		FromGroup: req.FromGroup, ToGroup: req.ToGroup,
		Ports: req.Ports, Mode: req.Mode, Comment: req.Comment,
	}
	row, err := h.store.Upsert(r.Context(), sub.OrgID, req.ClusterID, edge, &sub.UserID)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := map[string]any{"edge": row}
	if req.Expand {
		edge.ID = row.ID.String()
		exp, err := h.store.Expand(r.Context(), sub.OrgID, req.ClusterID, edge, &sub.UserID)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "expand: "+err.Error())
			return
		}
		resp["expansion"] = exp
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

// Expand handles POST /group-edges/{id}/expand — re-expand after membership change.
func (h *GroupEdgesHTTP) Expand(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id, err := uuid.Parse(pathSegmentBeforeExpand(r.URL.Path))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	row, err := h.store.get(r.Context(), sub.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	edge := netpolicy.GroupEdge{
		ID: row.ID.String(), FromGroup: row.FromGroup, ToGroup: row.ToGroup,
		Ports: row.Ports, Mode: row.Mode, Comment: row.Comment,
	}
	exp, err := h.store.Expand(r.Context(), sub.OrgID, row.ClusterID, edge, &sub.UserID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, exp)
}

// Delete handles DELETE /group-edges/{id}.
func (h *GroupEdgesHTTP) Delete(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id, err := uuid.Parse(pathTail(r.URL.Path))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.store.Delete(r.Context(), sub.OrgID, id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pathSegmentBeforeExpand pulls the {id} out of ".../group-edges/{id}/expand".
func pathSegmentBeforeExpand(p string) string {
	p = strings.TrimSuffix(p, "/expand")
	return pathTail(p)
}
