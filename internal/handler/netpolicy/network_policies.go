package netpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	handlerpkg "github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/netutil"
	"github.com/alphabravocompany/constellation/pkg/audit"
	netpolicy "github.com/alphabravocompany/constellation/pkg/netpolicy"
)

type NetworkPolicies struct {
	db       *db.DB
	auditLog *audit.Logger
}

func NewNetworkPolicies(args ...any) *NetworkPolicies {
	h := &NetworkPolicies{}
	for _, arg := range args {
		switch v := arg.(type) {
		case *db.DB:
			h.db = v
		case *audit.Logger:
			h.auditLog = v
		}
	}
	return h
}

func NewNetworkPoliciesForTest(database ...*db.DB) *NetworkPolicies {
	var d *db.DB
	if len(database) > 0 {
		d = database[0]
	}
	return &NetworkPolicies{db: d}
}

type networkPolicyLifecycleDTO struct {
	ID                    string                         `json:"id"`
	ClusterID             string                         `json:"cluster_id,omitempty"`
	ClusterName           string                         `json:"cluster_name,omitempty"`
	Workload              string                         `json:"workload"`
	Namespace             string                         `json:"namespace"`
	CurrentMode           string                         `json:"current_mode"`
	TargetMode            string                         `json:"target_mode,omitempty"`
	ForcedMode            string                         `json:"-"` // transient: the "force" action's target posture
	Reason                string                         `json:"reason"`
	AutoApplied           bool                           `json:"auto_applied"`
	EvaluatedAt           string                         `json:"evaluated_at"`
	GeneratedAt           string                         `json:"generated_at,omitempty"`
	CandidateHash         string                         `json:"candidate_hash,omitempty"`
	ApprovedCandidateHash string                         `json:"approved_candidate_hash,omitempty"`
	CandidateStale        bool                           `json:"candidate_stale"`
	ApprovalStatus        string                         `json:"approval_status"`
	LastAppliedAt         string                         `json:"last_applied_at,omitempty"`
	RollbackAvailable     bool                           `json:"rollback_available"`
	AppliedRef            string                         `json:"applied_ref,omitempty"`
	RollbackRef           string                         `json:"rollback_ref,omitempty"`
	Summary               networkPolicyLifecycleSummary  `json:"summary"`
	TuplePreview          []networkPolicyTuplePreviewDTO `json:"tuple_preview"`
	Preview               networkPolicyPreviewDTO        `json:"preview"`
	Diff                  networkPolicyDiffDTO           `json:"diff"`
	AuditTrail            []networkPolicyAuditEventDTO   `json:"audit_trail"`
	ApplyStatuses         []networkPolicyApplyStatusDTO  `json:"apply_statuses,omitempty"`
}

type networkPolicyLifecycleSummary struct {
	TotalFlows         int    `json:"total_flows"`
	UniquePeers        int    `json:"unique_peers"`
	UniquePortProtocol int    `json:"unique_port_protocol"`
	OutOfPolicyAlerts  int    `json:"out_of_policy_alerts"`
	NewTuplesLast24h   int    `json:"new_tuples_last_24h"`
	FirstObservation   string `json:"first_observation"`
	LastObservation    string `json:"last_observation"`
}

type networkPolicyTuplePreviewDTO struct {
	Direction     string `json:"direction"`
	Peer          string `json:"peer"`
	Protocol      string `json:"protocol"`
	Port          int    `json:"port"`
	L7Protocol    string `json:"l7_protocol,omitempty"`
	Verdict       string `json:"verdict"`
	Samples       int    `json:"samples"`
	Bytes         int64  `json:"bytes"`
	Packets       int64  `json:"packets"`
	FirstSeenAt   string `json:"first_seen_at"`
	LastSeenAt    string `json:"last_seen_at"`
	Included      bool   `json:"included"`
	ExcludeReason string `json:"exclude_reason,omitempty"`
}

type networkPolicyPreviewDTO struct {
	Engine      string            `json:"engine"`
	YAML        string            `json:"yaml"`
	Refs        map[string]string `json:"refs"`
	Manifests   map[string]string `json:"manifests,omitempty"`
	L7Protocols []string          `json:"l7_protocols,omitempty"`
}

type networkPolicyDiffDTO struct {
	Summary string   `json:"summary"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Changed []string `json:"changed"`
}

type networkPolicyAuditEventDTO struct {
	At             string `json:"at"`
	Actor          string `json:"actor"`
	Action         string `json:"action"`
	Message        string `json:"message"`
	ActionID       string `json:"action_id,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

type networkPolicyApplyStatusDTO struct {
	Flavor         string `json:"flavor"`
	ResourceRef    string `json:"resource_ref,omitempty"`
	DesiredMode    string `json:"desired_mode"`
	ApprovalStatus string `json:"approval_status"`
	LastAction     string `json:"last_action"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	CandidateHash  string `json:"candidate_hash,omitempty"`
	AppliedRef     string `json:"applied_ref,omitempty"`
	RollbackRef    string `json:"rollback_ref,omitempty"`
	LastAppliedAt  string `json:"last_applied_at,omitempty"`
	LastDeletedAt  string `json:"last_deleted_at,omitempty"`
	UpdatedAt      string `json:"updated_at"`
}

func (h *NetworkPolicies) List(w http.ResponseWriter, r *http.Request) {
	namespace := strings.TrimSpace(r.URL.Query().Get("namespace"))
	items := []networkPolicyLifecycleDTO{}
	var selectedCluster *networkPolicyCluster
	var selectedGroup string
	var selectedGroupMembers []string
	groupActive := false
	if h.db != nil {
		subj, ok := authctx.SubjectFrom(r.Context())
		if !ok {
			httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "subject required"})
			return
		}
		var err error
		selectedCluster, err = h.resolvePolicyCluster(r, subj.OrgID.String())
		if err != nil {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		var clusterUUID *uuid.UUID
		if selectedCluster != nil {
			if parsed, err := uuid.Parse(selectedCluster.ID); err == nil {
				clusterUUID = &parsed
			}
		}
		selectedGroupMembers, selectedGroup, groupActive, err = handlerpkg.ResolveGroupFilterMembers(r.Context(), h.db.Pool(), subj.OrgID, clusterUUID, r.URL.Query().Get("group"))
		if err != nil {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		items, err = h.observedPolicyLifecycleCatalog(r, subj.OrgID.String(), selectedCluster, namespace)
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		applyClusterToPolicies(items, selectedCluster)
		items, err = h.applyPersistedState(r, subj.OrgID.String(), selectedCluster, items)
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	if namespace != "" || groupActive {
		groupSet := map[string]struct{}{}
		for _, member := range selectedGroupMembers {
			groupSet[member] = struct{}{}
		}
		filtered := make([]networkPolicyLifecycleDTO, 0, len(items))
		for _, item := range items {
			if namespace != "" && item.Namespace != namespace {
				continue
			}
			if groupActive {
				if _, ok := groupSet[item.Workload]; !ok {
					continue
				}
			}
			filtered = append(filtered, item)
		}
		items = filtered
	}

	summary := map[string]any{
		"total":            len(items),
		"ready":            countNetworkPolicies(items, func(i networkPolicyLifecycleDTO) bool { return i.TargetMode != "" }),
		"discover":         countNetworkPolicies(items, func(i networkPolicyLifecycleDTO) bool { return i.CurrentMode == "discover" }),
		"monitor":          countNetworkPolicies(items, func(i networkPolicyLifecycleDTO) bool { return i.CurrentMode == "monitor" }),
		"protect":          countNetworkPolicies(items, func(i networkPolicyLifecycleDTO) bool { return i.CurrentMode == "protect" }),
		"rollback_ready":   countNetworkPolicies(items, func(i networkPolicyLifecycleDTO) bool { return i.RollbackAvailable }),
		"pending_approval": countNetworkPolicies(items, func(i networkPolicyLifecycleDTO) bool { return i.ApprovalStatus == "pending" }),
	}
	if selectedCluster != nil {
		summary["selected_cluster_id"] = selectedCluster.ID
	}
	if groupActive {
		summary["selected_group"] = selectedGroup
		summary["selected_group_members"] = len(selectedGroupMembers)
	}

	// A7: dead-rule signal — rules that have had zero matches over the window.
	// Advisory only (blocks nothing). Window is configurable via
	// ?dead_rule_window=<duration> (eg. "168h"), defaulting to
	// netpolicy.DefaultDeadRuleWindow.
	deadRules := []netpolicy.RuleMatchStat{}
	if h.db != nil && selectedCluster != nil {
		if subj, ok := authctx.SubjectFrom(r.Context()); ok {
			if clusterID, err := uuid.Parse(selectedCluster.ID); err == nil {
				window := netpolicy.DefaultDeadRuleWindow
				if raw := strings.TrimSpace(r.URL.Query().Get("dead_rule_window")); raw != "" {
					if d, perr := time.ParseDuration(raw); perr == nil && d > 0 {
						window = d
					}
				}
				dr, derr := NewMatchStatsStore(h.db).DeadRules(r.Context(), subj.OrgID, clusterID, time.Now().UTC(), window)
				if derr == nil {
					deadRules = dr
				}
			}
		}
	}
	summary["dead_rules"] = len(deadRules)

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"items":      items,
		"summary":    summary,
		"dead_rules": deadRules,
	})
}

func (h *NetworkPolicies) PreviewAction(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "network policy lifecycle storage unavailable"})
		return
	}
	subj, hasSubject := authctx.SubjectFrom(r.Context())
	if !hasSubject {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "subject required"})
		return
	}
	var rawBody []byte
	if r.Body != nil {
		rawBody, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(rawBody))
	}
	workload, action := policyWorkloadAndAction(r)
	if workload == "" || action == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "workload and action required"})
		return
	}
	selectedCluster, err := h.resolvePolicyCluster(r, subj.OrgID.String())
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	item, ok, err := h.findObservedNetworkPolicy(r, subj.OrgID.String(), selectedCluster, workload)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
		return
	}
	items, err := h.applyPersistedState(r, subj.OrgID.String(), selectedCluster, []networkPolicyLifecycleDTO{item})
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	item = items[0]
	if item.CurrentMode == "" {
		item.CurrentMode = "discover" // every workload defaults to the discover posture
	}
	if action == "force" {
		var body networkPolicyActionBody
		_ = json.NewDecoder(bytes.NewReader(rawBody)).Decode(&body)
		mode := strings.TrimSpace(strings.ToLower(body.Mode))
		if !isValidPolicyMode(mode) {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "force requires mode: discover, monitor, or protect"})
			return
		}
		item.ForcedMode = mode
	}
	if action == "promote" && item.CurrentMode == "protect" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "workload already at protect (highest posture)"})
		return
	}
	if action == "demote" && item.CurrentMode == "discover" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "discover workloads cannot be demoted"})
		return
	}
	if action == "apply" && h.db != nil && item.ApprovalStatus != "approved" && item.ApprovalStatus != "applied" {
		httpx.WriteJSON(w, http.StatusConflict, map[string]string{"error": "network policy must be approved before apply"})
		return
	}
	if action == "apply" && h.db != nil && item.CandidateStale {
		httpx.WriteJSON(w, http.StatusConflict, map[string]string{"error": "network policy candidate changed after approval; re-approval required"})
		return
	}
	if action == "demote" && h.db != nil {
		var body networkPolicyActionBody
		_ = json.NewDecoder(bytes.NewReader(rawBody)).Decode(&body)
		if strings.TrimSpace(body.Reason) == "" {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "demotion reason required"})
			return
		}
	}
	if (action == "approve" || action == "apply") && h.db != nil {
		var body networkPolicyActionBody
		_ = json.NewDecoder(bytes.NewReader(rawBody)).Decode(&body)
		// Idempotent replays must bypass candidate-hash validation: once the
		// original action persisted a lifecycle row, the observed candidate hash
		// legitimately shifts (mode_since is set, changing the evaluator output),
		// so a same-key retry must replay the recorded action rather than 409 on a
		// hash that is only "stale" because the first request succeeded.
		isReplay := false
		if key := networkPolicyIdempotencyKey(r, body); key != "" {
			if _, ok, err := h.replayNetworkPolicyAction(r, item, subj.OrgID.String(), selectedCluster, key); err == nil && ok {
				isReplay = true
			}
		}
		if !isReplay && (strings.TrimSpace(body.CandidateHash) == "" || strings.TrimSpace(body.CandidateHash) != item.CandidateHash) {
			httpx.WriteJSON(w, http.StatusConflict, map[string]string{"error": "network policy candidate hash mismatch; refresh and review the latest candidate"})
			return
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(rawBody))
	persisted, err := h.persistAction(r, item, action, subj.OrgID.String(), subj.UserID.String(), selectedCluster)
	if err != nil {
		if strings.Contains(err.Error(), "idempotency key already used") {
			httpx.WriteJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"policy":          persisted.Policy,
		"action":          action,
		"action_id":       persisted.ActionID,
		"idempotency_key": persisted.IdempotencyKey,
		"idempotent":      persisted.Idempotent,
		"persists":        true,
		"applies_live":    true,
		"message":         "Lifecycle action persisted; the network-policy-applier will reconcile this state to the cluster on its next interval.",
		"next_mode":       nextModeForAction(item, action),
		"rollback_ref":    persisted.RollbackRef,
		"rollback_refs":   persisted.Policy.Preview.Refs,
	})
}

func (h *NetworkPolicies) Rollback(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "network policy lifecycle storage unavailable"})
		return
	}
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "subject required"})
		return
	}
	workload, _ := policyWorkloadAndAction(r)
	if workload == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "workload required"})
		return
	}
	selectedCluster, err := h.resolvePolicyCluster(r, subj.OrgID.String())
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	item, ok, err := h.findObservedNetworkPolicy(r, subj.OrgID.String(), selectedCluster, workload)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
		return
	}
	items, err := h.applyPersistedState(r, subj.OrgID.String(), selectedCluster, []networkPolicyLifecycleDTO{item})
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	item = items[0]
	persisted, err := h.persistRollback(r, item, subj.OrgID.String(), subj.UserID.String(), selectedCluster)
	if err != nil {
		if strings.Contains(err.Error(), "rollback ref not found") {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if strings.Contains(err.Error(), "idempotency key already used") {
			httpx.WriteJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"policy":          persisted.Policy,
		"action":          "rollback",
		"action_id":       persisted.ActionID,
		"idempotency_key": persisted.IdempotencyKey,
		"idempotent":      persisted.Idempotent,
		"persists":        true,
		"applies_live":    true,
		"message":         "Rollback state persisted; the network-policy-applier will reconcile this state to the cluster on its next interval.",
		"next_mode":       persisted.Policy.CurrentMode,
		"rollback_ref":    persisted.RollbackRef,
		"rollback_refs":   persisted.Policy.Preview.Refs,
	})
}

type networkPolicyActionBody struct {
	Reason         string `json:"reason"`
	RollbackRef    string `json:"rollback_ref"`
	IdempotencyKey string `json:"idempotency_key"`
	CandidateHash  string `json:"candidate_hash"`
	// Mode is the target posture for the "force" action (discover|monitor|protect).
	Mode string `json:"mode"`
}

type persistedNetworkPolicyAction struct {
	Policy         networkPolicyLifecycleDTO
	ActionID       string
	RollbackRef    string
	IdempotencyKey string
	Idempotent     bool
}

type networkPolicyCluster struct {
	ID   string
	Name string
}

func (h *NetworkPolicies) resolvePolicyCluster(r *http.Request, orgID string) (*networkPolicyCluster, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if raw != "" {
		if _, err := uuid.Parse(raw); err != nil {
			return nil, err
		}
		var cluster networkPolicyCluster
		if err := h.db.Pool().QueryRow(r.Context(), `
SELECT id::text, name
  FROM clusters
 WHERE org_id = $1 AND id = $2`, orgID, raw).Scan(&cluster.ID, &cluster.Name); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("cluster not found")
			}
			return nil, err
		}
		return &cluster, nil
	}
	var cluster networkPolicyCluster
	if err := h.db.Pool().QueryRow(r.Context(), `
SELECT id::text, name
  FROM clusters
 WHERE org_id = $1
 ORDER BY CASE WHEN state = 'connected' THEN 0 ELSE 1 END, last_heartbeat_at DESC NULLS LAST, created_at ASC
 LIMIT 1`, orgID).Scan(&cluster.ID, &cluster.Name); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &cluster, nil
}

func applyClusterToPolicies(items []networkPolicyLifecycleDTO, cluster *networkPolicyCluster) {
	if cluster == nil {
		return
	}
	for i := range items {
		items[i].ClusterID = cluster.ID
		items[i].ClusterName = cluster.Name
		finalizeNetworkPolicyCandidate(&items[i])
	}
}

func (h *NetworkPolicies) findObservedNetworkPolicy(r *http.Request, orgID string, cluster *networkPolicyCluster, workload string) (networkPolicyLifecycleDTO, bool, error) {
	items, err := h.observedPolicyLifecycleCatalog(r, orgID, cluster, "")
	if err != nil {
		return networkPolicyLifecycleDTO{}, false, err
	}
	for _, item := range items {
		if item.Workload == workload {
			return item, true, nil
		}
	}
	return networkPolicyLifecycleDTO{}, false, nil
}

// LifecycleForWorkload returns the observed network-policy lifecycle entry for a
// single workload, with persisted state overlaid, or nil when none is found. It
// is the read-path seam the deployments handler consumes for its detail view.
//
// The return is a plain any (carrying *networkPolicyLifecycleDTO when present,
// or untyped nil) so the parent handler package can hold it without importing
// this sub-package back — the netpolicy package imports handler for the Subject
// seam, so the dependency must point one way only.
func (h *NetworkPolicies) LifecycleForWorkload(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, workloadID string) (any, error) {
	workloadID = strings.TrimSpace(workloadID)
	if h.db == nil || workloadID == "" {
		return nil, nil
	}
	var cluster *networkPolicyCluster
	if clusterID != nil {
		cluster = &networkPolicyCluster{ID: clusterID.String()}
		_ = h.db.Pool().QueryRow(r.Context(), `
SELECT name
  FROM clusters
 WHERE org_id = $1 AND id = $2`, orgID, *clusterID).Scan(&cluster.Name)
	}
	item, ok, err := h.findObservedNetworkPolicy(r, orgID.String(), cluster, workloadID)
	if err != nil || !ok {
		return nil, err
	}
	items, err := h.applyPersistedState(r, orgID.String(), cluster, []networkPolicyLifecycleDTO{item})
	if err != nil || len(items) == 0 {
		return nil, err
	}
	return &items[0], nil
}

func (h *NetworkPolicies) observedPolicyLifecycleCatalog(r *http.Request, orgID string, cluster *networkPolicyCluster, namespace string) ([]networkPolicyLifecycleDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT namespace, name, labels
  FROM deployments
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND ($3::text = '' OR namespace = $3)
 ORDER BY namespace, name`, orgID, clusterUUIDParam(cluster), namespace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type deploymentPolicySeed struct {
		namespace string
		name      string
		workload  string
		labels    map[string]string
	}
	deployments := []deploymentPolicySeed{}
	for rows.Next() {
		var ns, name string
		var labelsRaw []byte
		if err := rows.Scan(&ns, &name, &labelsRaw); err != nil {
			return nil, err
		}
		labels := map[string]string{"app": name}
		if len(labelsRaw) > 0 {
			var parsed map[string]string
			if err := json.Unmarshal(labelsRaw, &parsed); err == nil && len(parsed) > 0 {
				labels = parsed
			}
		}
		deployments = append(deployments, deploymentPolicySeed{
			namespace: ns,
			name:      name,
			workload:  ns + "/" + name,
			labels:    labels,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(deployments) == 0 {
		return nil, nil
	}

	flowRows, err := h.db.Pool().Query(r.Context(), `
	SELECT src_workload, dst_workload, protocol, COALESCE(l7_protocol, ''), COALESCE(dst_port, 0), verdict,
       COALESCE(dst_addr, ''), COALESCE(fqdn, ''), COUNT(*)::int, COALESCE(SUM(bytes), 0)::bigint,
       COALESCE(SUM(packets), 0)::bigint, MIN(at), MAX(at)
  FROM network_flows
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND at >= NOW() - INTERVAL '7 days'
 GROUP BY src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict, dst_addr, fqdn`, orgID, clusterUUIDParam(cluster))
	if err != nil {
		return nil, err
	}
	defer flowRows.Close()
	labelsByWorkload := make(map[string]map[string]string, len(deployments))
	for _, dep := range deployments {
		labelsByWorkload[dep.workload] = dep.labels
	}
	flows := []netpolicy.Flow{}
	flowCounts := map[string]int{}
	peers := map[string]map[string]bool{}
	tuples := map[string]map[string]bool{}
	alerts := map[string]int{}
	newTuples := map[string]int{}
	firstSeen := map[string]string{}
	lastSeen := map[string]string{}
	tuplePreviews := map[string][]networkPolicyTuplePreviewDTO{}
	for flowRows.Next() {
		var src, dst, proto, l7, verdict, dstAddr, fqdn string
		var port, count int
		var bytesSeen, packetsSeen int64
		var first, last time.Time
		if err := flowRows.Scan(&src, &dst, &proto, &l7, &port, &verdict, &dstAddr, &fqdn, &count, &bytesSeen, &packetsSeen, &first, &last); err != nil {
			return nil, err
		}
		srcNS, srcName := netutil.SplitWorkload(src)
		dstNS, dstName := netutil.SplitWorkload(dst)
		policyFlow := netpolicy.Flow{
			SrcWorkload:  srcName,
			SrcNamespace: srcNS,
			SrcLabels:    labelsByWorkload[src],
			DstWorkload:  dstName,
			DstNamespace: dstNS,
			DstLabels:    labelsByWorkload[dst],
			Protocol:     strings.ToUpper(proto),
			Port:         port,
			Count:        count,
			LastSeen:     last.UTC().Format(time.RFC3339),
			L7Protocol:   strings.ToLower(l7),
		}
		if isExternalPeer(dst) {
			policyFlow.DstWorkload = ""
			policyFlow.DstNamespace = ""
			policyFlow.DstLabels = nil
			policyFlow.DstIP = dstAddr
			// H12/FQDN: dst external => our workload is the egress source. Anchor
			// the egress allow rule to the observed FQDN (when present) so the
			// enforced Cilium manifest emits toFQDNs instead of pinning to a /32.
			// Mirrors runtime_policies_generate.go's flowFromRow.
			if fqdn != "" {
				policyFlow.Fqdn = fqdn
			}
		}
		if isExternalPeer(src) {
			policyFlow.SrcWorkload = ""
			policyFlow.SrcNamespace = ""
			policyFlow.SrcLabels = nil
		}
		includeInPolicy, excludeReason := tupleInclusion(verdict, src, dst, dstAddr)
		if includeInPolicy {
			flows = append(flows, policyFlow)
		}
		for _, workload := range []string{src, dst} {
			if isExternalPeer(workload) {
				continue
			}
			flowCounts[workload] += count
			if peers[workload] == nil {
				peers[workload] = map[string]bool{}
			}
			peer := dst
			if workload == dst {
				peer = src
			}
			peers[workload][peer] = true
			if tuples[workload] == nil {
				tuples[workload] = map[string]bool{}
			}
			tuples[workload][tupleDirection(workload, src, dst)+":"+peer+":"+strings.ToUpper(proto)+":"+stringIntForPolicy(port)+":"+strings.ToLower(l7)+":"+dstAddr] = true
			if strings.ToLower(verdict) != "allow" {
				alerts[workload] += count
			}
			tuplePreviews[workload] = append(tuplePreviews[workload], networkPolicyTuplePreviewDTO{
				Direction:     tupleDirection(workload, src, dst),
				Peer:          peer,
				Protocol:      strings.ToUpper(proto),
				Port:          port,
				L7Protocol:    strings.ToLower(l7),
				Verdict:       strings.ToLower(verdict),
				Samples:       count,
				Bytes:         bytesSeen,
				Packets:       packetsSeen,
				FirstSeenAt:   first.UTC().Format(time.RFC3339),
				LastSeenAt:    last.UTC().Format(time.RFC3339),
				Included:      includeInPolicy,
				ExcludeReason: excludeReason,
			})
			if first.After(time.Now().Add(-24 * time.Hour)) {
				newTuples[workload]++
			}
			firstValue := first.UTC().Format(time.RFC3339)
			if firstSeen[workload] == "" || firstSeen[workload] > firstValue {
				firstSeen[workload] = firstValue
			}
			lastValue := last.UTC().Format(time.RFC3339)
			if lastSeen[workload] == "" || lastSeen[workload] < lastValue {
				lastSeen[workload] = lastValue
			}
		}
	}
	if err := flowRows.Err(); err != nil {
		return nil, err
	}

	// NET-4: load the PERSISTED per-workload mode + mode_since so the elevation
	// engine evaluates real time-in-mode (e.g. Monitor->Protect). Without this the
	// loop below re-seeded Discover/first-observation every request and Monitor
	// criteria never ran. Workloads with no persisted row fall back to Discover.
	persistedMode, persistedModeSince, err := h.persistedWorkloadModes(r, orgID, cluster)
	if err != nil {
		return nil, err
	}

	mgr := netpolicy.NewManager()
	items := make([]networkPolicyLifecycleDTO, 0, len(deployments))
	for _, dep := range deployments {
		total := flowCounts[dep.workload]
		if total == 0 {
			continue
		}
		// Real elevation engine (discover->monitor->protect) over the per-workload
		// flow stats already computed above — replaces the old total>=20 heuristic.
		// Seed mode/ModeSince from persisted lifecycle state when present so
		// transitions evaluate against real time-in-mode; otherwise default to
		// Discover seeded from first observation. Env overrides let fresh/demo
		// clusters promote despite the 7-day default learn window.
		mode := netpolicy.ModeDiscover
		modeSince, _ := time.Parse(time.RFC3339, firstSeen[dep.workload])
		if modeSince.IsZero() {
			modeSince = time.Now()
		}
		if pm, ok := persistedMode[dep.workload]; ok {
			mode = pm
			modeSince = persistedModeSince[dep.workload]
		}
		d := mgr.Evaluate(
			netpolicy.WorkloadState{
				Workload: dep.workload, Namespace: dep.namespace,
				Mode: mode, ModeSince: modeSince,
				LearnWindow:      netpolicyLearnWindowFromEnv(),
				MinObservedFlows: netpolicyMinFlowsFromEnv(),
			},
			netpolicy.FlowsSummary{
				TotalFlows: total, UniquePeers: len(peers[dep.workload]),
				UniquePortProtocol: len(tuples[dep.workload]),
				OutOfPolicyAlerts:  alerts[dep.workload],
				NewTuplesLast24h:   newTuples[dep.workload],
			},
		)
		current, target := string(d.CurrentMode), string(d.TargetMode)
		approval := netpolicyApproval(d, alerts[dep.workload])
		reason, autoApplied := d.Reason, d.AutoApplied
		preview := buildNetworkPolicyPreview(dep.name, dep.namespace, dep.labels, flows)
		item := networkPolicyLifecycleDTO{
			ID: dep.workload, Workload: dep.workload, Namespace: dep.namespace,
			ClusterID: clusterIDForPolicy(cluster), ClusterName: clusterNameForPolicy(cluster),
			CurrentMode: current, TargetMode: target,
			Reason: reason, AutoApplied: autoApplied, EvaluatedAt: time.Now().UTC().Format(time.RFC3339),
			ApprovalStatus: approval, RollbackAvailable: current == "protect",
			Summary: networkPolicyLifecycleSummary{
				TotalFlows: total, UniquePeers: len(peers[dep.workload]), UniquePortProtocol: len(tuples[dep.workload]),
				OutOfPolicyAlerts: alerts[dep.workload], NewTuplesLast24h: newTuples[dep.workload],
				FirstObservation: firstSeen[dep.workload], LastObservation: lastSeen[dep.workload],
			},
			TuplePreview: compactTuplePreview(tuplePreviews[dep.workload]),
			Preview:      preview,
			Diff: networkPolicyDiffDTO{
				Summary: observedPolicyDiffSummary(current, target, alerts[dep.workload]),
				Added:   observedPolicyAddedLines(dep.workload, flows),
				Removed: []string{},
				Changed: []string{"policy mode " + current + " -> " + targetOrCurrent(current, target)},
			},
			AuditTrail: []networkPolicyAuditEventDTO{
				{At: time.Now().UTC().Format(time.RFC3339), Actor: "constellation-policy", Action: "evaluated", Message: reason},
			},
		}
		finalizeNetworkPolicyCandidate(&item)
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Summary.OutOfPolicyAlerts != items[j].Summary.OutOfPolicyAlerts {
			return items[i].Summary.OutOfPolicyAlerts > items[j].Summary.OutOfPolicyAlerts
		}
		return items[i].Summary.TotalFlows > items[j].Summary.TotalFlows
	})
	return items, nil
}

func buildNetworkPolicyPreview(workload, namespace string, labels map[string]string, flows []netpolicy.Flow) networkPolicyPreviewDTO {
	manifests := map[string]string{
		"native": netpolicy.GenerateNative(workload, namespace, labels, flows),
		"cilium": netpolicy.GenerateCilium(workload, namespace, labels, flows),
		"calico": netpolicy.GenerateCalico(workload, namespace, labels, flows),
	}
	return networkPolicyPreviewDTO{
		Engine: "cilium",
		YAML:   manifests["cilium"],
		Refs: map[string]string{
			"native": workload + "-policy",
			"cilium": workload + "-cilium",
			"calico": workload + "-calico",
		},
		Manifests:   manifests,
		L7Protocols: previewL7Protocols(flows),
	}
}

func previewL7Protocols(flows []netpolicy.Flow) []string {
	seen := map[string]bool{}
	for _, flow := range flows {
		for _, value := range strings.Split(flow.L7Protocol, ",") {
			protocol := strings.ToLower(strings.TrimSpace(value))
			if protocol == "" {
				continue
			}
			seen[protocol] = true
		}
	}
	out := make([]string, 0, len(seen))
	for protocol := range seen {
		out = append(out, protocol)
	}
	sort.Strings(out)
	return out
}

func finalizeNetworkPolicyCandidate(item *networkPolicyLifecycleDTO) {
	if item.GeneratedAt == "" {
		item.GeneratedAt = item.EvaluatedAt
	}
	normalizeNetworkPolicyPreview(&item.Preview)
	item.CandidateHash = netutil.StableFlowID(
		item.ClusterID,
		item.Workload,
		item.Namespace,
		item.CurrentMode,
		item.TargetMode,
		item.Preview.YAML,
		manifestHashInput(item.Preview.Manifests),
		strings.Join(item.Preview.L7Protocols, "|"),
		item.Diff.Summary,
		strings.Join(item.Diff.Added, "|"),
		strings.Join(item.Diff.Changed, "|"),
		strings.Join(item.Diff.Removed, "|"),
		tuplePreviewHashInput(item.TuplePreview),
		item.Summary.UniquePeers,
		item.Summary.UniquePortProtocol,
		item.Summary.OutOfPolicyAlerts,
	)
}

func normalizeNetworkPolicyPreview(preview *networkPolicyPreviewDTO) {
	if preview == nil {
		return
	}
	if preview.Engine == "" {
		preview.Engine = "cilium"
	}
	if preview.Manifests == nil {
		preview.Manifests = map[string]string{}
	}
	if preview.YAML != "" && preview.Manifests[preview.Engine] == "" {
		preview.Manifests[preview.Engine] = preview.YAML
	}
	if preview.YAML == "" && preview.Engine != "" && preview.Manifests[preview.Engine] != "" {
		preview.YAML = preview.Manifests[preview.Engine]
	}
	if preview.YAML == "" && preview.Manifests["cilium"] != "" {
		preview.Engine = "cilium"
		preview.YAML = preview.Manifests["cilium"]
	}
	if preview.Refs == nil {
		preview.Refs = map[string]string{}
	}
}

func manifestHashInput(manifests map[string]string) string {
	keys := make([]string, 0, len(manifests))
	for key := range manifests {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+manifests[key])
	}
	return strings.Join(parts, "\n---\n")
}

func networkPolicyPreviewManifestsRaw(preview networkPolicyPreviewDTO) string {
	normalizeNetworkPolicyPreview(&preview)
	raw, err := json.Marshal(preview.Manifests)
	if err != nil || len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

func tuplePreviewHashInput(items []networkPolicyTuplePreviewDTO) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, strings.Join([]string{
			item.Direction,
			item.Peer,
			item.Protocol,
			strconv.Itoa(item.Port),
			item.L7Protocol,
			item.Verdict,
			strconv.FormatBool(item.Included),
			item.ExcludeReason,
		}, "/"))
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// netpolicyApproval derives the approval gate from an elevation Decision:
// out-of-policy alerts hold the workload (blocked); a ready elevation is
// approved; otherwise it's pending more learning. Replaces the old
// total>=20 heuristic with the engine's verdict.
func netpolicyApproval(d netpolicy.Decision, alerts int) string {
	switch {
	case alerts > 0:
		return "blocked"
	case d.TargetMode != "":
		return "approved"
	default:
		return "pending"
	}
}

// netpolicyLearnWindowFromEnv parses CONSTELLATION_NETPOLICY_LEARN_WINDOW (a
// Go duration like "1h"). 0 (empty/invalid) falls through to the engine's
// 7-day default. Lets fresh/demo clusters promote without waiting a week.
func netpolicyLearnWindowFromEnv() time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(os.Getenv("CONSTELLATION_NETPOLICY_LEARN_WINDOW")))
	if err != nil {
		return 0
	}
	return d
}

// netpolicyMinFlowsFromEnv parses CONSTELLATION_NETPOLICY_MIN_FLOWS. 0 falls
// through to the engine's default (5).
func netpolicyMinFlowsFromEnv() int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("CONSTELLATION_NETPOLICY_MIN_FLOWS")))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func observedPolicyDiffSummary(current, target string, alerts int) string {
	if alerts > 0 {
		return "Keeps workload in monitor until out-of-policy traffic is triaged."
	}
	return "Adds explicit ingress/egress allow rules from selected-cluster observed stable tuples and preserves DNS access."
}

func observedPolicyAddedLines(workload string, flows []netpolicy.Flow) []string {
	_, targetName := netutil.SplitWorkload(workload)
	// Dedup: many observed flows collapse to the same (direction, proto, port,
	// peer) rule (e.g. egress 443 to many external IPs all read as
	// external/external). Emit each distinct learned allow-rule once, like
	// NeuVector collapses its learned rules, so the truncation cap bounds
	// distinct rules instead of dropping them in favor of duplicates.
	seen := map[string]struct{}{}
	lines := []string{}
	add := func(line string) {
		if _, ok := seen[line]; ok {
			return
		}
		seen[line] = struct{}{}
		lines = append(lines, line)
	}
	for _, f := range flows {
		if f.SrcWorkload == targetName && f.DstWorkload != "" {
			add("egress " + strings.ToLower(f.Protocol) + "/" + stringIntForPolicy(f.Port) + " to " + f.DstNamespace + "/" + f.DstWorkload)
		}
		if f.DstWorkload == targetName && f.SrcWorkload != "" {
			add("ingress " + strings.ToLower(f.Protocol) + "/" + stringIntForPolicy(f.Port) + " from " + f.SrcNamespace + "/" + f.SrcWorkload)
		}
	}
	sort.Strings(lines)
	if len(lines) > 8 {
		return lines[:8]
	}
	return lines
}

func tupleDirection(workload, src, dst string) string {
	if workload == src {
		return "egress"
	}
	if workload == dst {
		return "ingress"
	}
	return "related"
}

func tupleExcludeReason(verdict string) string {
	if strings.ToLower(verdict) == "allow" {
		return ""
	}
	return "held: " + strings.ToLower(verdict) + " verdict"
}

func tupleInclusion(verdict, src, dst, dstAddr string) (bool, string) {
	if strings.ToLower(verdict) != "allow" {
		return false, tupleExcludeReason(verdict)
	}
	if isExternalPeer(dst) && strings.TrimSpace(dstAddr) == "" {
		return false, "held: external destination missing CIDR"
	}
	if isExternalPeer(src) {
		return false, "held: external source missing workload selector"
	}
	return true, ""
}

// isExternalPeer reports whether a flow workload identifier denotes an external
// (off-cluster) peer. Ingest collapses non-well-known externals to the bare
// "external" bucket (real IP kept in dst_addr) and keeps the un-collapsed
// "external/<name>" form for well-known peers; both must be treated as external
// so the read path anchors egress to a toCIDR/toFQDNs instead of rendering an
// app=external podSelector that matches no pod. H12.
func isExternalPeer(workload string) bool {
	return workload == "external" || strings.HasPrefix(workload, "external/")
}

func compactTuplePreview(items []networkPolicyTuplePreviewDTO) []networkPolicyTuplePreviewDTO {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Included != items[j].Included {
			return !items[i].Included
		}
		if items[i].Direction != items[j].Direction {
			return items[i].Direction < items[j].Direction
		}
		if items[i].Peer != items[j].Peer {
			return items[i].Peer < items[j].Peer
		}
		return items[i].Port < items[j].Port
	})
	if len(items) > 12 {
		return items[:12]
	}
	return items
}

func clusterIDForPolicy(cluster *networkPolicyCluster) string {
	if cluster == nil {
		return ""
	}
	return cluster.ID
}

func clusterNameForPolicy(cluster *networkPolicyCluster) string {
	if cluster == nil {
		return ""
	}
	return cluster.Name
}

func stringIntForPolicy(value int) string {
	return strconv.Itoa(value)
}

// persistedWorkloadModes loads the durable per-workload lifecycle mode + the time
// that mode was entered (mode_since), so the elevation engine can evaluate real
// time-in-mode for transitions. Workloads with no persisted row are absent from
// the maps (callers default them to Discover). NET-4.
func (h *NetworkPolicies) persistedWorkloadModes(r *http.Request, orgID string, cluster *networkPolicyCluster) (map[string]netpolicy.Mode, map[string]time.Time, error) {
	modes := map[string]netpolicy.Mode{}
	since := map[string]time.Time{}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT workload, current_mode, mode_since
  FROM network_policy_lifecycle_states
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)`, orgID, clusterUUIDParam(cluster))
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var workload, mode string
		var modeSince time.Time
		if err := rows.Scan(&workload, &mode, &modeSince); err != nil {
			return nil, nil, err
		}
		modes[workload] = netpolicy.Mode(mode)
		since[workload] = modeSince
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return modes, since, nil
}

func (h *NetworkPolicies) applyPersistedState(r *http.Request, orgID string, cluster *networkPolicyCluster, items []networkPolicyLifecycleDTO) ([]networkPolicyLifecycleDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT COALESCE(s.cluster_id::text, ''), COALESCE(c.name, ''), s.workload, s.current_mode, COALESCE(s.target_mode, ''), s.approval_status, s.reason,
       rollback_available, rollback_refs, audit_trail, last_applied_at,
       COALESCE(applied_ref, ''), COALESCE(rollback_ref, ''), COALESCE(candidate_hash, '')
  FROM network_policy_lifecycle_states s
  LEFT JOIN clusters c ON c.id = s.cluster_id
 WHERE s.org_id = $1
   AND ($2::uuid IS NULL OR s.cluster_id = $2)`, orgID, clusterUUIDParam(cluster))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byWorkload := make(map[string]int, len(items))
	for i := range items {
		byWorkload[items[i].Workload] = i
	}
	for rows.Next() {
		var rowClusterID, rowClusterName, workload, current, target, approval, reason, appliedRef, rollbackRef, approvedCandidateHash string
		var rollback bool
		var refsRaw, auditRaw []byte
		var lastApplied *time.Time
		if err := rows.Scan(&rowClusterID, &rowClusterName, &workload, &current, &target, &approval, &reason, &rollback, &refsRaw, &auditRaw, &lastApplied, &appliedRef, &rollbackRef, &approvedCandidateHash); err != nil {
			return nil, err
		}
		idx, ok := byWorkload[workload]
		if !ok {
			continue
		}
		items[idx].CurrentMode = current
		items[idx].ClusterID = rowClusterID
		items[idx].ClusterName = rowClusterName
		items[idx].TargetMode = target
		items[idx].ApprovalStatus = approval
		items[idx].ApprovedCandidateHash = approvedCandidateHash
		items[idx].CandidateStale = approvedCandidateHash != "" && items[idx].CandidateHash != "" && approvedCandidateHash != items[idx].CandidateHash
		items[idx].Reason = reason
		items[idx].RollbackAvailable = rollback
		items[idx].AppliedRef = appliedRef
		items[idx].RollbackRef = rollbackRef
		if lastApplied != nil {
			items[idx].LastAppliedAt = lastApplied.UTC().Format(time.RFC3339)
		} else {
			items[idx].LastAppliedAt = ""
		}
		var refs map[string]string
		if err := json.Unmarshal(refsRaw, &refs); err == nil && len(refs) > 0 {
			items[idx].Preview.Refs = refs
		}
		var audit []networkPolicyAuditEventDTO
		if err := json.Unmarshal(auditRaw, &audit); err == nil && len(audit) > 0 {
			items[idx].AuditTrail = append(items[idx].AuditTrail, audit...)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := h.applyNetworkPolicyApplyStatuses(r, orgID, cluster, items); err != nil {
		return nil, err
	}
	return items, nil
}

func (h *NetworkPolicies) applyNetworkPolicyApplyStatuses(r *http.Request, orgID string, cluster *networkPolicyCluster, items []networkPolicyLifecycleDTO) error {
	if len(items) == 0 || h.db == nil {
		return nil
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT workload, flavor, resource_ref, desired_mode, approval_status, last_action, status, error,
       COALESCE(candidate_hash, ''), COALESCE(applied_ref, ''), COALESCE(rollback_ref, ''),
       last_applied_at, last_deleted_at, updated_at
  FROM network_policy_apply_status
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
 ORDER BY workload, flavor`, orgID, clusterUUIDParam(cluster))
	if err != nil {
		if strings.Contains(err.Error(), "network_policy_apply_status") {
			return nil
		}
		return err
	}
	defer rows.Close()
	byWorkload := make(map[string]int, len(items))
	for i := range items {
		byWorkload[items[i].Workload] = i
	}
	for rows.Next() {
		var workload string
		var status networkPolicyApplyStatusDTO
		var lastApplied, lastDeleted *time.Time
		var updated time.Time
		if err := rows.Scan(&workload, &status.Flavor, &status.ResourceRef, &status.DesiredMode, &status.ApprovalStatus, &status.LastAction, &status.Status, &status.Error, &status.CandidateHash, &status.AppliedRef, &status.RollbackRef, &lastApplied, &lastDeleted, &updated); err != nil {
			return err
		}
		idx, ok := byWorkload[workload]
		if !ok {
			continue
		}
		if lastApplied != nil {
			status.LastAppliedAt = lastApplied.UTC().Format(time.RFC3339)
		}
		if lastDeleted != nil {
			status.LastDeletedAt = lastDeleted.UTC().Format(time.RFC3339)
		}
		status.UpdatedAt = updated.UTC().Format(time.RFC3339)
		items[idx].ApplyStatuses = append(items[idx].ApplyStatuses, status)
	}
	return rows.Err()
}

func (h *NetworkPolicies) persistAction(r *http.Request, item networkPolicyLifecycleDTO, action, orgID, userID string, cluster *networkPolicyCluster) (persistedNetworkPolicyAction, error) {
	var body networkPolicyActionBody
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	idempotencyKey := networkPolicyIdempotencyKey(r, body)
	if idempotencyKey != "" {
		if replay, ok, err := h.replayNetworkPolicyAction(r, item, orgID, cluster, idempotencyKey); err != nil {
			return persistedNetworkPolicyAction{}, err
		} else if ok {
			return replay, nil
		}
	}
	previousMode := item.CurrentMode
	now := time.Now().UTC()
	nextMode := nextModeForAction(item, action)
	rollbackRef := ""
	targetMode := item.TargetMode
	approval := item.ApprovalStatus
	reason := item.Reason
	rollback := item.RollbackAvailable
	var lastApplied *time.Time
	if item.LastAppliedAt != "" {
		if parsed, err := time.Parse(time.RFC3339, item.LastAppliedAt); err == nil {
			lastApplied = &parsed
		}
	}
	switch action {
	case "approve":
		approval = "approved"
		reason = "approved for " + nextMode + "; awaiting apply"
	case "apply":
		item.CurrentMode = nextMode
		targetMode = ""
		approval = "applied"
		reason = "applied " + nextMode + " policy bundle"
		rollback = true
		lastApplied = &now
		rollbackRef = "rollback-" + netutil.StableFlowID(orgID, item.Workload, previousMode, nextMode, now.UnixNano())
	case "promote":
		// One-step advance discover→monitor→protect. The network-policy-applier
		// reconciles current_mode to the cluster (protect ⇒ enforce).
		item.CurrentMode = nextMode
		targetMode = ""
		approval = "applied"
		rollback = true
		lastApplied = &now
		rollbackRef = "rollback-" + netutil.StableFlowID(orgID, item.Workload, previousMode, nextMode, now.UnixNano())
		reason = "promoted to " + nextMode
	case "force":
		// Operator override — jump straight to a chosen posture, ignoring the ladder.
		item.CurrentMode = nextMode
		targetMode = ""
		approval = "applied"
		rollback = true
		lastApplied = &now
		rollbackRef = "rollback-" + netutil.StableFlowID(orgID, item.Workload, previousMode, nextMode, now.UnixNano())
		if strings.TrimSpace(body.Reason) != "" {
			reason = "forced to " + nextMode + ": " + strings.TrimSpace(body.Reason)
		} else {
			reason = "forced to " + nextMode
		}
	case "demote":
		item.CurrentMode = nextMode
		targetMode = ""
		approval = "demoted"
		rollback = true
		rollbackRef = "rollback-" + netutil.StableFlowID(orgID, item.Workload, previousMode, nextMode, now.UnixNano())
		if strings.TrimSpace(body.Reason) != "" {
			reason = strings.TrimSpace(body.Reason)
		} else {
			reason = "manual demotion to " + nextMode
		}
	default:
		return persistedNetworkPolicyAction{Policy: item}, nil
	}
	item.TargetMode = targetMode
	item.ApprovalStatus = approval
	item.Reason = reason
	item.RollbackAvailable = rollback
	if lastApplied != nil {
		item.LastAppliedAt = lastApplied.UTC().Format(time.RFC3339)
	}
	item.AppliedRef = "applied-" + netutil.StableFlowID(orgID, item.Workload, item.CurrentMode, item.TargetMode)
	item.RollbackRef = rollbackRef
	item.ApprovedCandidateHash = item.CandidateHash
	item.CandidateStale = false
	event := networkPolicyAuditEventDTO{
		At:             now.Format(time.RFC3339),
		Actor:          userID,
		Action:         action,
		Message:        reason,
		IdempotencyKey: idempotencyKey,
	}
	audit := []networkPolicyAuditEventDTO{event}
	refsRaw, _ := json.Marshal(item.Preview.Refs)
	manifestsRaw := networkPolicyPreviewManifestsRaw(item.Preview)
	diffRaw, _ := json.Marshal(item.Diff)
	auditRaw, _ := json.Marshal(audit)
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		return persistedNetworkPolicyAction{}, err
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if _, err := tx.Exec(r.Context(), `
INSERT INTO network_policy_lifecycle_states (
    org_id, cluster_id, workload, namespace, current_mode, target_mode, approval_status, reason,
    preview_yaml, preview_manifests, diff, rollback_available, rollback_refs, audit_trail, last_applied_at,
    applied_ref, rollback_ref, candidate_hash, created_by, updated_by, updated_at, mode_since
) VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13::jsonb,$14::jsonb,$15,$16,$17,NULLIF($18,''),$19,$19,NOW(),NOW())
ON CONFLICT (org_id, cluster_id, workload) DO UPDATE SET
    namespace = EXCLUDED.namespace,
    -- NET-4: only advance the mode clock when the mode actually transitions, so
    -- Monitor->Protect evaluates against real time-in-mode (not every re-evaluate).
    mode_since = CASE WHEN network_policy_lifecycle_states.current_mode IS DISTINCT FROM EXCLUDED.current_mode
                      THEN NOW() ELSE network_policy_lifecycle_states.mode_since END,
    current_mode = EXCLUDED.current_mode,
    target_mode = EXCLUDED.target_mode,
    approval_status = EXCLUDED.approval_status,
    reason = EXCLUDED.reason,
    preview_yaml = EXCLUDED.preview_yaml,
    preview_manifests = EXCLUDED.preview_manifests,
    diff = EXCLUDED.diff,
    rollback_available = EXCLUDED.rollback_available,
    rollback_refs = EXCLUDED.rollback_refs,
    audit_trail = network_policy_lifecycle_states.audit_trail || EXCLUDED.audit_trail,
    last_applied_at = EXCLUDED.last_applied_at,
    applied_ref = EXCLUDED.applied_ref,
    rollback_ref = EXCLUDED.rollback_ref,
    candidate_hash = EXCLUDED.candidate_hash,
    updated_by = EXCLUDED.updated_by,
    updated_at = NOW()`,
		orgID, clusterUUIDParam(cluster), item.Workload, item.Namespace, item.CurrentMode, item.TargetMode, item.ApprovalStatus, item.Reason,
		item.Preview.YAML, manifestsRaw, string(diffRaw), item.RollbackAvailable, string(refsRaw), string(auditRaw), lastApplied,
		"applied-"+netutil.StableFlowID(orgID, item.Workload, item.CurrentMode, item.TargetMode), rollbackRef, item.CandidateHash, userID); err != nil {
		return persistedNetworkPolicyAction{}, err
	}
	var actionID string
	if err := tx.QueryRow(r.Context(), `
INSERT INTO network_policy_lifecycle_actions (
    org_id, cluster_id, workload, namespace, action, previous_mode, next_mode, reason,
    preview_yaml, preview_manifests, preview_refs, diff, rollback_ref, idempotency_key, candidate_hash, actor_id
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12::jsonb,NULLIF($13,''),NULLIF($14,''),NULLIF($15,''),$16)
RETURNING id::text`,
		orgID, clusterUUIDParam(cluster), item.Workload, item.Namespace, action, previousMode, nextMode, item.Reason,
		item.Preview.YAML, manifestsRaw, string(refsRaw), string(diffRaw), rollbackRef, idempotencyKey, item.CandidateHash, userID).Scan(&actionID); err != nil {
		return persistedNetworkPolicyAction{}, err
	}
	if rollbackRef != "" {
		if _, err := tx.Exec(r.Context(), `
INSERT INTO network_policy_rollback_refs (
    org_id, cluster_id, workload, namespace, rollback_ref, previous_mode, restore_mode, preview_yaml, preview_manifests, preview_refs, created_by
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11)
ON CONFLICT (org_id, cluster_id, rollback_ref) DO NOTHING`,
			orgID, clusterUUIDParam(cluster), item.Workload, item.Namespace, rollbackRef, previousMode, previousMode, item.Preview.YAML, manifestsRaw, string(refsRaw), userID); err != nil {
			return persistedNetworkPolicyAction{}, err
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		return persistedNetworkPolicyAction{}, err
	}
	h.logPolicyAudit(r, orgID, userID, "network_policy."+action, item.Workload, previousMode, item.CurrentMode, item.Reason, actionID, idempotencyKey)
	item.AuditTrail = append(item.AuditTrail, event)
	return persistedNetworkPolicyAction{Policy: item, ActionID: actionID, RollbackRef: rollbackRef, IdempotencyKey: idempotencyKey}, nil
}

func (h *NetworkPolicies) persistRollback(r *http.Request, item networkPolicyLifecycleDTO, orgID, userID string, cluster *networkPolicyCluster) (persistedNetworkPolicyAction, error) {
	var body networkPolicyActionBody
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	idempotencyKey := networkPolicyIdempotencyKey(r, body)
	if idempotencyKey != "" {
		if replay, ok, err := h.replayNetworkPolicyAction(r, item, orgID, cluster, idempotencyKey); err != nil {
			return persistedNetworkPolicyAction{}, err
		} else if ok {
			return replay, nil
		}
	}
	now := time.Now().UTC()
	rollbackRef := item.RollbackRef
	if strings.TrimSpace(body.RollbackRef) != "" {
		rollbackRef = strings.TrimSpace(body.RollbackRef)
	}
	if rollbackRef == "" {
		return persistedNetworkPolicyAction{}, errNetworkPolicyRollbackNotFound(item.Workload)
	}
	var restoreMode string
	var refsRaw []byte
	var manifestsRaw []byte
	var previewYAML string
	if err := h.db.Pool().QueryRow(r.Context(), `
SELECT restore_mode, preview_refs, preview_yaml, COALESCE(preview_manifests, '{}'::jsonb)
  FROM network_policy_rollback_refs
 WHERE org_id = $1 AND ($2::uuid IS NULL OR cluster_id = $2) AND workload = $3 AND rollback_ref = $4
 ORDER BY created_at DESC
 LIMIT 1`, orgID, clusterUUIDParam(cluster), item.Workload, rollbackRef).Scan(&restoreMode, &refsRaw, &previewYAML, &manifestsRaw); err != nil {
		return persistedNetworkPolicyAction{}, errNetworkPolicyRollbackNotFound(item.Workload)
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		reason = "rolled back to " + restoreMode + " from " + item.CurrentMode
	}
	previousMode := item.CurrentMode
	item.CurrentMode = restoreMode
	item.TargetMode = ""
	item.ApprovalStatus = "rolled_back"
	item.Reason = reason
	item.RollbackAvailable = false
	item.RollbackRef = ""
	if previewYAML != "" {
		item.Preview.YAML = previewYAML
	}
	var manifests map[string]string
	if err := json.Unmarshal(manifestsRaw, &manifests); err == nil && len(manifests) > 0 {
		item.Preview.Manifests = manifests
	}
	var refs map[string]string
	if err := json.Unmarshal(refsRaw, &refs); err == nil && len(refs) > 0 {
		item.Preview.Refs = refs
	}
	normalizeNetworkPolicyPreview(&item.Preview)
	event := networkPolicyAuditEventDTO{
		At:             now.Format(time.RFC3339),
		Actor:          userID,
		Action:         "rollback",
		Message:        reason,
		IdempotencyKey: idempotencyKey,
	}
	auditRaw, _ := json.Marshal([]networkPolicyAuditEventDTO{event})
	diffRaw, _ := json.Marshal(item.Diff)
	nextRefsRaw, _ := json.Marshal(item.Preview.Refs)
	nextManifestsRaw := networkPolicyPreviewManifestsRaw(item.Preview)
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		return persistedNetworkPolicyAction{}, err
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if _, err := tx.Exec(r.Context(), `
UPDATE network_policy_lifecycle_states
   SET current_mode = $1,
       mode_since = CASE WHEN current_mode IS DISTINCT FROM $1 THEN NOW() ELSE mode_since END,
       target_mode = NULL,
       approval_status = 'rolled_back',
       reason = $2,
       rollback_available = FALSE,
       audit_trail = audit_trail || $3::jsonb,
       rollback_ref = NULL,
       updated_by = $4,
       updated_at = NOW()
 WHERE org_id = $5 AND ($6::uuid IS NULL OR cluster_id = $6) AND workload = $7`,
		item.CurrentMode, item.Reason, string(auditRaw), userID, orgID, clusterUUIDParam(cluster), item.Workload); err != nil {
		return persistedNetworkPolicyAction{}, err
	}
	var actionID string
	if err := tx.QueryRow(r.Context(), `
INSERT INTO network_policy_lifecycle_actions (
    org_id, cluster_id, workload, namespace, action, previous_mode, next_mode, reason,
    preview_yaml, preview_manifests, preview_refs, diff, rollback_ref, idempotency_key, actor_id
) VALUES ($1,$2,$3,$4,'rollback',$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11::jsonb,$12,NULLIF($13,''),$14)
RETURNING id::text`,
		orgID, clusterUUIDParam(cluster), item.Workload, item.Namespace, previousMode, item.CurrentMode, item.Reason,
		item.Preview.YAML, nextManifestsRaw, string(nextRefsRaw), string(diffRaw), rollbackRef, idempotencyKey, userID).Scan(&actionID); err != nil {
		return persistedNetworkPolicyAction{}, err
	}
	if err := tx.Commit(r.Context()); err != nil {
		return persistedNetworkPolicyAction{}, err
	}
	h.logPolicyAudit(r, orgID, userID, "network_policy.rollback", item.Workload, previousMode, item.CurrentMode, item.Reason, actionID, idempotencyKey)
	item.AuditTrail = append(item.AuditTrail, event)
	return persistedNetworkPolicyAction{Policy: item, ActionID: actionID, RollbackRef: rollbackRef, IdempotencyKey: idempotencyKey}, nil
}

func networkPolicyIdempotencyKey(r *http.Request, body networkPolicyActionBody) string {
	if key := strings.TrimSpace(r.Header.Get("Idempotency-Key")); key != "" {
		return key
	}
	return strings.TrimSpace(body.IdempotencyKey)
}

func clusterUUIDParam(cluster *networkPolicyCluster) any {
	if cluster == nil || cluster.ID == "" {
		return nil
	}
	return cluster.ID
}

func (h *NetworkPolicies) replayNetworkPolicyAction(r *http.Request, item networkPolicyLifecycleDTO, orgID string, cluster *networkPolicyCluster, idempotencyKey string) (persistedNetworkPolicyAction, bool, error) {
	var actionID, workload, action string
	var rollbackRef *string
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT id::text, workload, action, rollback_ref
  FROM network_policy_lifecycle_actions
 WHERE org_id = $1 AND ($2::uuid IS NULL OR cluster_id = $2) AND idempotency_key = $3
 ORDER BY created_at DESC
 LIMIT 1`, orgID, clusterUUIDParam(cluster), idempotencyKey).Scan(&actionID, &workload, &action, &rollbackRef)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return persistedNetworkPolicyAction{}, false, nil
		}
		return persistedNetworkPolicyAction{}, false, err
	}
	if workload != item.Workload {
		return persistedNetworkPolicyAction{}, false, errNetworkPolicyIdempotencyConflict(idempotencyKey)
	}
	items, err := h.applyPersistedState(r, orgID, cluster, []networkPolicyLifecycleDTO{item})
	if err != nil {
		return persistedNetworkPolicyAction{}, false, err
	}
	ref := ""
	if rollbackRef != nil {
		ref = *rollbackRef
	}
	return persistedNetworkPolicyAction{
		Policy:         items[0],
		ActionID:       actionID,
		RollbackRef:    ref,
		IdempotencyKey: idempotencyKey,
		Idempotent:     true,
	}, action != "", nil
}

func (h *NetworkPolicies) logPolicyAudit(r *http.Request, orgID, userID, action, workload, previousMode, nextMode, reason, actionID, idempotencyKey string) {
	if h.auditLog == nil {
		return
	}
	parsedOrg, err := uuid.Parse(orgID)
	if err != nil {
		return
	}
	parsedUser, err := uuid.Parse(userID)
	if err != nil {
		return
	}
	actorIP := net.ParseIP(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		actorIP = net.ParseIP(host)
	}
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{
		OrgID:      &parsedOrg,
		ActorID:    &parsedUser,
		ActorIP:    actorIP,
		Action:     action,
		TargetKind: "network-policy",
		TargetID:   workload,
		Before: map[string]any{
			"mode": previousMode,
		},
		After: map[string]any{
			"mode":            nextMode,
			"reason":          reason,
			"action_id":       actionID,
			"idempotency_key": idempotencyKey,
		},
		RequestID: chimw.GetReqID(r.Context()),
	})
}

type networkPolicyRollbackNotFound string

func (e networkPolicyRollbackNotFound) Error() string {
	return "rollback ref not found for " + string(e)
}

func errNetworkPolicyRollbackNotFound(workload string) error {
	return networkPolicyRollbackNotFound(workload)
}

type networkPolicyIdempotencyConflict string

func (e networkPolicyIdempotencyConflict) Error() string {
	return "idempotency key already used for another network policy action: " + string(e)
}

func errNetworkPolicyIdempotencyConflict(key string) error {
	return networkPolicyIdempotencyConflict(key)
}

func policyWorkloadAndAction(r *http.Request) (string, string) {
	workload := chi.URLParam(r, "workload")
	action := chi.URLParam(r, "action")
	if decoded, err := url.PathUnescape(workload); err == nil {
		workload = decoded
	}
	return workload, action
}

// policyModeOrder is the discover→monitor→protect posture ladder.
var policyModeOrder = []string{"discover", "monitor", "protect"}

func policyModeIndex(mode string) int {
	for i, m := range policyModeOrder {
		if m == mode {
			return i
		}
	}
	return 0 // unknown ⇒ discover (the default posture)
}

func isValidPolicyMode(mode string) bool {
	return mode == "discover" || mode == "monitor" || mode == "protect"
}

func nextModeForAction(item networkPolicyLifecycleDTO, action string) string {
	cur := item.CurrentMode
	if cur == "" {
		cur = "discover" // every workload defaults to discover
	}
	switch action {
	case "approve", "apply":
		return targetOrCurrent(cur, item.TargetMode)
	case "promote": // advance one rung: discover→monitor→protect
		i := policyModeIndex(cur)
		if i < len(policyModeOrder)-1 {
			return policyModeOrder[i+1]
		}
		return cur // already at protect
	case "force": // jump straight to an operator-chosen posture
		if isValidPolicyMode(item.ForcedMode) {
			return item.ForcedMode
		}
		return cur
	case "demote":
		if cur == "protect" {
			return "monitor"
		}
		if cur == "monitor" {
			return "discover"
		}
	}
	return cur
}

func targetOrCurrent(current, target string) string {
	if target != "" {
		return target
	}
	return current
}

func countNetworkPolicies(items []networkPolicyLifecycleDTO, match func(networkPolicyLifecycleDTO) bool) int {
	total := 0
	for _, item := range items {
		if match(item) {
			total++
		}
	}
	return total
}
