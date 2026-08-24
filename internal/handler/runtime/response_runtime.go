// RT-2: response/quarantine engine wiring for the runtime-event ingest path.
//
// The API server constructs a response.Engine (pkg/response) whose rules are loaded from
// the same response_rules_v2 table the ResponseRulesV2 CRUD handler writes. EventsIngest
// hands each HIGH/CRITICAL classified runtime event to ResponseDispatch, which loads the
// org's enabled rules, evaluates them, and fires matching actions.
//
// quarantineRuntime is the response.Runtime bridge: it records an origin='auto' row in
// quarantine_entries (distinct from the 'manual' origin the user-facing handler writes)
// reusing the same insert path.
//
// RT-3: Isolate additionally enqueues a live network cordon. Quarantine still only
// records the entry (it blocks at next admission via the quarantine snapshot). The
// distinction matters: Quarantine is the image/admission deny primitive; Isolate is the
// running-workload enforcement primitive (NeuVector's enforcer network-isolates a live
// workload), so only Isolate emits a deny-all NetworkPolicy for the netpolicy-applier to
// reconcile onto the cluster.
package runtime

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	runtimequarantine "github.com/alphabravocompany/constellation/internal/runtime/quarantine"
	"github.com/alphabravocompany/constellation/pkg/notify"
	"github.com/alphabravocompany/constellation/pkg/quarantine"
	"github.com/alphabravocompany/constellation/pkg/response"
)

// quarantineRuntime implements response.Runtime by recording auto-origin quarantine
// entries. Per-dispatch org/cluster context is captured at construction time by the
// server-side closure (see NewResponseDispatch), so the interface's workload-only methods
// have everything they need.
type quarantineRuntime struct {
	db        *db.DB
	orgID     uuid.UUID
	clusterID uuid.UUID
}

// Quarantine records an origin='auto' workload-scoped quarantine entry. Best-effort: a
// duplicate active entry (collapsed by uniq_quarantine_active_target) is treated as
// success, matching the manual handler's conflict semantics.
func (q *quarantineRuntime) Quarantine(ctx context.Context, workload, reason string) error {
	_, err := q.record(ctx, workload, reason)
	return err
}

// Isolate records the auto quarantine entry AND enqueues a live network cordon for the
// running workload: a default-deny NetworkPolicy is written as a lifecycle state with
// approval_status='applied', current_mode='protect', which the netpolicy-applier
// reconciles onto the cluster on its next interval (see cmd/constellation-netpolicy-applier
// loadActionableStates). This is the RT-3 enforcement primitive — Quarantine blocks at
// next admission, Isolate severs an already-running workload's network.
//
// ponytail: the applier doing the live `kubectl apply` needs a running cluster to validate
// end-to-end; that's a cluster-only path. Here we own rendering + enqueuing the row.
func (q *quarantineRuntime) Isolate(ctx context.Context, workload, reason string) error {
	entryID, err := q.record(ctx, workload, reason)
	if err != nil {
		return err
	}
	return q.enqueueCordon(ctx, workload, reason, entryID)
}

// Kill enqueues a targeted kill_process response action (RT-KILL-02) for the running
// workload onto runtime_response_actions. The runtime-agent responder pulls pending rows
// for its node (GET /runtime/response-actions:pending), SIGKILLs the resolved pid, and
// POSTs the outcome back to the :result sink. Best-effort and node-agnostic: the row is
// left node=” so it's offered to every agent in the cluster; each agent's
// killProcessDecision guards against killing the wrong process (comm/container/pid checks),
// so an empty-target row is harmless where the workload isn't present.
//
// Mirrors Isolate's shape (org/cluster captured at construction, workload+reason in). The
// pid/comm are resolved by the agent from the workload/container at execution time; the
// Runtime interface carries only the workload, so nothing narrower is passed through here.
func (q *quarantineRuntime) Kill(ctx context.Context, workload, reason string) error {
	matchKey := strings.TrimSpace(workload)
	if matchKey == "" {
		return nil // nothing to target
	}
	_, err := q.db.Pool().Exec(ctx, `
INSERT INTO runtime_response_actions (org_id, cluster_id, type, workload_id, state)
VALUES ($1, $2, 'kill_process', $3, 'pending')`,
		q.orgID, q.clusterID, matchKey)
	return err
}

// record inserts the origin='auto' quarantine entry and returns its id. A nil id (with no
// error) means there was nothing to record or an existing active entry collapsed the insert.
func (q *quarantineRuntime) record(ctx context.Context, workload, reason string) (*uuid.UUID, error) {
	matchKey := strings.TrimSpace(workload)
	if matchKey == "" {
		return nil, nil // nothing to attribute the quarantine to
	}
	if strings.TrimSpace(reason) == "" {
		reason = "auto-response"
	}
	// origin='auto', no created_by (NULL); 24h expiry so a noisy auto-quarantine fades
	// unless an operator promotes it (per migration 047's intended default).
	var id uuid.UUID
	err := q.db.Pool().QueryRow(ctx, `
INSERT INTO quarantine_entries
    (org_id, cluster_id, scope, match_key, reason, origin, source_kind, expires_at)
VALUES ($1, $2, $3, $4, $5, 'auto', 'runtime_event', NOW() + INTERVAL '24 hours')
RETURNING id`,
		q.orgID, q.clusterID, string(quarantine.ScopeWorkload), matchKey, reason).Scan(&id)
	// uniq_quarantine_active_target is a partial unique INDEX (can't be named in ON
	// CONFLICT), so an existing active entry surfaces as a duplicate-key error here —
	// collapse it into success, mirroring the manual handler's 409-conflict semantics.
	if err != nil && strings.Contains(err.Error(), "uniq_quarantine_active_target") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// enqueueCordon writes a default-deny NetworkPolicy for the running workload into
// network_policy_lifecycle_states so the netpolicy-applier applies it live. The
// quarantine entry id is recorded as provenance in the reason + audit trail, linking the
// applied policy back to the runtime alert that triggered it.
func (q *quarantineRuntime) enqueueCordon(ctx context.Context, workload, reason string, entryID *uuid.UUID) error {
	matchKey := strings.TrimSpace(workload)
	if matchKey == "" {
		return nil
	}
	ns, name := splitWorkloadKey(matchKey)
	target := runtimequarantine.Target{Namespace: ns, Pod: name, WorkloadID: matchKey}
	denyAll := runtimequarantine.RenderDenyAllYAML(target)
	manifests, _ := json.Marshal(map[string]string{"native": denyAll})

	prov := "runtime quarantine isolate"
	if strings.TrimSpace(reason) != "" {
		prov = strings.TrimSpace(reason)
	}
	if entryID != nil {
		prov += " (quarantine_entry " + entryID.String() + ")"
	}
	auditTrail := []map[string]any{{
		"at":      time.Now().UTC().Format(time.RFC3339),
		"actor":   "constellation-response",
		"action":  "isolate",
		"message": prov,
	}}
	auditRaw, _ := json.Marshal(auditTrail)

	// approval_status='applied' + current_mode='protect' is exactly the state the applier's
	// loadActionableStates selects on (and DesiredAction maps protect->ActionApply). We
	// upsert on (org_id, cluster_id, workload) so a re-fired isolate refreshes the cordon
	// rather than erroring.
	_, err := q.db.Pool().Exec(ctx, `
INSERT INTO network_policy_lifecycle_states (
    org_id, cluster_id, workload, namespace, current_mode, approval_status, reason,
    preview_yaml, preview_manifests, audit_trail, last_applied_at
) VALUES ($1, $2, $3, $4, 'protect', 'applied', $5, $6, $7::jsonb, $8::jsonb, NOW())
ON CONFLICT (org_id, cluster_id, workload) DO UPDATE SET
    current_mode = 'protect',
    approval_status = 'applied',
    reason = EXCLUDED.reason,
    preview_yaml = EXCLUDED.preview_yaml,
    preview_manifests = EXCLUDED.preview_manifests,
    audit_trail = network_policy_lifecycle_states.audit_trail || EXCLUDED.audit_trail,
    last_applied_at = NOW(),
    updated_at = NOW()`,
		q.orgID, q.clusterID, matchKey, ns, prov, denyAll, string(manifests), string(auditRaw))
	return err
}

// splitWorkloadKey splits a "namespace/name" quarantine match key. Keys without a slash
// (a bare pod/workload name) fall back to the "default" namespace.
func splitWorkloadKey(key string) (namespace, name string) {
	if i := strings.IndexByte(key, '/'); i >= 0 {
		return key[:i], key[i+1:]
	}
	return "default", key
}

// NewResponseDispatch builds the EventsIngest response hook (RT-2). It returns a closure
// that, per HIGH/CRITICAL event, loads the org/cluster's enabled response rules from
// response_rules_v2, points the engine at an auto-quarantine runtime bridge scoped to that
// org/cluster, and dispatches.
//
// dispatcher wires the notify.Receiver map into the engine so a rule's notify/ticket action
// actually reaches the receiver it names (previously the engine was built with nil receivers,
// so those actions appended an "unknown receiver" warning and were silently dropped). Each
// receiver is delivered through the dispatcher's own tracked path (persisted delivery row,
// HMAC signing, retries, and the SSRF-hardened HTTP client). dispatcher may be nil (tests),
// in which case notify/ticket actions still surface as logged warnings rather than vanishing.
func NewResponseDispatch(database *db.DB, dispatcher *notify.Dispatcher) func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event) {
	return func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event) {
		rules, err := loadResponseRulesV2(ctx, database, orgID, clusterID)
		if err != nil || len(rules) == 0 {
			return
		}
		ev = annotateResponseRuleGroups(ctx, database, orgID, clusterID, ev, rules)
		receivers := buildReceiverMap(ctx, database, dispatcher, orgID, rules)
		eng := response.NewEngine(receivers, &quarantineRuntime{db: database, orgID: orgID, clusterID: clusterID}, nil)
		eng.SetRules(rules)
		// Don't discard the engine's warnings: an unknown/paused receiver or a delivery
		// error here used to vanish silently, so an operator's notify/ticket rule could
		// no-op with no trace. Surface them.
		for _, d := range eng.Dispatch(ctx, &ev) {
			for _, warn := range d.Warnings {
				slog.Default().Warn("response: rule action warning",
					slog.String("rule_id", d.RuleID),
					slog.String("org_id", orgID.String()),
					slog.String("warning", warn))
			}
		}
	}
}

// ResponseRuleDecision is the side-effect-free v2 response-rule result used by ingest
// handlers before they write a security-event row. SuppressLog means at least one matching
// rule contains suppress-log; explicit rule actions are still dispatched later by
// NewResponseDispatch so suppression does not turn quarantine/webhook/ticket into no-ops.
type ResponseRuleDecision struct {
	Matches     []response.MatchedRule
	SuppressLog bool
}

// NewResponseDecision builds a side-effect-free v2 response-rule evaluator. It intentionally
// shares loadResponseRulesV2 with NewResponseDispatch so the same ordered, cluster-scoped
// rules drive both "should this log be suppressed?" and the actual post-commit actions.
func NewResponseDecision(database *db.DB) func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event) ResponseRuleDecision {
	return func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event) ResponseRuleDecision {
		if database == nil {
			return ResponseRuleDecision{}
		}
		rules, err := loadResponseRulesV2(ctx, database, orgID, clusterID)
		if err != nil || len(rules) == 0 {
			if err != nil {
				slog.Default().Warn("response: evaluate rules for suppress-log",
					slog.String("org_id", orgID.String()),
					slog.String("err", err.Error()))
			}
			return ResponseRuleDecision{}
		}
		ev = annotateResponseRuleGroups(ctx, database, orgID, clusterID, ev, rules)
		eng := response.NewEngine(nil, nil, nil)
		eng.SetRules(rules)
		matches := eng.MatchRules(&ev)
		return ResponseRuleDecision{Matches: matches, SuppressLog: response.SuppressesLog(matches)}
	}
}

func annotateResponseRuleGroups(ctx context.Context, database *db.DB, orgID, clusterID uuid.UUID, ev response.Event, rules []response.Rule) response.Event {
	if database == nil || !rulesNeedGroups(rules) {
		return ev
	}
	selectors := responseRuleGroupSelectors(rules)
	if len(selectors) == 0 {
		return ev
	}
	candidates := responseEventWorkloadCandidates(ev)
	if len(candidates) == 0 {
		return ev
	}
	if expanded, err := expandResponseEventWorkloadCandidates(ctx, database, orgID, clusterID, candidates); err == nil {
		for candidate := range expanded {
			candidates[candidate] = struct{}{}
		}
	} else {
		slog.Default().Warn("response: expand workload candidates for group selector",
			slog.String("org_id", orgID.String()),
			slog.String("cluster_id", clusterID.String()),
			slog.String("err", err.Error()))
	}
	matched, err := responseRuleMatchingGroups(ctx, database, orgID, clusterID, selectors, candidates)
	if err != nil {
		slog.Default().Warn("response: resolve group selector",
			slog.String("org_id", orgID.String()),
			slog.String("cluster_id", clusterID.String()),
			slog.String("err", err.Error()))
		return ev
	}
	if len(matched) == 0 {
		return ev
	}
	labels := cloneLabels(ev.Labels)
	ids := make([]string, 0, len(matched))
	names := make([]string, 0, len(matched))
	for _, group := range matched {
		ids = append(ids, group.id)
		names = append(names, group.name)
	}
	sort.Strings(ids)
	sort.Strings(names)
	labels["group_ids"] = strings.Join(ids, ",")
	labels["group_names"] = strings.Join(names, ",")
	labels["groups"] = labels["group_names"]
	if labels["group_id"] == "" && len(ids) > 0 {
		labels["group_id"] = ids[0]
	}
	if labels["group_name"] == "" && len(names) > 0 {
		labels["group_name"] = names[0]
	}
	if labels["group"] == "" && len(names) > 0 {
		labels["group"] = names[0]
	}
	ev.Labels = labels
	return ev
}

func rulesNeedGroups(rules []response.Rule) bool {
	for i := range rules {
		if strings.TrimSpace(rules[i].Selector.Group) != "" {
			return true
		}
	}
	return false
}

func responseRuleGroupSelectors(rules []response.Rule) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for i := range rules {
		group := strings.TrimSpace(rules[i].Selector.Group)
		if group == "" {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		out = append(out, group)
	}
	return out
}

func responseEventWorkloadCandidates(ev response.Event) map[string]struct{} {
	out := map[string]struct{}{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			out[value] = struct{}{}
		}
	}
	add(ev.Workload)
	for _, key := range []string{"workload_id", "pod_workload_id", "owner_workload_id", "deployment", "pod"} {
		add(ev.Labels[key])
	}
	pod := strings.TrimSpace(ev.Labels["pod"])
	if ev.Namespace != "" && pod != "" {
		add(ev.Namespace + "/pod/" + pod)
		add(ev.Namespace + "/" + pod)
	}
	if ns, rest, ok := splitNamespacedWorkload(ev.Workload); ok {
		if strings.HasPrefix(rest, "pod/") {
			add(ns + "/" + strings.TrimPrefix(rest, "pod/"))
		}
	}
	return out
}

func expandResponseEventWorkloadCandidates(ctx context.Context, database *db.DB, orgID, clusterID uuid.UUID, candidates map[string]struct{}) (map[string]struct{}, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	values := make([]string, 0, len(candidates))
	for candidate := range candidates {
		values = append(values, candidate)
	}
	rows, err := database.Pool().Query(ctx, `
SELECT DISTINCT owner_workload_id
  FROM pod_workload_links
 WHERE org_id = $1
   AND cluster_id = $2
   AND pod_workload_id = ANY($3::text[])
   AND owner_workload_id <> ''
UNION
SELECT DISTINCT namespace || '/' || COALESCE(NULLIF(deployment, ''), pod_name)
  FROM pod_ips
 WHERE org_id = $1
   AND cluster_id = $2
   AND (workload_id = ANY($3::text[]) OR namespace || '/pod/' || pod_name = ANY($3::text[]))`,
		orgID, clusterID, values)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var workloadID string
		if err := rows.Scan(&workloadID); err != nil {
			return nil, err
		}
		workloadID = strings.TrimSpace(workloadID)
		if workloadID != "" {
			out[workloadID] = struct{}{}
		}
	}
	return out, rows.Err()
}

type responseRuleGroupMatch struct {
	id   string
	name string
}

func responseRuleMatchingGroups(ctx context.Context, database *db.DB, orgID, clusterID uuid.UUID, selectors []string, candidates map[string]struct{}) ([]responseRuleGroupMatch, error) {
	rows, err := database.Pool().Query(ctx, `
SELECT id::text, name, COALESCE(members, '[]'::jsonb)
  FROM groups
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)
   AND (id::text = ANY($3::text[]) OR name = ANY($3::text[]))
 ORDER BY name`, orgID, clusterID, selectors)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []responseRuleGroupMatch{}
	for rows.Next() {
		var (
			id, name string
			raw      []byte
		)
		if err := rows.Scan(&id, &name, &raw); err != nil {
			return nil, err
		}
		var members []string
		if err := json.Unmarshal(raw, &members); err != nil {
			return nil, err
		}
		if groupMembersContain(members, candidates) {
			out = append(out, responseRuleGroupMatch{id: id, name: name})
		}
	}
	return out, rows.Err()
}

func groupMembersContain(members []string, candidates map[string]struct{}) bool {
	for _, member := range members {
		member = strings.TrimSpace(member)
		if member == "" {
			continue
		}
		if _, ok := candidates[member]; ok {
			return true
		}
	}
	return false
}

func cloneLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+6)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func splitNamespacedWorkload(value string) (namespace, name string, ok bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", false
	}
	parts := strings.SplitN(value, "/", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// buildReceiverMap returns the engine's name/id -> notify.Receiver map for the org, but only
// when (a) a dispatcher is wired and (b) at least one rule actually carries a notify/ticket
// action — so the common quarantine/isolate-only path does no extra query. Each entry is an
// adapter that re-enters the dispatcher's tracked delivery path for the named receiver.
func buildReceiverMap(ctx context.Context, database *db.DB, dispatcher *notify.Dispatcher, orgID uuid.UUID, rules []response.Rule) map[string]notify.Receiver {
	if dispatcher == nil {
		return nil
	}
	if !rulesNeedReceivers(rules) {
		return nil
	}
	rows, err := database.Pool().Query(ctx,
		`SELECT id, name FROM receivers WHERE org_id = $1 AND COALESCE(paused,false) = false`, orgID)
	if err != nil {
		slog.Default().Warn("response: load receivers for notify actions", slog.String("err", err.Error()))
		return nil
	}
	defer rows.Close()
	out := map[string]notify.Receiver{}
	for rows.Next() {
		var (
			id   uuid.UUID
			name string
		)
		if err := rows.Scan(&id, &name); err != nil {
			continue
		}
		recv := &dispatchReceiver{dispatcher: dispatcher, receiverID: id, orgID: orgID, name: name}
		// Rules may target a receiver by name (the documented form) or by id; key both.
		if name != "" {
			out[name] = recv
		}
		out[id.String()] = recv
	}
	return out
}

// rulesNeedReceivers reports whether any enabled rule has a notify or ticket action.
func rulesNeedReceivers(rules []response.Rule) bool {
	for i := range rules {
		for _, a := range rules[i].Actions {
			if a.Kind == response.ActionNotify || a.Kind == response.ActionTicket || a.Kind == response.ActionWebhook {
				return true
			}
		}
	}
	return false
}

// dispatchReceiver adapts a persisted receiver to the response.Engine's notify.Receiver
// interface by re-entering the notify.Dispatcher for that specific receiver. This reuses the
// full tracked delivery path (delivery row, HMAC, retries, SSRF-hardened client) instead of
// POSTing from the engine with a stock client.
type dispatchReceiver struct {
	dispatcher *notify.Dispatcher
	receiverID uuid.UUID
	orgID      uuid.UUID
	name       string
}

func (d *dispatchReceiver) Name() string { return d.name }

func (d *dispatchReceiver) Send(ctx context.Context, alerts []notify.Alert) error {
	for _, a := range alerts {
		kind := a.Kind
		if kind == "" {
			kind = "response.notify"
		}
		ev := notify.Event{
			Kind: kind, OrgID: d.orgID, Severity: a.Severity, Title: a.Title,
			Cluster: a.Cluster, Workload: a.Workload, URL: a.URL, Labels: a.Labels,
			FiredAt: a.FiredAt,
		}
		if _, err := d.dispatcher.DispatchTo(ctx, d.receiverID, ev); err != nil {
			return err
		}
	}
	return nil
}

// loadResponseRulesV2 reads the enabled response rules for an org, scoped to the given
// cluster (cluster-agnostic rules — cluster_id IS NULL — always apply). Mirrors the SELECT
// shape ResponseRulesV2.List uses so the same persisted rows drive both the UI and runtime.
func loadResponseRulesV2(ctx context.Context, database *db.DB, orgID, clusterID uuid.UUID) ([]response.Rule, error) {
	rows, err := database.Pool().Query(ctx, `
SELECT id, name, enabled, event_type, conditions, actions, workload_match
  FROM response_rules_v2
 WHERE org_id = $1
   AND enabled
   AND (cluster_id IS NULL OR cluster_id = $2)
 ORDER BY priority, name`, orgID, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []response.Rule
	for rows.Next() {
		var (
			r                        response.Rule
			conditions, actions, sel []byte
		)
		if err := rows.Scan(&r.ID, &r.Name, &r.Enabled, &r.EventType, &conditions, &actions, &sel); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(conditions, &r.Conditions)
		_ = json.Unmarshal(actions, &r.Actions)
		_ = json.Unmarshal(sel, &r.Selector)
		out = append(out, r)
	}
	return out, rows.Err()
}
