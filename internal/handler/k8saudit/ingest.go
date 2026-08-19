package k8saudit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/notify"
	"github.com/alphabravocompany/constellation/pkg/response"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// Ingest serves the apiserver audit-webhook receiver and the console read path.
// Auth is dispatched at the router level (runtime-agent / cluster token on the
// ingest route, user JWT on the list route), so the same struct sits behind two
// middleware chains — mirroring runtime.RuntimeThreats.
type Ingest struct {
	db *db.DB

	// High-signal alerting fan-out. All optional/injected, mirroring the
	// runtime EventsIngest / RuntimeThreats fan-out (audit + notify + response
	// engines). When a hook is nil that leg is skipped; a bare NewIngest still
	// only persists rows. See WithAlerting / With* below.
	audit             *audit.Logger
	dispatcher        *notify.Dispatcher
	respond           func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event)
	evalResponseRules func(ctx context.Context, orgID uuid.UUID, ev *responserule.Event) ([]responserule.Action, error)

	// dedup collapses repeated identical high-signal events into one alert per
	// window. Always non-nil (set by the constructor).
	dedup *auditDedup
}

// NewIngest constructs the handler. By default it only persists rows; wire the
// fan-out with WithAlerting (or the individual With* setters) to light up
// high-signal control-plane alerting.
func NewIngest(d *db.DB) *Ingest {
	return &Ingest{db: d, dedup: newAuditDedup(dedupWindowFromEnv())}
}

// WithAudit attaches the audit logger so high-signal events append a
// k8s.audit.<signal> audit row. Returns the receiver for chaining.
func (h *Ingest) WithAudit(a *audit.Logger) *Ingest { h.audit = a; return h }

// WithDispatcher attaches the notify Dispatcher. Returns the receiver.
func (h *Ingest) WithDispatcher(d *notify.Dispatcher) *Ingest { h.dispatcher = d; return h }

// WithResponseEngine attaches the RT-2 response/quarantine dispatch hook.
func (h *Ingest) WithResponseEngine(respond func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event)) *Ingest {
	h.respond = respond
	return h
}

// WithResponseRuleEngine attaches the E1 declarative response-rule evaluator.
func (h *Ingest) WithResponseRuleEngine(eval func(ctx context.Context, orgID uuid.UUID, ev *responserule.Event) ([]responserule.Action, error)) *Ingest {
	h.evalResponseRules = eval
	return h
}

// WithAlerting wires the whole fan-out in one call, matching the runtime-ingest
// wiring the server uses.
func (h *Ingest) WithAlerting(
	a *audit.Logger,
	d *notify.Dispatcher,
	respond func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event),
	eval func(ctx context.Context, orgID uuid.UUID, ev *responserule.Event) ([]responserule.Action, error),
) *Ingest {
	return h.WithAudit(a).WithDispatcher(d).WithResponseEngine(respond).WithResponseRuleEngine(eval)
}

// maxAuditBatchSize caps items per webhook POST. The apiserver batches with
// --audit-webhook-batch-max-size (default 400); 1000 is generous headroom.
const maxAuditBatchSize = 1000

// IngestResponse summarizes a bulk POST.
type IngestResponse struct {
	Accepted int `json:"accepted"`
	Alerts   int `json:"alerts,omitempty"`
}

// pendingAlert carries a persisted high-signal row to the post-commit fan-out.
type pendingAlert struct {
	ev        *AuditEvent
	signal    string
	severity  string
	decision  string
	sourceIP  string
	clusterID uuid.UUID
}

// Bulk is the Kubernetes audit-webhook receiver. The apiserver POSTs batches of
// audit.k8s.io/v1 Events here (kind: EventList). Auth is the runtime-agent /
// cluster token — the same credential the DaemonSet agent uses for the other
// ingest routes — supplied to the apiserver as the webhook kubeconfig's bearer
// token. cluster_id is resolved best-effort against the token's org.
//
// TODO(matrix): apiserver audit-webhook config required to feed this endpoint
// (documented here rather than in a separate doc so it travels with the code):
//
//  1. Audit policy (--audit-policy-file), capturing at least Metadata level for
//     the high-signal resources — and RequestResponse for pods create/update so
//     privileged_create can be classified from the captured spec:
//
//     apiVersion: audit.k8s.io/v1
//     kind: Policy
//     rules:
//     - level: RequestResponse
//     verbs: ["create","update","patch"]
//     resources: [{group: "", resources: ["pods"]}]
//     - level: Metadata
//     resources:
//     - {group: "", resources: ["pods/exec","pods/attach"]}
//     - {group: "", resources: ["secrets"]}
//     - {group: "rbac.authorization.k8s.io", resources: ["*"]}
//     - level: None   # drop the rest to keep volume sane
//
//  2. Webhook backend kubeconfig (--audit-webhook-config-file) whose cluster
//     server is https://<constellation>/api/v1/k8s-audit:bulk and whose user
//     carries `token: <runtime-agent-token>`; set
//     --audit-webhook-batch-max-size / --audit-webhook-mode=batch.
//
// Managed control planes (EKS/GKE/AKS) that don't expose these flags can instead
// stream their audit log to this endpoint via a small forwarder — a future
// collector variant. A watch-based approximation (watching RBAC objects + the
// events API) is possible but needs cluster-privileged read and misses exec /
// secret reads, so the webhook receiver is preferred.
func (h *Ingest) Bulk(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "cluster token required"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20) // 16 MiB — audit events can carry request objects

	items, err := decodeAuditItems(r.Body)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body: " + err.Error()})
		return
	}
	if len(items) == 0 {
		httpx.WriteJSON(w, http.StatusOK, IngestResponse{})
		return
	}
	if len(items) > maxAuditBatchSize {
		httpx.WriteJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": fmt.Sprintf("batch > %d", maxAuditBatchSize)})
		return
	}

	// Resolve the org's primary cluster as the attribution fallback — same
	// heuristic the runtime-threats ingest uses (the token knows only the org).
	var cluster uuid.UUID
	_ = h.db.Pool().QueryRow(r.Context(),
		`SELECT id FROM clusters WHERE org_id = $1
		 ORDER BY CASE WHEN state = 'connected' THEN 0 ELSE 1 END,
		          last_heartbeat_at DESC NULLS LAST, created_at ASC
		 LIMIT 1`, tok.OrgID).
		Scan(&cluster)
	if cluster == uuid.Nil {
		httpx.WriteJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "no cluster for org"})
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	const insertSQL = `
INSERT INTO k8s_audit_events
  (org_id, cluster_id, verb, resource, subresource, api_group, namespace, name,
   "user", source_ip, decision, signal, severity, audit_id, raw, reported_at, at)
VALUES ($1,$2, NULLIF($3,''), NULLIF($4,''), NULLIF($5,''), NULLIF($6,''), NULLIF($7,''), NULLIF($8,''),
        NULLIF($9,''), NULLIF($10,''), NULLIF($11,''), NULLIF($12,''), $13, NULLIF($14,''), $15,
        $16, $17)`

	accepted := 0
	pending := make([]pendingAlert, 0, 8)
	for i := range items {
		var ev AuditEvent
		if err := json.Unmarshal(items[i], &ev); err != nil {
			// Skip a malformed item rather than 500 the whole batch — the
			// apiserver won't retry a 200, and one bad event shouldn't lose the
			// rest of the batch.
			continue
		}
		// The apiserver emits an event per stage; ResponseComplete/Panic is the
		// terminal one. Ignore the intermediate ResponseStarted duplicate.
		if strings.EqualFold(ev.Stage, "ResponseStarted") || strings.EqualFold(ev.Stage, "RequestReceived") {
			continue
		}
		reported := ev.RequestReceivedTimestamp
		if reported.IsZero() {
			reported = time.Now().UTC()
		}
		signal, severity, highSignal := classify(&ev)
		decision := ev.decision()
		sourceIP := ev.sourceIP()

		if _, err := tx.Exec(r.Context(), insertSQL,
			tok.OrgID, cluster,
			strings.TrimSpace(ev.Verb),
			strings.TrimSpace(ev.ObjectRef.Resource),
			strings.TrimSpace(ev.ObjectRef.Subresource),
			strings.TrimSpace(ev.ObjectRef.APIGroup),
			strings.TrimSpace(ev.ObjectRef.Namespace),
			strings.TrimSpace(ev.ObjectRef.Name),
			strings.TrimSpace(ev.User.Username),
			sourceIP,
			decision,
			signal,
			severity,
			strings.TrimSpace(ev.AuditID),
			[]byte(items[i]), // raw jsonb — full event verbatim
			reported.UTC(),
			time.Now().UTC(),
		); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "insert: " + err.Error()})
			return
		}
		accepted++
		if highSignal {
			evCopy := ev
			pending = append(pending, pendingAlert{
				ev:        &evCopy,
				signal:    signal,
				severity:  severity,
				decision:  decision,
				sourceIP:  sourceIP,
				clusterID: cluster,
			})
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "commit: " + err.Error()})
		return
	}

	// Fan out high-signal events post-commit — deduped, best-effort, never
	// affecting the 200 the apiserver already earned.
	alerts := h.fanOut(r.Context(), tok.OrgID, pending)

	slog.Default().Debug("k8s_audit ingest",
		slog.Int("accepted", accepted), slog.Int("alerts", alerts),
		slog.String("org", tok.OrgID.String()))
	httpx.WriteJSON(w, http.StatusOK, IngestResponse{Accepted: accepted, Alerts: alerts})
}

// decodeAuditItems accepts either the apiserver's EventList envelope
// ({"kind":"EventList","items":[...]}) or a bare array of events, returning the
// per-item raw JSON (preserved verbatim for the raw column).
func decodeAuditItems(body io.Reader) ([]json.RawMessage, error) {
	dec := json.NewDecoder(body)
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, err
		}
		return items, nil
	}
	var list EventList
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(list.Items, &items); err != nil {
		return nil, err
	}
	return items, nil
}

// --- fan-out ---------------------------------------------------------------

// fanOut runs alerting for the high-signal events in a batch and returns the
// number that actually alerted (post-dedup). Best-effort / panic-isolated.
func (h *Ingest) fanOut(ctx context.Context, orgID uuid.UUID, pending []pendingAlert) int {
	if h.audit == nil && h.dispatcher == nil && h.respond == nil && h.evalResponseRules == nil {
		return 0
	}
	alerts := 0
	for i := range pending {
		p := &pending[i]
		if !h.dedup.allow(dedupKey(orgID, p)) {
			continue
		}
		if h.fanOutOne(ctx, orgID, p) {
			alerts++
		}
	}
	return alerts
}

// fanOutOne emits the audit + notify + response legs for a single deduped
// high-signal event. Panic-isolated. Returns true if it alerted (i.e. not
// suppressed by an E1 suppress_log rule).
func (h *Ingest) fanOutOne(ctx context.Context, orgID uuid.UUID, p *pendingAlert) (alerted bool) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Default().Error("k8s audit fan-out panic", slog.Any("recover", rec))
		}
	}()

	action := "k8s.audit." + p.signal
	title := auditAlertTitle(p)
	labels := map[string]string{
		"severity":  p.severity,
		"signal":    p.signal,
		"verb":      strings.TrimSpace(p.ev.Verb),
		"resource":  strings.TrimSpace(p.ev.ObjectRef.Resource),
		"namespace": strings.TrimSpace(p.ev.ObjectRef.Namespace),
		"user":      strings.TrimSpace(p.ev.User.Username),
		"decision":  p.decision,
	}
	after := map[string]any{
		"signal":      p.signal,
		"severity":    p.severity,
		"verb":        strings.TrimSpace(p.ev.Verb),
		"resource":    strings.TrimSpace(p.ev.ObjectRef.Resource),
		"subresource": strings.TrimSpace(p.ev.ObjectRef.Subresource),
		"api_group":   strings.TrimSpace(p.ev.ObjectRef.APIGroup),
		"namespace":   strings.TrimSpace(p.ev.ObjectRef.Namespace),
		"name":        strings.TrimSpace(p.ev.ObjectRef.Name),
		"user":        strings.TrimSpace(p.ev.User.Username),
		"source_ip":   p.sourceIP,
		"decision":    p.decision,
		"audit_id":    strings.TrimSpace(p.ev.AuditID),
	}

	// E1 declarative response rules first, so a suppress_log action can gate the
	// audit/notify legs, exactly as the runtime paths do.
	var ruleActions []responserule.Action
	if h.evalResponseRules != nil {
		ruleActions = h.evalRulesSafe(ctx, orgID, p)
	}
	suppressed := false
	for _, a := range ruleActions {
		if a.Type == responserule.ActionSuppressLog {
			suppressed = true
			break
		}
	}

	if !suppressed {
		if h.audit != nil {
			oid := orgID
			_, _, _ = h.audit.Log(ctx, audit.Event{
				OrgID:      &oid,
				Action:     action,
				TargetKind: "k8s_audit",
				TargetID:   strings.TrimSpace(p.ev.AuditID),
				After:      after,
				At:         p.ev.RequestReceivedTimestamp,
			})
		}
		if h.dispatcher != nil {
			_, _ = h.dispatcher.Dispatch(ctx, notify.Event{
				Kind:     action,
				OrgID:    orgID,
				Severity: p.severity,
				Title:    title,
				Cluster:  p.clusterID.String(),
				Labels:   labels,
				Payload:  after,
				URL:      "/k8s-audit",
				FiredAt:  p.ev.RequestReceivedTimestamp,
			})
		}
		alerted = true
	}

	// RT-2 response engine (response_rules_v2). Seeded rules are MONITOR-mode.
	if h.respond != nil {
		h.respond(ctx, orgID, p.clusterID, response.Event{
			ID:        uuid.NewString(),
			Name:      p.signal,
			Type:      response.EventAdmission, // control-plane / admission-adjacent
			Severity:  p.severity,
			Cluster:   p.clusterID.String(),
			Namespace: strings.TrimSpace(p.ev.ObjectRef.Namespace),
			Workload:  auditWorkload(p),
			Title:     title,
			URL:       "/k8s-audit",
		})
	}
	return alerted
}

// evalRulesSafe folds a high-signal audit event down to a responserule.Event
// (admission type) and evaluates the org's enabled E1 rules. Webhook delivery
// happens inside the injected evaluator. Panic-isolated / best-effort.
func (h *Ingest) evalRulesSafe(ctx context.Context, orgID uuid.UUID, p *pendingAlert) (actions []responserule.Action) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Default().Error("k8s audit response-rule panic", slog.Any("recover", rec))
			actions = nil
		}
	}()
	rev := &responserule.Event{
		Type: responserule.EventAdmission,
		Fields: map[string]string{
			"kind":        "k8s_audit",
			"signal":      p.signal,
			"severity":    p.severity,
			"verb":        strings.ToLower(strings.TrimSpace(p.ev.Verb)),
			"resource":    strings.ToLower(strings.TrimSpace(p.ev.ObjectRef.Resource)),
			"subresource": strings.ToLower(strings.TrimSpace(p.ev.ObjectRef.Subresource)),
			"api_group":   strings.ToLower(strings.TrimSpace(p.ev.ObjectRef.APIGroup)),
			"namespace":   strings.TrimSpace(p.ev.ObjectRef.Namespace),
			"name":        strings.TrimSpace(p.ev.ObjectRef.Name),
			"user":        strings.TrimSpace(p.ev.User.Username),
			"source_ip":   p.sourceIP,
			"decision":    p.decision,
		},
	}
	got, err := h.evalResponseRules(ctx, orgID, rev)
	if err != nil {
		slog.Default().Warn("k8s audit response-rule evaluate", slog.Any("err", err))
		return nil
	}
	// TODO(matrix): enforce quarantine/tag actions here (mirroring the runtime
	// threats path's applyThreatResponseRuleActions). Control-plane audit is
	// out-of-band so there is no live request to block; the useful enforcement
	// is quarantining the *subject workload* that just exec'd, which needs the
	// pod->workload resolver. Until then we honor suppress_log + webhook (fired
	// inside the evaluator) and leave the rest observe-only.
	return got
}

// auditAlertTitle renders a one-line subject for the alert.
func auditAlertTitle(p *pendingAlert) string {
	obj := strings.TrimSpace(p.ev.ObjectRef.Resource)
	if sub := strings.TrimSpace(p.ev.ObjectRef.Subresource); sub != "" {
		obj += "/" + sub
	}
	target := strings.TrimSpace(p.ev.ObjectRef.Name)
	if ns := strings.TrimSpace(p.ev.ObjectRef.Namespace); ns != "" && target != "" {
		target = ns + "/" + target
	} else if ns != "" {
		target = ns
	}
	user := strings.TrimSpace(p.ev.User.Username)
	if user == "" {
		user = "?"
	}
	verdict := ""
	if p.decision == "forbid" {
		verdict = " (denied)"
	}
	return fmt.Sprintf("%s: %s %s %s%s", strings.ToUpper(p.signal), user, strings.TrimSpace(p.ev.Verb), strings.TrimSpace(obj+" "+target), verdict)
}

// auditWorkload derives a "namespace/pod" key when the object is a pod, for the
// response engine's workload matching. Empty for non-pod objects.
func auditWorkload(p *pendingAlert) string {
	if strings.EqualFold(strings.TrimSpace(p.ev.ObjectRef.Resource), "pods") {
		ns := strings.TrimSpace(p.ev.ObjectRef.Namespace)
		name := strings.TrimSpace(p.ev.ObjectRef.Name)
		if ns != "" && name != "" {
			return ns + "/" + name
		}
	}
	return ""
}

// --- dedup -----------------------------------------------------------------

const defaultDedupWindowS = 60
const dedupMaxKeys = 8192

func dedupWindowFromEnv() time.Duration {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("CONSTELLATION_K8S_AUDIT_DEDUP_WINDOW_S"))); err == nil && v >= 0 {
		return time.Duration(v) * time.Second
	}
	return defaultDedupWindowS * time.Second
}

// auditDedup collapses repeated identical high-signal events into one alert per
// window. Safe for concurrent use. window<=0 disables dedup. Mirrors
// runtime.threatDedup.
type auditDedup struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[string]time.Time
	now    func() time.Time
}

func newAuditDedup(window time.Duration) *auditDedup {
	return &auditDedup{window: window, seen: make(map[string]time.Time), now: time.Now}
}

func (d *auditDedup) allow(key string) bool {
	if d == nil || d.window <= 0 {
		return true
	}
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if last, ok := d.seen[key]; ok && now.Sub(last) < d.window {
		return false
	}
	d.seen[key] = now
	if len(d.seen) > dedupMaxKeys {
		for k, t := range d.seen {
			if now.Sub(t) >= d.window {
				delete(d.seen, k)
			}
		}
	}
	return true
}

// dedupKey is the collapse identity: org + who + what + which object. The same
// (user, verb, resource/subresource, namespace, name) within the window is one
// alert — so a controller hot-looping a secret list pages once, not thousands.
func dedupKey(orgID uuid.UUID, p *pendingAlert) string {
	return strings.Join([]string{
		orgID.String(),
		p.signal,
		strings.ToLower(strings.TrimSpace(p.ev.User.Username)),
		strings.ToLower(strings.TrimSpace(p.ev.Verb)),
		strings.ToLower(strings.TrimSpace(p.ev.ObjectRef.Resource)),
		strings.ToLower(strings.TrimSpace(p.ev.ObjectRef.Subresource)),
		strings.ToLower(strings.TrimSpace(p.ev.ObjectRef.Namespace)),
		strings.ToLower(strings.TrimSpace(p.ev.ObjectRef.Name)),
	}, "|")
}
