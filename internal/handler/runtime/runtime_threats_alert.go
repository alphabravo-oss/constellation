// P0-5: real-time alerting + response on DPI network threats.
//
// RuntimeThreats.Bulk() persists one row per DPMsgThreatLog the runtime-agent
// decoded (SYN floods, SQL injection, Heartbleed, ...). Persisting alone makes
// a live attack invisible until an operator polls GET /runtime-threats. This
// file mirrors the eBPF EVENTS ingest fan-out (internal/handler/runtime/
// events_ingest.go): for each persisted threat at/above a severity threshold we
//
//   - write a `runtime.alert.dpi` audit event (pkg/audit),
//   - dispatch a notification through the notify Dispatcher (pkg/notify), and
//   - evaluate the org's response rules — both the RT-2 response engine
//     (response_rules_v2, via the injected respond hook) and the E1 declarative
//     evaluator (response_rules, via evalResponseRules), reusing the same
//     helpers/quarantine bridge the events path uses.
//
// Flood dedup: a real SYN flood emits thousands of identical threat logs a
// second. We collapse repeats of the same (org, threat_id, src, dst, port)
// tuple within a short window down to ONE alert, in-memory, so the operator
// gets a single "SYN flood from X" alert rather than a pager storm. The first
// hit in a window fires; identical hits within the window are suppressed; once
// the window elapses the next hit re-fires so an ongoing flood keeps surfacing.
//
// SAFETY: this path is observe-first. The notify/audit legs are pure
// observation. The response-rule legs reuse the existing engines, whose seeded
// rules ship in MONITOR mode and whose enforcing actions (quarantine/isolate)
// are operator-authored opt-in — nothing here blocks a live workload by default.
package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/notify"
	"github.com/alphabravocompany/constellation/pkg/response"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// pendingThreatAlert carries a persisted threat row plus the cluster/workload
// attribution the insert resolved, to the post-commit fan-out.
type pendingThreatAlert struct {
	row        *ThreatIngestRow
	clusterID  uuid.UUID
	workloadID string
	namespace  string
	podName    string
	v2Decision ResponseRuleDecision
}

// --- configuration (env, safe defaults, evaluated once at init) ------------

// Default alert severity threshold: NeuVector THRT_SEVERITY_HIGH (4). Threats
// below this (info/low/medium — e.g. the noisy protocol-anomaly signatures)
// still get persisted and listed, they just don't page anyone. Override with
// CONSTELLATION_THREAT_ALERT_SEVERITY_MIN (1..5, NeuVector scale).
const defaultThreatAlertSeverityMin = 4 // THRT_SEVERITY_HIGH

// Default flood-dedup window. One alert per identical (threat_id,src,dst,port)
// tuple per minute. Override with CONSTELLATION_THREAT_ALERT_DEDUP_WINDOW_S.
const defaultThreatDedupWindowS = 60

// threatDedupMaxKeys bounds the in-memory dedup map; on overflow we sweep
// expired entries. A flood is few tuples, so this is generous headroom.
const threatDedupMaxKeys = 8192

var (
	threatAlertSeverityMin = threatAlertSeverityMinFromEnv()
	threatDedupWindow      = threatDedupWindowFromEnv()
)

func threatAlertSeverityMinFromEnv() uint8 {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("CONSTELLATION_THREAT_ALERT_SEVERITY_MIN"))); err == nil && v >= 1 && v <= 5 {
		return uint8(v)
	}
	return defaultThreatAlertSeverityMin
}

func threatDedupWindowFromEnv() time.Duration {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("CONSTELLATION_THREAT_ALERT_DEDUP_WINDOW_S"))); err == nil && v >= 0 {
		return time.Duration(v) * time.Second
	}
	return defaultThreatDedupWindowS * time.Second
}

// --- fluent wiring (mirrors EventsIngest.With*) ----------------------------

// WithAudit attaches the audit logger so alerted threats append a
// runtime.alert.dpi audit row. Returns the receiver for chaining.
func (h *RuntimeThreats) WithAudit(a *audit.Logger) *RuntimeThreats { h.audit = a; return h }

// WithDispatcher attaches the notify Dispatcher so alerted threats fan out to
// configured receivers. Returns the receiver for chaining.
func (h *RuntimeThreats) WithDispatcher(d *notify.Dispatcher) *RuntimeThreats {
	h.dispatcher = d
	return h
}

// WithResponseEngine attaches the RT-2 response/quarantine dispatch hook (the
// same closure NewResponseDispatch builds for the events path). Returns the
// receiver for chaining.
func (h *RuntimeThreats) WithResponseEngine(respond func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event)) *RuntimeThreats {
	h.respond = respond
	return h
}

// WithResponseDecision attaches the side-effect-free v2 response-rule evaluator used for
// pre-insert suppress-log decisions. Returns the receiver for chaining.
func (h *RuntimeThreats) WithResponseDecision(decide func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event) ResponseRuleDecision) *RuntimeThreats {
	h.decideResponseRules = decide
	return h
}

// WithResponseRuleEngine attaches the E1 declarative response-rule evaluator
// (pkg/responserule). Returns the receiver for chaining.
func (h *RuntimeThreats) WithResponseRuleEngine(eval func(ctx context.Context, orgID uuid.UUID, ev *responserule.Event) ([]responserule.Action, error)) *RuntimeThreats {
	h.evalResponseRules = eval
	return h
}

// WithAlerting is the convenience the server uses to wire the whole fan-out in
// one call, matching the events path wiring.
func (h *RuntimeThreats) WithAlerting(
	a *audit.Logger,
	d *notify.Dispatcher,
	respond func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event),
	eval func(ctx context.Context, orgID uuid.UUID, ev *responserule.Event) ([]responserule.Action, error),
) *RuntimeThreats {
	return h.WithAudit(a).WithDispatcher(d).WithResponseEngine(respond).WithResponseRuleEngine(eval)
}

// --- flood dedup -----------------------------------------------------------

// threatDedup collapses repeated identical threats into one alert per window.
// Safe for concurrent use. window<=0 disables dedup (every hit alerts).
type threatDedup struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[string]time.Time // dedup key -> time the current window was armed
	now    func() time.Time     // test seam
}

func newThreatDedup(window time.Duration) *threatDedup {
	return &threatDedup{window: window, seen: make(map[string]time.Time), now: time.Now}
}

// allow reports whether an alert for key should fire now. The first hit in a
// window fires (true) and arms the window; identical hits within the window are
// suppressed (false). Once the window elapses the next hit re-fires and re-arms
// — so a sustained flood surfaces once per window instead of once per packet.
func (d *threatDedup) allow(key string) bool {
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
	if len(d.seen) > threatDedupMaxKeys {
		d.pruneLocked(now)
	}
	return true
}

// pruneLocked drops entries whose window has fully elapsed. Caller holds mu.
func (d *threatDedup) pruneLocked(now time.Time) {
	for k, t := range d.seen {
		if now.Sub(t) >= d.window {
			delete(d.seen, k)
		}
	}
}

// threatDedupKey is the flood-collapse identity: org + threat signature +
// src/dst + dst port. Same tuple within the window => one alert.
func threatDedupKey(orgID uuid.UUID, row *ThreatIngestRow) string {
	return strings.Join([]string{
		orgID.String(),
		strconv.FormatUint(uint64(row.ThreatID), 10),
		strings.ToLower(strings.TrimSpace(row.SrcIP)),
		strings.ToLower(strings.TrimSpace(row.DstIP)),
		strconv.Itoa(row.DstPort),
	}, "|")
}

// --- fan-out ---------------------------------------------------------------

// fanOutThreats runs the P0-5 alerting for a batch of persisted threats and
// returns the number that actually alerted (post threshold + dedup). It is
// best-effort and panic-isolated: a broken receiver/rule can never take down
// the ingest goroutine or affect the 200 the agent already earned.
func (h *RuntimeThreats) fanOutThreats(ctx context.Context, orgID uuid.UUID, pending []pendingThreatAlert) int {
	// Nothing to do if no fan-out legs are wired (bare NewRuntimeThreats).
	if h.audit == nil && h.dispatcher == nil && h.respond == nil && h.evalResponseRules == nil {
		return 0
	}
	alerts := 0
	for i := range pending {
		p := &pending[i]
		if p.row.Severity < threatAlertSeverityMin {
			continue
		}
		if !h.dedup.allow(threatDedupKey(orgID, p.row)) {
			continue
		}
		if h.fanOutOneThreat(ctx, orgID, p) {
			alerts++
		}
	}
	return alerts
}

// fanOutOneThreat emits the audit + notify + response legs for a single
// deduped, at-threshold threat. Panic-isolated. Returns true if it alerted
// (i.e. was not suppressed by an E1 suppress_log rule).
func (h *RuntimeThreats) fanOutOneThreat(ctx context.Context, orgID uuid.UUID, p *pendingThreatAlert) (alerted bool) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Default().Error("runtime threat fan-out panic", slog.Any("recover", rec))
		}
	}()

	row := p.row
	sev := threatSeverityLabel(row.Severity)
	name := handler.NeuVectorThreatName(row.ThreatID)
	category := threatCategory(int32(row.ThreatID))
	action := "runtime.alert.dpi"

	// E1 declarative response rules first, so a suppress_log action can gate
	// the audit/notify legs (the very log/alert it is meant to suppress),
	// exactly as the events path does. Webhook actions fire inside the
	// evaluator; the returned actions are enforced below.
	var ruleActions []responserule.Action
	if h.evalResponseRules != nil {
		ruleActions = h.evalThreatRulesSafe(ctx, orgID, p, sev, name, category)
	}
	suppressed := responseRulesSuppressLog(ruleActions) || p.v2Decision.SuppressLog

	if !suppressed {
		title := fmt.Sprintf("%s (%s) %s -> %s", name, sev, srcHostPort(row.SrcIP, row.SrcPort), srcHostPort(row.DstIP, row.DstPort))
		labels := map[string]string{
			"severity":    sev,
			"category":    category,
			"threat_id":   strconv.FormatUint(uint64(row.ThreatID), 10),
			"threat_name": name,
			"namespace":   p.namespace,
			"node":        strings.TrimSpace(row.Node),
		}
		after := map[string]any{
			"threat_id":   row.ThreatID,
			"threat_name": name,
			"category":    category,
			"severity":    sev,
			"action":      row.Action,
			"node":        strings.TrimSpace(row.Node),
			"namespace":   p.namespace,
			"pod":         p.podName,
			"workload_id": p.workloadID,
			"src_ip":      strings.TrimSpace(row.SrcIP),
			"src_port":    row.SrcPort,
			"dst_ip":      strings.TrimSpace(row.DstIP),
			"dst_port":    row.DstPort,
			"msg":         strings.TrimSpace(row.Msg),
		}

		// Audit — outside any txn; an audit-chain error must not break ingest.
		if h.audit != nil {
			oid := orgID
			_, _, _ = h.audit.Log(ctx, audit.Event{
				OrgID:      &oid,
				Action:     action,
				TargetKind: "workload",
				TargetID:   p.workloadID,
				After:      after,
				At:         row.At,
			})
		}

		// Notify — fire-and-forget through the dispatcher.
		if h.dispatcher != nil {
			_, _ = h.dispatcher.Dispatch(ctx, notify.Event{
				Kind:     action,
				OrgID:    orgID,
				Severity: sev,
				Title:    title,
				Workload: p.workloadID,
				Cluster:  p.clusterID.String(),
				Labels:   labels,
				Payload:  after,
				URL:      "/runtime/threats",
				FiredAt:  row.At,
			})
		}
		alerted = true
	}
	if p.v2Decision.SuppressLog {
		h.auditThreatResponseV2SuppressLog(ctx, orgID, p)
	}

	// RT-2 response engine (response_rules_v2). Independent of E1 suppress_log,
	// mirroring the events path; seeded rules are MONITOR-mode.
	if h.respond != nil {
		h.respond(ctx, orgID, p.clusterID, responseEventForThreat(p, sev, name, action))
	}

	// E1: enforce the matched actions (quarantine/tag), priority-ordered.
	if h.evalResponseRules != nil && len(ruleActions) > 0 {
		h.applyThreatResponseRuleActions(ctx, orgID, p, ruleActions)
	}
	return alerted
}

func responseEventForThreat(p *pendingThreatAlert, sev, name, action string) response.Event {
	return response.Event{
		ID:        uuid.NewString(),
		Name:      name,
		Type:      response.EventThreat,
		Severity:  sev,
		Cluster:   p.clusterID.String(),
		Namespace: p.namespace,
		Workload:  p.workloadID,
		Labels: map[string]string{
			"event_kind":  "dpi_threat",
			"namespace":   p.namespace,
			"pod":         p.podName,
			"workload_id": p.workloadID,
			"threat_id":   fmt.Sprint(p.row.ThreatID),
		},
		Title: fmt.Sprintf("%s on %s/%s", action, p.namespace, p.podName),
		URL:   "/runtime/threats",
	}
}

func (h *RuntimeThreats) threatResponseDecisionSafe(ctx context.Context, orgID uuid.UUID, p *pendingThreatAlert) (decision ResponseRuleDecision) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Default().Error("runtime threat v2 decision panic", slog.Any("recover", rec))
			decision = ResponseRuleDecision{}
		}
	}()
	sev := threatSeverityLabel(p.row.Severity)
	name := handler.NeuVectorThreatName(p.row.ThreatID)
	return h.decideResponseRules(ctx, orgID, p.clusterID, responseEventForThreat(p, sev, name, "runtime.alert.dpi"))
}

func (h *RuntimeThreats) auditThreatResponseV2SuppressLog(ctx context.Context, orgID uuid.UUID, p *pendingThreatAlert) {
	if h.audit == nil || !p.v2Decision.SuppressLog {
		return
	}
	row := p.row
	for _, match := range p.v2Decision.Matches {
		for i, act := range match.Actions {
			if !response.IsSuppressLogAction(act.Kind) {
				continue
			}
			oid := orgID
			after := map[string]any{
				"action":      string(response.ActionSuppressLog),
				"order":       i,
				"rule_id":     match.RuleID,
				"rule_name":   match.RuleName,
				"event_kind":  "dpi_threat",
				"threat_id":   row.ThreatID,
				"threat_name": handler.NeuVectorThreatName(row.ThreatID),
				"namespace":   p.namespace,
				"pod":         p.podName,
				"workload_id": p.workloadID,
				"cluster_id":  p.clusterID.String(),
				"src_ip":      strings.TrimSpace(row.SrcIP),
				"src_port":    row.SrcPort,
				"dst_ip":      strings.TrimSpace(row.DstIP),
				"dst_port":    row.DstPort,
				"enforced":    "suppressed_log",
			}
			for k, v := range act.Params {
				after["param_"+k] = v
			}
			_, _, _ = h.audit.Log(ctx, audit.Event{
				OrgID:      &oid,
				Action:     "response_rule_v2.action.suppress_log",
				TargetKind: "workload",
				TargetID:   p.workloadID,
				After:      after,
				At:         row.At,
			})
		}
	}
}

// evalThreatRulesSafe folds a threat down to a responserule.Event (network
// type) and evaluates the org's enabled E1 rules, returning the ordered
// matching actions. Webhook delivery happens inside the injected evaluator.
// Panic-isolated/best-effort.
func (h *RuntimeThreats) evalThreatRulesSafe(ctx context.Context, orgID uuid.UUID, p *pendingThreatAlert, sev, name, category string) (actions []responserule.Action) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Default().Error("runtime threat response-rule panic", slog.Any("recover", rec))
			actions = nil
		}
	}()
	row := p.row
	direction := "egress"
	if row.SessIngress {
		direction = "ingress"
	}
	rev := &responserule.Event{
		Type: responserule.EventNetwork,
		Fields: map[string]string{
			"kind":         "dpi_threat",
			"severity":     sev,
			"threat_id":    strconv.FormatUint(uint64(row.ThreatID), 10),
			"threat_name":  name,
			"process_name": name, // best available process-ish label for rule matching
			"category":     category,
			"namespace":    p.namespace,
			"pod":          p.podName,
			"node":         strings.TrimSpace(row.Node),
			"workload_id":  p.workloadID,
			"protocol":     "tcp",
			"direction":    direction,
			"src":          strings.TrimSpace(row.SrcIP),
			"dst":          strings.TrimSpace(row.DstIP),
			"src_port":     strconv.Itoa(row.SrcPort),
			"dst_port":     strconv.Itoa(row.DstPort),
			"msg":          strings.TrimSpace(row.Msg),
		},
	}
	got, err := h.evalResponseRules(ctx, orgID, rev)
	if err != nil {
		slog.Default().Warn("runtime threat response-rule evaluate", slog.Any("err", err))
		return nil
	}
	return got
}

// applyThreatResponseRuleActions applies the ordered E1 actions, reusing the
// same quarantineRuntime bridge the events path uses. Each action is audited so
// the enforcement is observable. suppress_log was already honored (audit/notify
// skipped); webhooks fired inside the evaluator; quarantine/isolate/tag land
// here. Best-effort, mirrors EventsIngest.applyResponseRuleActions.
func (h *RuntimeThreats) applyThreatResponseRuleActions(ctx context.Context, orgID uuid.UUID, p *pendingThreatAlert, actions []responserule.Action) {
	for i := range actions {
		a := actions[i]
		oid := orgID
		after := map[string]any{
			"action":      string(a.Type),
			"order":       i,
			"event_kind":  "dpi_threat",
			"namespace":   p.namespace,
			"pod":         p.podName,
			"workload_id": p.workloadID,
		}
		for k, v := range a.Params {
			after["param_"+k] = v
		}
		switch a.Type {
		case responserule.ActionSuppressLog:
			after["enforced"] = "suppressed_log"
		case responserule.ActionTag:
			after["enforced"] = "tagged"
		case responserule.ActionWebhook:
			after["enforced"] = "webhook_dispatched"
		case responserule.ActionQuarantine:
			workload := threatWorkloadMatchKey(p)
			switch {
			case workload == "":
				after["enforced"] = "skipped_no_workload"
			case p.clusterID == uuid.Nil:
				after["enforced"] = "skipped_no_cluster"
			default:
				q := &quarantineRuntime{db: h.db, orgID: orgID, clusterID: p.clusterID}
				reason := "response_rule: dpi_threat " + handler.NeuVectorThreatName(p.row.ThreatID)
				isolate := strings.EqualFold(a.Params["isolate"], "true")
				var qerr error
				if isolate {
					qerr = q.Isolate(ctx, workload, reason)
				} else {
					qerr = q.Quarantine(ctx, workload, reason)
				}
				switch {
				case qerr != nil:
					after["enforced"] = "error"
					after["enforce_error"] = qerr.Error()
					slog.Default().Warn("runtime threat quarantine", slog.Any("err", qerr), slog.String("workload", workload))
				case isolate:
					after["enforced"] = "isolate"
				default:
					after["enforced"] = "quarantine"
				}
			}
		}
		if h.audit != nil {
			_, _, _ = h.audit.Log(ctx, audit.Event{
				OrgID:      &oid,
				Action:     "response_rule.action." + string(a.Type),
				TargetKind: "workload",
				TargetID:   p.workloadID,
				After:      after,
				At:         p.row.At,
			})
		}
	}
}

// threatWorkloadMatchKey derives the "namespace/pod" quarantine key from a
// threat's attribution, falling back to the raw workload_id.
func threatWorkloadMatchKey(p *pendingThreatAlert) string {
	if p.namespace != "" && p.podName != "" {
		return p.namespace + "/" + p.podName
	}
	return strings.TrimSpace(p.workloadID)
}

// threatSeverityLabel maps a NeuVector THRT_SEVERITY_* value (1..5, defs.h) to
// the info/low/medium/high/critical string the notify + response engines use.
func threatSeverityLabel(sev uint8) string {
	switch {
	case sev >= 5:
		return "critical"
	case sev == 4:
		return "high"
	case sev == 3:
		return "medium"
	case sev == 2:
		return "low"
	default:
		return "info"
	}
}

// srcHostPort renders "ip:port" (or just "ip" when no port) for alert titles.
func srcHostPort(ip string, port int) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		ip = "?"
	}
	if port > 0 {
		return ip + ":" + strconv.Itoa(port)
	}
	return ip
}
