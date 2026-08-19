// Compliance -> response/notify wiring (P1-16).
//
// NeuVector registers EventCompliance in its response-rule dispatch table, so a
// failed CIS/bench control is matched against response rules and can fire
// webhook/quarantine/suppress-log actions and flow to syslog under the audit
// category (neuvector/controller/cache/response.go). Constellation defined the
// response.EventCompliance enum but never constructed such an event, so bench and
// host-CIS results produced no alerts, no rule evaluation, and no SIEM mirror.
//
// complianceResponder closes that loop: each failed control is folded into a
// response.Event{Type: EventCompliance} for the RT-2 engine (response_rules_v2),
// evaluated against the E1 declarative rules (responserule.EventCompliance) whose
// webhooks fire in-evaluator and whose suppress_log action gates the alert, and —
// unless suppressed — dispatched as a notify.Event so receivers and the syslog/SIEM
// mirror see the failure. Mirrors the runtime events-ingest path.
package compliance

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/notify"
	"github.com/alphabravocompany/constellation/pkg/response"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// complianceFailure is one failed bench/CIS control folded to the neutral shape the
// response engine + notify dispatcher consume.
type complianceFailure struct {
	CheckID   string // control / check id, e.g. "1.2.22"
	Title     string // human-readable control title
	Framework string // e.g. "cis-k8s"; empty for host-CIS
	Severity  string // info|low|medium|high|critical; defaults to "high"
	Node      string // node name for host-CIS; empty for cluster/kube-bench
	Detail    string // optional actual/expected detail
}

func (f complianceFailure) severity() string {
	switch f.Severity {
	case "info", "low", "medium", "high", "critical":
		return f.Severity
	default:
		return "high"
	}
}

// name is the value CondName / EventCondTypeName regexes match against.
func (f complianceFailure) name() string {
	if f.CheckID != "" {
		return f.CheckID
	}
	return f.Title
}

func (f complianceFailure) title() string {
	loc := f.Node
	if loc == "" {
		loc = f.Framework
	}
	if loc == "" {
		return fmt.Sprintf("compliance check failed: %s", f.name())
	}
	return fmt.Sprintf("compliance check failed: %s on %s", f.name(), loc)
}

// responseEvent folds the failure to the RT-2 engine's canonical event.
func (f complianceFailure) responseEvent(clusterID uuid.UUID) response.Event {
	return response.Event{
		ID:       uuid.NewString(),
		Name:     f.name(),
		Type:     response.EventCompliance,
		Severity: f.severity(),
		Cluster:  clusterStr(clusterID),
		Workload: f.Node,
		Title:    f.title(),
		URL:      "/compliance/checks",
	}
}

// ruleEvent folds the failure to the E1 declarative engine's generic field event.
func (f complianceFailure) ruleEvent() *responserule.Event {
	return &responserule.Event{
		Type: responserule.EventCompliance,
		Fields: map[string]string{
			"check_id":  f.CheckID,
			"name":      f.name(),
			"title":     f.Title,
			"framework": f.Framework,
			"level":     f.severity(),
			"severity":  f.severity(),
			"node":      f.Node,
			"workload":  f.Node,
			"detail":    f.Detail,
		},
	}
}

// notifyEvent folds the failure to a notify.Event for receiver fan-out + syslog mirror.
func (f complianceFailure) notifyEvent(orgID, clusterID uuid.UUID) notify.Event {
	return notify.Event{
		Kind:     "compliance.fail",
		OrgID:    orgID,
		Severity: f.severity(),
		Title:    f.title(),
		Cluster:  clusterStr(clusterID),
		Workload: f.Node,
		URL:      "/compliance/checks",
		Labels: map[string]string{
			"check_id":  f.CheckID,
			"framework": f.Framework,
			"node":      f.Node,
		},
		Payload: map[string]any{
			"check_id":  f.CheckID,
			"title":     f.Title,
			"framework": f.Framework,
			"level":     f.severity(),
			"node":      f.Node,
			"detail":    f.Detail,
		},
	}
}

func clusterStr(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

// actionsSuppressLog reports whether an E1 suppress_log action matched (NeuVector
// parity: suppress_log suppresses the security-event/audit log — here the notify
// fan-out and its syslog mirror).
func actionsSuppressLog(actions []responserule.Action) bool {
	for _, a := range actions {
		if a.Type == responserule.ActionSuppressLog {
			return true
		}
	}
	return false
}

// complianceResponder holds the (all optional) alerting collaborators shared by the
// compliance ingest and host-CIS report handlers. A zero value is safe: every hook
// is nil-checked, so wiring is opt-in exactly like the runtime handlers.
type complianceResponder struct {
	// respond is the RT-2 response-engine hook (response_rules_v2). Same shape the
	// runtime/k8saudit ingest handlers use.
	respond func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event)
	// dispatcher fans a compliance failure out to the org's receivers and the syslog
	// mirror.
	dispatcher *notify.Dispatcher
	// evalRules is the E1 declarative evaluator. It fires webhook actions in-evaluator
	// and returns the matched actions so suppress_log can gate the notify fan-out.
	evalRules func(ctx context.Context, orgID uuid.UUID, ev *responserule.Event) ([]responserule.Action, error)
}

// fire folds each failed control into response/notify events and dispatches them.
// Panic-isolated and best-effort: a misbehaving rule, receiver, or bridge must never
// roll back or 500 the ingest that already persisted the results.
func (cr complianceResponder) fire(ctx context.Context, orgID, clusterID uuid.UUID, failures []complianceFailure) {
	if cr.respond == nil && cr.dispatcher == nil && cr.evalRules == nil {
		return
	}
	defer func() {
		if rec := recover(); rec != nil {
			slog.Default().Error("compliance response dispatch panic", slog.Any("recover", rec))
		}
	}()
	for _, f := range failures {
		// E1 declarative rules: webhooks fire inside the evaluator; a matched
		// suppress_log gates the notify fan-out (and its syslog mirror) below.
		suppress := false
		if cr.evalRules != nil {
			if acts, err := cr.evalRules(ctx, orgID, f.ruleEvent()); err != nil {
				slog.Default().Warn("compliance response-rule evaluate", slog.Any("err", err))
			} else {
				suppress = actionsSuppressLog(acts)
			}
		}
		// RT-2 engine — independent of E1 suppress_log, mirroring the events path.
		if cr.respond != nil {
			cr.respond(ctx, orgID, clusterID, f.responseEvent(clusterID))
		}
		if !suppress && cr.dispatcher != nil {
			_, _ = cr.dispatcher.Dispatch(ctx, f.notifyEvent(orgID, clusterID))
		}
	}
}
