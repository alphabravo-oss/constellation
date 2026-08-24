// Runtime-event ingest + read endpoints.
//
//	POST /api/v1/events:bulk        — runtime-agent bulk insert (auth: runtime-agent-token)
//	GET  /api/v1/events             — recent runtime events (auth: user JWT, verb=read-findings)
//
// The bulk path is what the per-node DaemonSet (cmd/constellation-runtime-agent) calls every
// few hundred ms with a batch of typed eBPF observations. Each incoming record is:
//
//   - tagged with ATT&CK techniques via pkg/attack (e.g. "exec" of a shell -> T1059.004),
//   - severity-heuristic'd against the workload's pkg/runtime/baseline state (when known),
//   - persisted into the `events` partitioned table, and
//   - optionally promoted to a `runtime.alert.<kind>` row in audit_events via pkg/audit
//     when severity is HIGH (e.g. shell exec in an "enforce"-mode workload).
//
// Runtime-agent-token auth is separate from user JWT auth: tokens are per-org service
// credentials that hold a SINGLE rbac verb (runtime-ingest), so a compromised agent cannot
// read findings, suppress them, etc. The hash is stored in runtime_agent_tokens.token_hash;
// the raw token is shown to the admin once at issuance.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	"github.com/alphabravocompany/constellation/pkg/attack"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/notify"
	"github.com/alphabravocompany/constellation/pkg/response"
	"github.com/alphabravocompany/constellation/pkg/responserule"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
)

// EventsIngest is the runtime-agent ingest handler.
type EventsIngest struct {
	db         *db.DB
	audit      *audit.Logger
	dispatcher *notify.Dispatcher

	// respond, when non-nil, is invoked once per HIGH/CRITICAL classified event so the
	// response/quarantine engine can close the detection->response loop (RT-2). Injected
	// by the API server (which owns the response.Engine + rule loading + runtime bridge);
	// nil disables auto-response. Called best-effort/panic-isolated like the notify fan-out.
	respond func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event)

	// decideResponseRules, when non-nil, evaluates response_rules_v2 without side effects
	// before a HIGH/CRITICAL event is written. This is what lets v2 suppress-log actually
	// suppress the runtime security-event row instead of firing after the log already exists.
	decideResponseRules func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event) ResponseRuleDecision

	// baselineMode returns the pkg/runtime/baseline mode of a workload (learn/monitor/enforce)
	// and the set of process basenames in its baseline. Injected so tests can drive the
	// severity-promotion path without standing up an Engine. Nil = treat every workload as
	// "learn" (never promotes to runtime.alert.*).
	baselineMode func(orgID uuid.UUID, workloadID string) (mode baseline.Mode, processes map[string]struct{}, ok bool)

	// clusterBaselineMode is the production runtime path. It scopes duplicate
	// namespace/name workloads by the authenticated agent cluster before classifying drift.
	clusterBaselineMode func(orgID, clusterID uuid.UUID, workloadID string) (mode baseline.Mode, processes map[string]struct{}, ok bool)

	// procTree is the bounded, TTL'd cross-batch process-tree cache (RT-4) that lets the
	// privilege-escalation detector correlate a root child against a non-root ancestor that
	// arrived in an EARLIER Bulk call. Lazily initialized on first Bulk so the existing
	// constructor signature is unchanged.
	procTree *procTreeCache

	// evalResponseRules, when non-nil, is the E1 declarative response-rule evaluator. It is
	// invoked once per HIGH/CRITICAL classified event with the event folded down to a
	// responserule.Event; it returns the ordered matching actions (priority-ordered) and
	// fires any webhook actions through the notify dispatcher as a side effect. Injected by
	// the API server (which owns response_rules loading); nil disables E1 evaluation. This
	// is the server-side half of E1 that closes "a rule fires on a matching runtime event".
	evalResponseRules func(ctx context.Context, orgID uuid.UUID, ev *responserule.Event) ([]responserule.Action, error)
}

// NewEventsIngest constructs the handler. Pass nil for baselineFn to disable severity
// promotion (every event is severity=info / verdict=observed).
func NewEventsIngest(d *db.DB, a *audit.Logger, baselineFn func(uuid.UUID, string) (baseline.Mode, map[string]struct{}, bool)) *EventsIngest {
	return &EventsIngest{db: d, audit: a, baselineMode: baselineFn, procTree: newProcTreeCache()}
}

func NewEventsIngestWithClusterBaseline(d *db.DB, a *audit.Logger, baselineFn func(uuid.UUID, uuid.UUID, string) (baseline.Mode, map[string]struct{}, bool)) *EventsIngest {
	return &EventsIngest{db: d, audit: a, clusterBaselineMode: baselineFn, procTree: newProcTreeCache()}
}

// WithDispatcher attaches a notify Dispatcher so high-severity events get fanned out to
// configured receivers. Returns the receiver for chaining.
func (h *EventsIngest) WithDispatcher(d *notify.Dispatcher) *EventsIngest {
	h.dispatcher = d
	return h
}

// WithResponseEngine attaches the response/quarantine dispatch hook (RT-2). The hook is
// called for each HIGH/CRITICAL classified event so matching response rules can fire
// quarantine/isolate actions. Returns the receiver for chaining.
func (h *EventsIngest) WithResponseEngine(respond func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event)) *EventsIngest {
	h.respond = respond
	return h
}

// WithResponseDecision attaches the side-effect-free v2 response-rule evaluator used for
// pre-insert suppress-log decisions. Returns the receiver for chaining.
func (h *EventsIngest) WithResponseDecision(decide func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event) ResponseRuleDecision) *EventsIngest {
	h.decideResponseRules = decide
	return h
}

// WithResponseRuleEngine attaches the E1 declarative response-rule evaluator (pkg/responserule).
// The hook is called for each HIGH/CRITICAL classified event so the org's enabled E1 rules can
// match and fire their ordered actions (quarantine/suppress_log/tag) and webhooks. Returns the
// receiver for chaining.
func (h *EventsIngest) WithResponseRuleEngine(eval func(ctx context.Context, orgID uuid.UUID, ev *responserule.Event) ([]responserule.Action, error)) *EventsIngest {
	h.evalResponseRules = eval
	return h
}

// IngestEvent is the JSON wire shape sent by the runtime-agent. Field names are stable;
// the agent's main.go emits exactly these keys (snake_case, matching the rest of the API).
//
// The "kind" field is the canonical event kind name: "process_exec", "tcp_connect",
// "tcp_accept", "file_open". The agent maps its internal EventKindProcess/Network/File
// -> these strings before posting.
type IngestEvent struct {
	At          time.Time `json:"at"`
	Kind        string    `json:"kind"`
	Node        string    `json:"node,omitempty"`
	WorkloadID  string    `json:"workload_id,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	Pod         string    `json:"pod,omitempty"`
	ContainerID string    `json:"container_id,omitempty"`

	// Process fields (kind=process_exec).
	PID      uint32   `json:"pid,omitempty"`
	PPID     uint32   `json:"ppid,omitempty"`
	UID      uint32   `json:"uid,omitempty"`
	Comm     string   `json:"comm,omitempty"`
	Filename string   `json:"filename,omitempty"`
	Args     []string `json:"args,omitempty"`

	// RT-4 /proc enrichment from the agent (optional; absent => current behavior).
	// UID above is the EFFECTIVE uid; Ruid is the REAL uid read from /proc/<pid>/status.
	// RuidKnown distinguishes ruid=0 (root) from ruid-unread. StdioSocket is true when the
	// process had a socket on fd 0/1/2 at exec time (reverse-shell tell).
	Ruid        uint32 `json:"ruid,omitempty"`
	RuidKnown   bool   `json:"ruid_known,omitempty"`
	StdioSocket bool   `json:"stdio_socket,omitempty"`

	// RT-MATCH-16 process-match enrichment (optional). ExePath is the resolved
	// /proc/<pid>/exe target; ExeSha256 the opt-in bounded content hash; ParentName the
	// parent comm. Persisted in the process_exec payload so the DB-derived baseline
	// bundle can pin allowed processes to a full path/hash/parent, defeating a
	// rename-to-allowed-name bypass. Absent => the baseline falls back to basename.
	ExePath    string `json:"exe_path,omitempty"`
	ExeSha256  string `json:"exe_sha256,omitempty"`
	ParentName string `json:"parent_name,omitempty"`

	// PrevUID is the effective UID a process held BEFORE a setuid(2) UID change with no
	// intervening exec (RT-SETUID-49; kind=uid_change). UID above is the new (escalated)
	// effective UID. Both set only for uid_change events emitted by the agent's UID monitor.
	PrevUID uint32 `json:"prev_uid,omitempty"`

	// Network fields (kind=tcp_connect / tcp_accept).
	Direction string `json:"direction,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Src       string `json:"src,omitempty"`
	Dst       string `json:"dst,omitempty"`

	// File fields (kind=file_open).
	Path  string `json:"path,omitempty"`
	Flags uint32 `json:"flags,omitempty"`
	Mode  uint32 `json:"mode,omitempty"`

	Blocked           bool   `json:"blocked,omitempty"`
	FileProfileRuleID string `json:"file_profile_rule_id,omitempty"`

	// ZeroDriftReason is the agent's P0-4 zero-drift tag ("zero-drift:image-drift" |
	// "zero-drift:unanchored") for a process_exec flagged by the agent's /proc
	// provenance proxy (ctime-vs-container-start + lineage anchoring). The server
	// cannot reproduce this /proc-derived signal, so classifyProcess trusts the tag
	// when its own baseline heuristics did not already fire.
	ZeroDriftReason string `json:"zero_drift_reason,omitempty"`
}

// IngestRequest is the wire shape POST'd to /api/v1/events:bulk: an array of typed events
// (envelope-less so the agent can stream-encode in one pass).
type IngestRequest = []IngestEvent

// IngestResponse summarizes what was accepted.
type IngestResponse struct {
	Accepted int `json:"accepted"`
	Alerts   int `json:"alerts"`
}

type eventClassification struct {
	Severity string
	Verdict  string
	FileRule *fileProfileRuleMatch

	// Techniques, when non-nil, overrides the generic techniquesFor() mapping for this
	// event (e.g. a privilege-escalation exec maps to T1068 rather than the shell mapping).
	Techniques []string
	// Reason is a short machine tag for why a finding fired ("provenance-drift",
	// "suspicious-binary", "privilege-escalation", "fim-default"); surfaced in the payload.
	Reason string
	// FIM, when non-nil, is a default File Integrity Monitoring watch-set hit (no
	// operator-authored file-profile rule matched, but the path is a default-watched one).
	FIM *fimWatch
}

type fileProfileRuleMatch struct {
	ID           uuid.UUID
	WorkloadID   string
	ProfileMode  fileProfileMode
	Filter       string
	Behavior     string
	Applications []string
	WouldBlock   bool
}

type fileProfileRuntimeRule struct {
	ID           uuid.UUID
	WorkloadID   string
	ProfileMode  fileProfileMode
	Filter       string
	Path         string
	Regex        string
	Recursive    bool
	Behavior     string
	Applications []string
	Exceptions   []fileProfileRuntimeException
	UpdatedAt    time.Time
	exactRE      *regexp.Regexp
	dirRE        *regexp.Regexp
	recursiveRE  *regexp.Regexp
	baseRE       *regexp.Regexp
}

type fileProfileRuntimeException struct {
	ID           uuid.UUID
	RuleID       uuid.UUID
	Filter       string
	Path         string
	Regex        string
	Recursive    bool
	Applications []string
	UpdatedAt    time.Time
	exactRE      *regexp.Regexp
	dirRE        *regexp.Regexp
	recursiveRE  *regexp.Regexp
	baseRE       *regexp.Regexp
}

type fileProfileRuleSet struct {
	byWorkload  map[string][]fileProfileRuntimeRule
	ownersByPod map[string][]string
}

// shellBinaries are the exec'd binaries that are categorically interesting (T1059.004) and
// trigger severity=high in enforce-mode workloads.
var shellBinaries = map[string]struct{}{
	"sh":      {},
	"bash":    {},
	"ash":     {},
	"dash":    {},
	"zsh":     {},
	"ksh":     {},
	"busybox": {},
	"nc":      {},
	"ncat":    {},
	"netcat":  {},
	"socat":   {},
	"python":  {},
	"python3": {},
}

// Bulk handles POST /api/v1/events:bulk. Validates the body, tags each event, persists in
// one transaction, and promotes severity=high events to runtime.alert.* audit rows.
//
// At most 1000 events per request to keep the txn short; the agent is supposed to send 200
// per batch. Anything bigger gets 413.
func (h *EventsIngest) Bulk(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB cap

	var events IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if len(events) == 0 {
		httpx.WriteJSON(w, http.StatusOK, IngestResponse{})
		return
	}
	if len(events) > 1000 {
		jsonError(w, http.StatusRequestEntityTooLarge, "batch > 1000")
		return
	}

	clusterID, status, err := h.resolveRuntimeEventClusterID(r.Context(), tok.OrgID, r)
	if err != nil {
		jsonError(w, status, err.Error())
		return
	}
	fileRules, err := h.loadFileProfileRuleSet(r.Context(), tok.OrgID, clusterID, events)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "file profile rules: "+err.Error())
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	const insertSQL = `
INSERT INTO events (org_id, cluster_id, node_id, workload_id, namespace, container_id,
                    source, kind, severity, verdict, attack_techniques, payload, at)
VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),'ebpf',$7,$8,$9,$10,$11,$12)`

	uidByPID := buildUIDByPID(events)
	now := time.Now().UTC()
	// Record this batch's execs in the cross-batch cache BEFORE classifying so a child and
	// its parent in the SAME batch still resolve, and so ancestors persist for later batches.
	for i := range events {
		ev := &events[i]
		if ev.Kind == "process_exec" {
			h.procTree.put(clusterID, ev.Node, ev.PID, ev.PPID, ev.UID, ev.Comm, now)
		}
	}

	var alerts, inserted int
	classifications := make([]eventClassification, len(events))
	// ruleActions holds the ordered E1 response-rule actions matched for each event (only the
	// HIGH/CRITICAL ones are evaluated); suppressed[i] is true when one of them is suppress_log.
	// Both are computed BEFORE the events insert so a suppress_log action can actually skip the
	// events row / audit / notify side-effects rather than firing after they were emitted.
	ruleActions := make([][]responserule.Action, len(events))
	v2Decisions := make([]ResponseRuleDecision, len(events))
	suppressed := make([]bool, len(events))
	for i := range events {
		ev := &events[i]
		if ev.Kind == "" {
			continue
		}
		if ev.At.IsZero() {
			ev.At = time.Now().UTC()
		}
		// privEsc is true if EITHER the within-batch index (privEscFromBatch) or the
		// cross-batch cache walk (privEscWithCache) finds a non-root ancestor of this root
		// child. The cache strictly augments the batch path; the original path keeps working.
		privEsc := privEscFromBatch(ev, uidByPID) ||
			h.procTree.privEscWithCache(ev, clusterID, uidByPID, now)
		cls := h.classifyEvent(tok.OrgID, clusterID, ev, fileRules, privEsc)
		classifications[i] = cls

		// E1 declarative response rules fire on HIGH/CRITICAL events (the same scope that gets
		// audited + notified). Evaluate them HERE — before the events insert and before the
		// post-commit audit/notify fan-out — so a matching suppress_log action can suppress
		// those side-effects instead of firing after the very log/alert it is meant to
		// suppress has already been emitted. The evaluator also fires any webhook actions
		// internally; we capture the ordered matched actions to enforce quarantine/tag in the
		// post-commit loop. Panic-isolated so a buggy rule can never roll back or 500 ingest.
		if (cls.Severity == "high" || cls.Severity == "critical") && h.evalResponseRules != nil {
			ruleActions[i] = h.evalResponseRulesSafe(r.Context(), tok.OrgID, ev, cls)
			suppressed[i] = responseRulesSuppressLog(ruleActions[i])
		}
		// v2 response_rules_v2 suppress-log is evaluated side-effect-free before the insert.
		// The explicit rule actions still run post-commit via h.respond; this decision only
		// gates the security-event row and generic runtime.alert/notify fan-out.
		if (cls.Severity == "high" || cls.Severity == "critical") && h.decideResponseRules != nil {
			v2Decisions[i] = h.responseDecisionSafe(r.Context(), tok.OrgID, clusterID, ev, cls)
			if v2Decisions[i].SuppressLog {
				suppressed[i] = true
			}
		}
		// suppress_log: drop the events row entirely for this detection (NeuVector parity —
		// suppress_log suppresses the security-event log). Enforcement actions on the same
		// rule (quarantine/tag/v2 explicit response actions) are still applied post-commit.
		if suppressed[i] {
			continue
		}

		techniques := techniquesForClassified(ev, cls)
		payload := payloadFor(ev, cls)
		// A default-FIM write is recorded as a file_modified finding (vs the raw
		// file_open observation) so the UI can distinguish integrity hits.
		storedKind := ev.Kind
		if cls.FIM != nil {
			storedKind = "file_modified"
		}

		if _, err := tx.Exec(r.Context(), insertSQL,
			tok.OrgID, clusterID, ev.Node, ev.WorkloadID, ev.Namespace, ev.ContainerID,
			storedKind, cls.Severity, cls.Verdict, techniques, payload, ev.At,
		); err != nil {
			jsonError(w, http.StatusInternalServerError, "insert: "+err.Error())
			return
		}
		inserted++
		if cls.Severity == "high" || cls.Severity == "critical" {
			alerts++
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit: "+err.Error())
		return
	}

	// Audit-log the high-severity events outside the events txn so an audit-chain
	// failure doesn't roll back the ingest.
	for i := range events {
		ev := &events[i]
		cls := classifications[i]
		if cls.Severity != "high" && cls.Severity != "critical" {
			continue
		}
		orgID := tok.OrgID
		techniques := techniquesForClassified(ev, cls)
		// suppress_log: the matching event's events row was already skipped pre-commit; skip
		// the runtime.alert audit row and the notify fan-out too. The response_rule.action
		// audit written by applyResponseRuleActions below still records that the rule fired
		// and that it suppressed the alert, so the suppression itself stays observable.
		if !suppressed[i] {
			auditKind := ev.Kind
			if cls.FIM != nil {
				auditKind = "file_modified"
			}
			action := "runtime.alert." + auditSubKind(auditKind)
			after := map[string]any{
				"node":              ev.Node,
				"namespace":         ev.Namespace,
				"pod":               ev.Pod,
				"comm":              ev.Comm,
				"filename":          ev.Filename,
				"severity":          cls.Severity,
				"attack_techniques": techniques,
			}
			if cls.Reason != "" {
				after["reason"] = cls.Reason
			}
			if cls.FileRule != nil {
				after["path"] = ev.Path
				after["file_profile_rule_id"] = cls.FileRule.ID.String()
				after["file_profile_rule_filter"] = cls.FileRule.Filter
				after["file_profile_behavior"] = cls.FileRule.Behavior
				after["file_profile_mode"] = string(cls.FileRule.ProfileMode)
				after["would_block"] = cls.FileRule.WouldBlock
			}
			if cls.FIM != nil {
				after["path"] = ev.Path
				after["fim_watch"] = cls.FIM.label
			}
			_, _, _ = h.audit.Log(r.Context(), audit.Event{
				OrgID:      &orgID,
				Action:     action,
				TargetKind: "workload",
				TargetID:   ev.WorkloadID,
				After:      after,
				At:         ev.At,
			})
			// Fan out via notify on HIGH/CRITICAL — fire-and-forget, never blocks ingest.
			if h.dispatcher != nil {
				_, _ = h.dispatcher.Dispatch(r.Context(), notify.Event{
					Kind: action, OrgID: orgID, Severity: cls.Severity,
					Title:    fmt.Sprintf("%s on %s/%s", action, ev.Namespace, ev.Pod),
					Workload: ev.WorkloadID,
					Cluster:  ev.Node,
					Labels: map[string]string{
						"severity":   cls.Severity,
						"event_kind": ev.Kind,
						"node":       ev.Node,
						"namespace":  ev.Namespace,
					},
					Payload: map[string]any{
						"comm":              ev.Comm,
						"filename":          ev.Filename,
						"attack_techniques": techniques,
						"file_profile_rule": fileProfileRulePayload(cls.FileRule),
					},
					URL:     "/runtime/events",
					FiredAt: ev.At,
				})
			}
		}
		// If a v2 suppress-log action gated the row/audit/notify side-effects, record the
		// suppression itself so the absence of the runtime event is explainable.
		if v2Decisions[i].SuppressLog {
			h.auditResponseV2SuppressLog(r.Context(), orgID, clusterID, ev, v2Decisions[i])
		}
		// Close the detection->response loop on HIGH/CRITICAL (RT-2). Best-effort and
		// panic-isolated, exactly like the notify fan-out above: a misbehaving rule or
		// runtime bridge must never roll back or 500 the ingest. v2 suppress-log only gates
		// the generic log/alert side-effects; explicit v2 actions still dispatch here.
		if h.respond != nil {
			h.dispatchResponse(r.Context(), orgID, clusterID, ev, cls, techniques)
		}
		// E1: enforce the actions matched pre-commit, in priority order (quarantine/tag);
		// webhooks already fired inside the evaluator and suppress_log was enforced above.
		if h.evalResponseRules != nil {
			h.applyResponseRuleActions(r.Context(), orgID, clusterID, ev, ruleActions[i])
		}
	}

	httpx.WriteJSON(w, http.StatusOK, IngestResponse{Accepted: inserted, Alerts: alerts})
}

// dispatchResponse folds a classified HIGH/CRITICAL event down to a response.Event and
// hands it to the injected response-engine hook. Panic-isolated so a buggy rule/bridge
// can't take down the ingest goroutine.
func (h *EventsIngest) dispatchResponse(ctx context.Context, orgID, clusterID uuid.UUID, ev *IngestEvent, cls eventClassification, techniques []string) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Default().Error("response dispatch panic", slog.Any("recover", rec))
		}
	}()
	revt := responseEventForIngest(clusterID, ev, cls)
	h.respond(ctx, orgID, clusterID, revt)
}

func responseEventForIngest(clusterID uuid.UUID, ev *IngestEvent, cls eventClassification) response.Event {
	revt := response.Event{
		ID:        uuid.NewString(),
		Name:      ev.Kind,
		Type:      response.EventRuntime,
		Severity:  cls.Severity,
		Cluster:   clusterID.String(),
		Namespace: ev.Namespace,
		Workload:  ev.WorkloadID,
		Labels: map[string]string{
			"event_kind":  ev.Kind,
			"node":        ev.Node,
			"namespace":   ev.Namespace,
			"pod":         ev.Pod,
			"workload_id": ev.WorkloadID,
		},
		ProcessName: commBasename(ev.Comm, ev.Filename),
		Title:       fmt.Sprintf("runtime.alert.%s on %s/%s", auditSubKind(ev.Kind), ev.Namespace, ev.Pod),
		URL:         "/runtime/events",
	}
	if cls.Reason != "" {
		revt.Name = cls.Reason
	}
	return revt
}

func (h *EventsIngest) responseDecisionSafe(ctx context.Context, orgID, clusterID uuid.UUID, ev *IngestEvent, cls eventClassification) (decision ResponseRuleDecision) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Default().Error("response v2 decision panic", slog.Any("recover", rec))
			decision = ResponseRuleDecision{}
		}
	}()
	return h.decideResponseRules(ctx, orgID, clusterID, responseEventForIngest(clusterID, ev, cls))
}

func (h *EventsIngest) auditResponseV2SuppressLog(ctx context.Context, orgID, clusterID uuid.UUID, ev *IngestEvent, decision ResponseRuleDecision) {
	if h.audit == nil || !decision.SuppressLog {
		return
	}
	for _, match := range decision.Matches {
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
				"event_kind":  ev.Kind,
				"namespace":   ev.Namespace,
				"pod":         ev.Pod,
				"workload_id": ev.WorkloadID,
				"cluster_id":  clusterID.String(),
				"enforced":    "suppressed_log",
			}
			for k, v := range act.Params {
				after["param_"+k] = v
			}
			_, _, _ = h.audit.Log(ctx, audit.Event{
				OrgID:      &oid,
				Action:     "response_rule_v2.action.suppress_log",
				TargetKind: "workload",
				TargetID:   ev.WorkloadID,
				After:      after,
				At:         ev.At,
			})
		}
	}
}

// evalResponseRulesSafe folds a classified HIGH/CRITICAL event down to a responserule.Event
// and evaluates the org's enabled E1 rules, returning the ordered matching actions. Webhook
// delivery happens inside the injected evaluator (which owns the notify dispatcher) as a side
// effect of evaluation; the returned actions are enforced later in priority order by
// applyResponseRuleActions. This is called BEFORE the events insert so a suppress_log action
// is known in time to suppress the events/audit/notify side-effects. Panic-isolated/best-effort
// so a buggy rule can never roll back or 500 the ingest.
func (h *EventsIngest) evalResponseRulesSafe(ctx context.Context, orgID uuid.UUID, ev *IngestEvent, cls eventClassification) (actions []responserule.Action) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Default().Error("response-rule dispatch panic", slog.Any("recover", rec))
			actions = nil
		}
	}()
	rev := responseRuleEvent(ev, cls)
	if rev == nil {
		return nil
	}
	got, err := h.evalResponseRules(ctx, orgID, rev)
	if err != nil {
		slog.Default().Warn("response-rule evaluate", slog.Any("err", err))
		return nil
	}
	return got
}

// responseRulesSuppressLog reports whether the matched actions include a suppress_log action.
// When true the ingest path skips the event's events row, runtime.alert audit, and notify
// fan-out (the side-effects suppress_log is meant to suppress).
func responseRulesSuppressLog(actions []responserule.Action) bool {
	for i := range actions {
		if actions[i].Type == responserule.ActionSuppressLog {
			return true
		}
	}
	return false
}

// responseRuleEvent maps an ingested runtime event to the E1 responserule.Event shape. It
// returns nil for kinds that have no E1 event_type. Fields are string-valued attributes a
// Condition.Field can reference (process_name, path, severity, namespace, ...).
func responseRuleEvent(ev *IngestEvent, cls eventClassification) *responserule.Event {
	var et responserule.EventType
	switch ev.Kind {
	case "process_exec":
		et = responserule.EventProcess
	case "file_open", "file_modified":
		et = responserule.EventFile
	case "tcp_connect", "tcp_accept":
		et = responserule.EventNetwork
	default:
		return nil
	}
	fields := map[string]string{
		"kind":         ev.Kind,
		"severity":     cls.Severity,
		"verdict":      cls.Verdict,
		"process_name": commBasename(ev.Comm, ev.Filename),
		"comm":         ev.Comm,
		"filename":     ev.Filename,
		"namespace":    ev.Namespace,
		"pod":          ev.Pod,
		"node":         ev.Node,
		"workload_id":  ev.WorkloadID,
		"container_id": ev.ContainerID,
	}
	switch et {
	case responserule.EventFile:
		fields["path"] = ev.Path
	case responserule.EventNetwork:
		fields["direction"] = ev.Direction
		fields["protocol"] = ev.Protocol
		fields["src"] = ev.Src
		fields["dst"] = ev.Dst
	}
	if cls.Reason != "" {
		fields["reason"] = cls.Reason
	}
	return &responserule.Event{Type: et, Fields: fields}
}

// applyResponseRuleActions applies the ordered E1 actions in the data plane. Actions are
// applied in the priority order the evaluator returned them. quarantine reuses the existing
// runtime quarantine bridge (via the RT-2 respond hook is the v2 path; here we audit-log the
// applied action so the ordered execution is observable and the loop is closed). suppress_log
// and tag are recorded too. Webhook delivery already happened inside the evaluator.
func (h *EventsIngest) applyResponseRuleActions(ctx context.Context, orgID, clusterID uuid.UUID, ev *IngestEvent, actions []responserule.Action) {
	for i := range actions {
		a := actions[i]
		oid := orgID
		after := map[string]any{
			"action":      string(a.Type),
			"order":       i,
			"event_kind":  ev.Kind,
			"namespace":   ev.Namespace,
			"pod":         ev.Pod,
			"workload_id": ev.WorkloadID,
		}
		for k, v := range a.Params {
			after["param_"+k] = v
		}
		// E1: actually ENFORCE the action, not just record it. Quarantine reuses the same
		// origin='auto' quarantine bridge RT-2 uses (quarantineRuntime): a plain quarantine
		// records the blocking entry; param isolate=true additionally severs the live
		// workload's network via a deny-all cordon. suppress_log was enforced earlier in Bulk
		// (the events row / runtime.alert audit / notify fan-out were skipped); tag is recorded
		// as workload metadata (NeuVector's tag is likewise just a label — Constellation has no
		// workload-tags table, so it lives in this audit row's param_* fields); webhook already
		// fired inside the evaluator. Every branch sets an explicit "enforced" outcome so no
		// configured action is a silent no-op.
		switch a.Type {
		case responserule.ActionSuppressLog:
			after["enforced"] = "suppressed_log"
		case responserule.ActionTag:
			after["enforced"] = "tagged"
		case responserule.ActionWebhook:
			after["enforced"] = "webhook_dispatched"
		case responserule.ActionQuarantine:
			workload := workloadMatchKey(ev)
			switch {
			case workload == "":
				after["enforced"] = "skipped_no_workload"
			case clusterID == uuid.Nil:
				// quarantine_entries + the isolate cordon are cluster-scoped and FK-bound to
				// clusters(id); a uuid.Nil cluster (org has none, or no cluster_id on the
				// event) can't be enforced without writing an orphaned row, so record the
				// intent instead. Mirrors the scan path's clusterID==Nil guard.
				after["enforced"] = "skipped_no_cluster"
			default:
				q := &quarantineRuntime{db: h.db, orgID: orgID, clusterID: clusterID}
				reason := "response_rule: " + ev.Kind
				isolate := strings.EqualFold(a.Params["isolate"], "true")
				var qerr error
				if isolate {
					qerr = q.Isolate(ctx, workload, reason)
				} else {
					qerr = q.Quarantine(ctx, workload, reason)
				}
				// Set enforced only on success so the audit trail never claims an isolate
				// that the FK-bound cordon actually rejected (the prior bug).
				switch {
				case qerr != nil:
					after["enforced"] = "error"
					after["enforce_error"] = qerr.Error()
					slog.Default().Warn("response-rule quarantine", slog.Any("err", qerr), slog.String("workload", workload))
				case isolate:
					after["enforced"] = "isolate"
				default:
					after["enforced"] = "quarantine"
				}
			}
		}
		_, _, _ = h.audit.Log(ctx, audit.Event{
			OrgID:      &oid,
			Action:     "response_rule.action." + string(a.Type),
			TargetKind: "workload",
			TargetID:   ev.WorkloadID,
			After:      after,
			At:         ev.At,
		})
	}
}

// workloadMatchKey derives the "namespace/pod" quarantine match key from an ingested
// event, falling back to the raw workload_id. Empty when nothing identifies a workload.
func workloadMatchKey(ev *IngestEvent) string {
	if ev.Namespace != "" && ev.Pod != "" {
		return ev.Namespace + "/" + ev.Pod
	}
	return strings.TrimSpace(ev.WorkloadID)
}

func (h *EventsIngest) resolveRuntimeEventClusterID(ctx context.Context, orgID uuid.UUID, r *http.Request) (uuid.UUID, int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if raw != "" {
		clusterID, err := uuid.Parse(raw)
		if err != nil {
			return uuid.Nil, http.StatusBadRequest, errors.New("invalid cluster_id")
		}
		var exists bool
		if err := h.db.Pool().QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM clusters WHERE org_id = $1 AND id = $2)`,
			orgID, clusterID).Scan(&exists); err != nil {
			return uuid.Nil, http.StatusInternalServerError, fmt.Errorf("cluster lookup: %w", err)
		}
		if !exists {
			return uuid.Nil, http.StatusNotFound, errors.New("cluster not found")
		}
		return clusterID, http.StatusOK, nil
	}

	var clusterID uuid.UUID
	_ = h.db.Pool().QueryRow(ctx,
		`SELECT id FROM clusters WHERE org_id = $1 ORDER BY created_at LIMIT 1`, orgID).
		Scan(&clusterID)
	return clusterID, http.StatusOK, nil
}

func (h *EventsIngest) loadFileProfileRuleSet(ctx context.Context, orgID, clusterID uuid.UUID, events []IngestEvent) (*fileProfileRuleSet, error) {
	set := &fileProfileRuleSet{
		byWorkload:  map[string][]fileProfileRuntimeRule{},
		ownersByPod: map[string][]string{},
	}
	if h == nil || h.db == nil || clusterID == uuid.Nil {
		return set, nil
	}

	workloadSeen := map[string]bool{}
	workloads := []string{}
	for i := range events {
		ev := events[i]
		if ev.Kind != "file_open" || strings.TrimSpace(ev.WorkloadID) == "" {
			continue
		}
		if !workloadSeen[ev.WorkloadID] {
			workloadSeen[ev.WorkloadID] = true
			workloads = append(workloads, ev.WorkloadID)
		}
	}
	if len(workloads) == 0 {
		return set, nil
	}

	targetWorkloadSeen := map[string]bool{}
	for _, workloadID := range workloads {
		targetWorkloadSeen[workloadID] = true
	}
	linkRows, err := h.db.Pool().Query(ctx, `
SELECT pod_workload_id,
       owner_workload_id
  FROM pod_workload_links
 WHERE org_id = $1
   AND cluster_id = $2
   AND pod_workload_id = ANY($3::text[])
   AND owner_workload_id <> ''`, orgID, clusterID, workloads)
	if err != nil {
		return nil, err
	}
	defer linkRows.Close()
	for linkRows.Next() {
		var podWorkloadID, ownerWorkloadID string
		if err := linkRows.Scan(&podWorkloadID, &ownerWorkloadID); err != nil {
			return nil, err
		}
		if podWorkloadID == "" || ownerWorkloadID == "" {
			continue
		}
		set.ownersByPod[podWorkloadID] = append(set.ownersByPod[podWorkloadID], ownerWorkloadID)
		targetWorkloadSeen[ownerWorkloadID] = true
	}
	if err := linkRows.Err(); err != nil {
		return nil, err
	}
	targetWorkloads := make([]string, 0, len(targetWorkloadSeen))
	for workloadID := range targetWorkloadSeen {
		targetWorkloads = append(targetWorkloads, workloadID)
	}
	sort.Strings(targetWorkloads)

	rows, err := h.db.Pool().Query(ctx, `
SELECT r.id,
       r.workload_id,
       COALESCE(s.mode, 'learn'),
       r.filter,
       r.path,
       r.regex,
       r.recursive,
       r.behavior,
       r.applications,
       r.updated_at
  FROM file_profile_rules r
  LEFT JOIN file_profile_states s
    ON s.org_id = r.org_id
   AND s.cluster_id = r.cluster_id
   AND s.workload_id = r.workload_id
 WHERE r.org_id = $1
   AND r.cluster_id = $2
   AND r.enabled
   AND r.workload_id = ANY($3::text[])`, orgID, clusterID, targetWorkloads)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ruleIDs := []string{}
	for rows.Next() {
		var rule fileProfileRuntimeRule
		var modeRaw string
		if err := rows.Scan(&rule.ID, &rule.WorkloadID, &modeRaw, &rule.Filter, &rule.Path,
			&rule.Regex, &rule.Recursive, &rule.Behavior, &rule.Applications, &rule.UpdatedAt); err != nil {
			return nil, err
		}
		mode, err := normalizeFileProfileMode(modeRaw)
		if err != nil {
			return nil, err
		}
		rule.ProfileMode = mode
		rule.Applications = nonNilStrings(rule.Applications)
		if err := compileFileProfileRuntimeRule(&rule); err != nil {
			return nil, fmt.Errorf("compile %s: %w", rule.Filter, err)
		}
		ruleIDs = append(ruleIDs, rule.ID.String())
		set.byWorkload[rule.WorkloadID] = append(set.byWorkload[rule.WorkloadID], rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ruleIDs) > 0 {
		if err := h.attachFileProfileRuntimeExceptions(ctx, orgID, clusterID, targetWorkloads, ruleIDs, set); err != nil {
			return nil, err
		}
	}
	return set, nil
}

func (h *EventsIngest) attachFileProfileRuntimeExceptions(ctx context.Context, orgID, clusterID uuid.UUID, workloadIDs []string, ruleIDs []string, set *fileProfileRuleSet) error {
	rows, err := h.db.Pool().Query(ctx, `
SELECT id,
       workload_id,
       COALESCE(rule_id::text, ''),
       filter,
       path,
       regex,
       recursive,
       applications,
       updated_at
  FROM file_profile_exceptions
 WHERE org_id = $1
   AND cluster_id = $2
   AND enabled
   AND workload_id = ANY($3::text[])
   AND (expires_at IS NULL OR expires_at > NOW())
   AND (rule_id IS NULL OR rule_id::text = ANY($4::text[]))`, orgID, clusterID, workloadIDs, ruleIDs)
	if err != nil {
		return err
	}
	defer rows.Close()
	byRule := map[uuid.UUID][]fileProfileRuntimeException{}
	byWorkload := map[string][]fileProfileRuntimeException{}
	for rows.Next() {
		var exception fileProfileRuntimeException
		var workloadID, ruleIDRaw string
		if err := rows.Scan(&exception.ID, &workloadID, &ruleIDRaw, &exception.Filter, &exception.Path,
			&exception.Regex, &exception.Recursive, &exception.Applications, &exception.UpdatedAt); err != nil {
			return err
		}
		exception.Applications = nonNilStrings(exception.Applications)
		if err := compileFileProfileRuntimeException(&exception); err != nil {
			return fmt.Errorf("compile exception %s: %w", exception.Filter, err)
		}
		if ruleIDRaw != "" {
			exception.RuleID = parseFileProfileOptionalUUID(ruleIDRaw)
			byRule[exception.RuleID] = append(byRule[exception.RuleID], exception)
		} else {
			byWorkload[workloadID] = append(byWorkload[workloadID], exception)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for workloadID := range set.byWorkload {
		rules := set.byWorkload[workloadID]
		for i := range rules {
			exceptions := append([]fileProfileRuntimeException{}, byWorkload[workloadID]...)
			exceptions = append(exceptions, byRule[rules[i].ID]...)
			rules[i].Exceptions = exceptions
		}
		set.byWorkload[workloadID] = rules
	}
	return nil
}

func compileFileProfileRuntimeRule(rule *fileProfileRuntimeRule) error {
	if rule.Regex == "" {
		re, err := regexp.Compile("^" + rule.Path + "$")
		if err != nil {
			return err
		}
		rule.exactRE = re
		return nil
	}
	dirRE, err := regexp.Compile("^" + rule.Path + "$")
	if err != nil {
		return err
	}
	recursiveRE, err := regexp.Compile("^" + rule.Path + "(?:/.*)?$")
	if err != nil {
		return err
	}
	baseRE, err := regexp.Compile("^" + rule.Regex + "$")
	if err != nil {
		return err
	}
	rule.dirRE = dirRE
	rule.recursiveRE = recursiveRE
	rule.baseRE = baseRE
	return nil
}

func compileFileProfileRuntimeException(exception *fileProfileRuntimeException) error {
	if exception.Regex == "" {
		re, err := regexp.Compile("^" + exception.Path + "$")
		if err != nil {
			return err
		}
		exception.exactRE = re
		return nil
	}
	dirRE, err := regexp.Compile("^" + exception.Path + "$")
	if err != nil {
		return err
	}
	recursiveRE, err := regexp.Compile("^" + exception.Path + "(?:/.*)?$")
	if err != nil {
		return err
	}
	baseRE, err := regexp.Compile("^" + exception.Regex + "$")
	if err != nil {
		return err
	}
	exception.dirRE = dirRE
	exception.recursiveRE = recursiveRE
	exception.baseRE = baseRE
	return nil
}

func (set *fileProfileRuleSet) match(ev *IngestEvent) *fileProfileRuleMatch {
	if set == nil || ev == nil || ev.Kind != "file_open" {
		return nil
	}
	if ev.WorkloadID == "" || ev.Path == "" || !strings.HasPrefix(ev.Path, "/") {
		return nil
	}
	workloads := []string{ev.WorkloadID}
	workloads = append(workloads, set.ownersByPod[ev.WorkloadID]...)

	candidates := []fileProfileRuntimeRule{}
	seen := map[uuid.UUID]bool{}
	for _, workloadID := range workloads {
		for _, rule := range set.byWorkload[workloadID] {
			if seen[rule.ID] {
				continue
			}
			seen[rule.ID] = true
			candidates = append(candidates, rule)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if fileProfileBehaviorRank(candidates[i].Behavior) != fileProfileBehaviorRank(candidates[j].Behavior) {
			return fileProfileBehaviorRank(candidates[i].Behavior) < fileProfileBehaviorRank(candidates[j].Behavior)
		}
		if candidates[i].Recursive != candidates[j].Recursive {
			return candidates[i].Recursive
		}
		if !candidates[i].UpdatedAt.Equal(candidates[j].UpdatedAt) {
			return candidates[i].UpdatedAt.After(candidates[j].UpdatedAt)
		}
		return candidates[i].Filter < candidates[j].Filter
	})
	for _, rule := range candidates {
		if rule.ProfileMode == fileProfileModeLearn {
			continue
		}
		if !fileProfileRuleApplicationMatches(rule.Behavior, rule.Applications, ev.Comm, ev.Filename) {
			continue
		}
		if !rule.filePathMatches(ev.Path) {
			continue
		}
		if rule.exceptionMatches(ev.Path, ev.Comm, ev.Filename) {
			continue
		}
		return &fileProfileRuleMatch{
			ID:           rule.ID,
			WorkloadID:   rule.WorkloadID,
			ProfileMode:  rule.ProfileMode,
			Filter:       rule.Filter,
			Behavior:     rule.Behavior,
			Applications: rule.Applications,
			WouldBlock:   rule.Behavior == "block_access",
		}
	}
	return nil
}

func (rule fileProfileRuntimeRule) exceptionMatches(filePath, comm, filename string) bool {
	for _, exception := range rule.Exceptions {
		if !exception.filePathMatches(filePath) {
			continue
		}
		if len(exception.Applications) > 0 && !fileProfileRuleApplicationListContains(exception.Applications, comm, filename) {
			continue
		}
		return true
	}
	return false
}

func (rule fileProfileRuntimeRule) filePathMatches(filePath string) bool {
	if rule.Regex == "" {
		return rule.exactRE != nil && rule.exactRE.MatchString(filePath)
	}
	idx := strings.LastIndex(filePath, "/")
	if idx < 0 {
		return false
	}
	dir := filePath[:idx]
	if dir == "" {
		dir = "/"
	}
	base := filePath[idx+1:]
	if base == "" || rule.baseRE == nil || !rule.baseRE.MatchString(base) {
		return false
	}
	if rule.Recursive {
		return rule.recursiveRE != nil && rule.recursiveRE.MatchString(dir)
	}
	return rule.dirRE != nil && rule.dirRE.MatchString(dir)
}

func (exception fileProfileRuntimeException) filePathMatches(filePath string) bool {
	if exception.Regex == "" {
		return exception.exactRE != nil && exception.exactRE.MatchString(filePath)
	}
	idx := strings.LastIndex(filePath, "/")
	if idx < 0 {
		return false
	}
	dir := filePath[:idx]
	if dir == "" {
		dir = "/"
	}
	base := filePath[idx+1:]
	if base == "" || exception.baseRE == nil || !exception.baseRE.MatchString(base) {
		return false
	}
	if exception.Recursive {
		return exception.recursiveRE != nil && exception.recursiveRE.MatchString(dir)
	}
	return exception.dirRE != nil && exception.dirRE.MatchString(dir)
}

func fileProfileBehaviorRank(behavior string) int {
	if behavior == "block_access" {
		return 0
	}
	return 1
}

func fileProfileRuleApplicationMatches(behavior string, apps []string, comm, filename string) bool {
	if len(apps) == 0 {
		return true
	}
	matched := fileProfileRuleApplicationListContains(apps, comm, filename)
	if behavior == "block_access" {
		return !matched
	}
	return matched
}

func fileProfileRuleApplicationListContains(apps []string, comm, filename string) bool {
	candidates := map[string]bool{}
	for _, value := range []string{comm, filename, commBasename(comm, filename)} {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		candidates[value] = true
		if i := strings.LastIndex(value, "/"); i >= 0 && i+1 < len(value) {
			candidates[value[i+1:]] = true
		}
	}
	for _, app := range apps {
		app = strings.TrimSpace(app)
		if app == "" || app == "*" {
			return true
		}
		if candidates[app] {
			return true
		}
		if i := strings.LastIndex(app, "/"); i >= 0 && i+1 < len(app) && candidates[app[i+1:]] {
			return true
		}
	}
	return false
}

// classify returns (severity, verdict) for an event. The heuristic is intentionally simple:
//   - process_exec of a shell binary in an enforce-mode workload that isn't in the baseline
//     -> severity=high, verdict=alert
//   - process_exec of a shell binary in any other workload -> severity=medium, verdict=observed
//   - everything else -> severity=info, verdict=observed
//
// The full ATT&CK -> severity matrix lives in pkg/policy; this is a deliberate v1.
func (h *EventsIngest) classify(orgID uuid.UUID, ev *IngestEvent) (severity, verdict string) {
	cls := h.classifyWithFileRules(orgID, ev, nil)
	return cls.Severity, cls.Verdict
}

func (h *EventsIngest) classifyWithFileRules(orgID uuid.UUID, ev *IngestEvent, fileRules *fileProfileRuleSet) eventClassification {
	return h.classifyEvent(orgID, uuid.Nil, ev, fileRules, false)
}

// classifyEvent is the full classifier. privEsc is precomputed by the caller (Bulk)
// from within-batch PID/PPID UID correlation; tests can drive it directly.
func (h *EventsIngest) classifyEvent(orgID, clusterID uuid.UUID, ev *IngestEvent, fileRules *fileProfileRuleSet, privEsc bool) eventClassification {
	cls := eventClassification{Severity: "info", Verdict: "observed"}
	if ev.Kind == "file_open" {
		return h.classifyFileOpen(ev, fileRules, cls)
	}
	// RT-SETUID-49: a running process that escalated its effective UID to root via
	// setuid(2) WITHOUT an intervening exec (the agent's UID monitor only emits this
	// kind for that case) is a strong privilege-escalation signal — NeuVector's
	// rootEscalationCheck flags the same on its process monitor, not just at exec.
	if setuidWithoutExec(ev) {
		cls.Severity = "high"
		cls.Verdict = "alert"
		cls.Reason = "setuid-without-exec"
		cls.Techniques = attack.Map(attack.EventPrivilegeEscalation)
		return cls
	}
	if ev.Kind != "process_exec" {
		return cls
	}
	return h.classifyProcess(orgID, clusterID, ev, cls, privEsc)
}

// classifyFileOpen handles file_open events: explicit operator file-profile rules take
// precedence; otherwise the default FIM watch-set classifies writes to sensitive paths
// as file_modified findings.
func (h *EventsIngest) classifyFileOpen(ev *IngestEvent, fileRules *fileProfileRuleSet, cls eventClassification) eventClassification {
	if match := fileRules.match(ev); match != nil {
		cls.FileRule = match
		if ev.Blocked {
			cls.Verdict = "block"
		} else {
			cls.Verdict = "alert"
		}
		if match.Behavior == "block_access" {
			cls.Severity = "high"
		} else {
			cls.Severity = "medium"
		}
		return cls
	}
	if ev.Blocked {
		cls.Severity = "high"
		cls.Verdict = "block"
		return cls
	}
	// Default File Integrity Monitoring watch-set. Only a *write* to a watched path is a
	// modification; reads of sensitive files are already covered by techniquesFor/
	// isSensitivePath.
	if defaultFIMEnabled && isFileWrite(ev.Flags) {
		if w := matchDefaultFIM(ev.Path); w != nil {
			cls.FIM = w
			cls.Severity = w.fimSeverity()
			cls.Verdict = "alert"
			cls.Reason = "fim-default"
			cls.Techniques = attack.Map(attack.EventWriteSensitiveFile)
		}
	}
	return cls
}

// classifyProcess handles process_exec events with the broadened detections (provenance
// drift, suspicious binaries, privilege escalation) layered over the shell heuristic.
func (h *EventsIngest) classifyProcess(orgID, clusterID uuid.UUID, ev *IngestEvent, cls eventClassification, privEsc bool) eventClassification {
	bin := commBasename(ev.Comm, ev.Filename)
	_, isShell := shellBinaries[bin]

	var (
		mode         baseline.Mode
		inBaseline   bool
		haveBaseline bool
	)
	if h.clusterBaselineMode != nil && ev.WorkloadID != "" && clusterID != uuid.Nil {
		if m, procs, ok := h.clusterBaselineMode(orgID, clusterID, ev.WorkloadID); ok {
			mode = m
			haveBaseline = true
			_, inBaseline = procs[bin]
		}
	} else if h.baselineMode != nil && ev.WorkloadID != "" {
		if m, procs, ok := h.baselineMode(orgID, ev.WorkloadID); ok {
			mode = m
			haveBaseline = true
			_, inBaseline = procs[bin]
		}
	}

	revShell := reverseShell(ev, isShell)
	ruidEsc := realUIDEscalation(ev)
	if sig, ok := classifyProcessExec(bin, ev.Args, inBaseline, haveBaseline, mode, isShell, privEsc, revShell, ruidEsc); ok {
		cls.Severity = sig.severity
		cls.Verdict = sig.verdict
		cls.Reason = sig.reason
		if len(sig.techniques) > 0 {
			cls.Techniques = sig.techniques
		}
		return cls
	}

	// P0-4: the agent's /proc zero-drift proxy flagged this exec (a binary that
	// post-dates container start, or a process not anchored to the container root).
	// The server cannot recompute this signal, so trust the agent's tag when the
	// baseline heuristics above did not already fire. Blocked (enforce / pre-exec
	// deny) -> high/block; monitor observation -> medium/alert. Mirrors the server's
	// own provenance-drift severities.
	if strings.TrimSpace(ev.ZeroDriftReason) != "" {
		cls.Reason = ev.ZeroDriftReason
		if ev.Blocked {
			cls.Severity, cls.Verdict = "high", "block"
		} else {
			cls.Severity, cls.Verdict = "medium", "alert"
		}
		cls.Techniques = driftTechniques(isShell)
		return cls
	}

	// Fall back to the original shell heuristic for shells that are baselined / in a
	// learn-mode (or baseline-unknown) workload: still categorically interesting.
	if isShell {
		cls.Severity = "medium"
	}
	return cls
}

// techniquesForClassified returns the ATT&CK technique IDs for a classified event. When
// the classifier picked an explicit mapping (privilege escalation, suspicious binary,
// default-FIM write) that override wins; otherwise it falls back to the generic
// techniquesFor heuristic.
func techniquesForClassified(ev *IngestEvent, cls eventClassification) []string {
	if len(cls.Techniques) > 0 {
		return cls.Techniques
	}
	return techniquesFor(ev)
}

// techniquesFor returns the ATT&CK technique IDs this event maps to. Uses pkg/attack's
// EventKind catalog where applicable; otherwise returns an empty slice.
func techniquesFor(ev *IngestEvent) []string {
	switch ev.Kind {
	case "process_exec":
		bin := commBasename(ev.Comm, ev.Filename)
		if _, isShell := shellBinaries[bin]; isShell {
			return attack.Map(attack.EventShellSpawn)
		}
	case "tcp_connect":
		// Outbound tcp connect to a non-private IP could be C2 egress. We don't have
		// the address-classification context here so we leave it bare; pkg/attack's
		// EventEgress is appropriate when the address is non-private.
		if isPublicDst(ev.Dst) {
			return attack.Map(attack.EventEgress)
		}
	case "file_open":
		if isSensitivePath(ev.Path) {
			return attack.Map(attack.EventReadSensitiveFile)
		}
	}
	return []string{}
}

// payloadFor builds the JSONB payload column. Stays compact; only includes the per-kind
// fields the UI actually shows.
func payloadFor(ev *IngestEvent, cls eventClassification) []byte {
	m := map[string]any{}
	if ev.Pod != "" {
		m["pod"] = ev.Pod
	}
	switch ev.Kind {
	case "process_exec":
		m["pid"] = ev.PID
		m["ppid"] = ev.PPID
		m["uid"] = ev.UID
		m["comm"] = ev.Comm
		m["filename"] = ev.Filename
		if len(ev.Args) > 0 {
			m["args"] = ev.Args
		}
		// RT-4 /proc enrichment, surfaced only when present so absent => unchanged payload.
		if ev.StdioSocket {
			m["stdio_socket"] = true
		}
		if ev.RuidKnown {
			m["ruid"] = ev.Ruid
		}
		// RT-MATCH-16 process-match enrichment (present only when the agent sent it).
		if p := strings.TrimSpace(ev.ExePath); p != "" {
			m["exe_path"] = p
		}
		if s := strings.TrimSpace(ev.ExeSha256); s != "" {
			m["exe_sha256"] = s
		}
		if pn := strings.TrimSpace(ev.ParentName); pn != "" {
			m["parent_name"] = pn
		}
	case "uid_change":
		// RT-SETUID-49: privilege escalation via setuid(2) with no exec.
		m["pid"] = ev.PID
		m["comm"] = ev.Comm
		m["uid"] = ev.UID
		m["prev_uid"] = ev.PrevUID
	case "tcp_connect", "tcp_accept":
		m["pid"] = ev.PID
		m["comm"] = ev.Comm
		m["direction"] = ev.Direction
		m["protocol"] = ev.Protocol
		m["src"] = ev.Src
		m["dst"] = ev.Dst
	case "file_open":
		m["pid"] = ev.PID
		m["comm"] = ev.Comm
		m["path"] = ev.Path
		m["flags"] = ev.Flags
		m["mode"] = ev.Mode
		if ev.Blocked {
			m["blocked"] = true
		}
		if strings.TrimSpace(ev.FileProfileRuleID) != "" {
			m["file_profile_rule_id"] = strings.TrimSpace(ev.FileProfileRuleID)
		}
		if cls.FileRule != nil {
			m["file_profile_rule_id"] = cls.FileRule.ID.String()
			m["file_profile_rule_filter"] = cls.FileRule.Filter
			m["file_profile_workload_id"] = cls.FileRule.WorkloadID
			m["file_profile_mode"] = string(cls.FileRule.ProfileMode)
			m["file_profile_behavior"] = cls.FileRule.Behavior
			m["file_profile_applications"] = nonNilStrings(cls.FileRule.Applications)
			m["would_block"] = cls.FileRule.WouldBlock
		}
		if cls.FIM != nil {
			m["fim_default"] = true
			m["fim_watch"] = cls.FIM.label
			m["file_modified"] = true
		}
	}
	if cls.Reason != "" {
		m["detection_reason"] = cls.Reason
	}
	b, _ := json.Marshal(m)
	return b
}

func fileProfileRulePayload(match *fileProfileRuleMatch) map[string]any {
	if match == nil {
		return nil
	}
	return map[string]any{
		"id":           match.ID.String(),
		"workload_id":  match.WorkloadID,
		"mode":         string(match.ProfileMode),
		"filter":       match.Filter,
		"behavior":     match.Behavior,
		"applications": nonNilStrings(match.Applications),
		"would_block":  match.WouldBlock,
	}
}

func commBasename(comm, filename string) string {
	if comm != "" {
		return comm
	}
	if filename == "" {
		return ""
	}
	if i := strings.LastIndexByte(filename, '/'); i >= 0 {
		return filename[i+1:]
	}
	return filename
}

func auditSubKind(kind string) string {
	switch kind {
	case "process_exec":
		return "exec"
	case "tcp_connect", "tcp_accept":
		return "net"
	case "file_open":
		return "file"
	}
	return "other"
}

// isPublicDst returns true when dst is an IP:port whose IP isn't in RFC1918 / loopback /
// link-local / ULA ranges. Best-effort prefix check; for a deterministic CIDR test we'd
// pull in net/netip, but the payload here is already a string from the agent.
func isPublicDst(dst string) bool {
	if dst == "" {
		return false
	}
	host := dst
	if i := strings.LastIndexByte(dst, ':'); i > 0 {
		host = dst[:i]
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	switch {
	case host == "" || strings.HasPrefix(host, "127.") || host == "::1":
		return false
	case strings.HasPrefix(host, "10."):
		return false
	case strings.HasPrefix(host, "192.168."):
		return false
	case strings.HasPrefix(host, "172."):
		// 172.16.0.0/12 -- approximate by checking 172.16-172.31.
		var b1 int
		_, _ = fmt.Sscanf(host[4:], "%d", &b1)
		if b1 >= 16 && b1 <= 31 {
			return false
		}
	case strings.HasPrefix(host, "fe80:") || strings.HasPrefix(host, "fc") || strings.HasPrefix(host, "fd"):
		return false
	}
	return true
}

// isSensitivePath returns true for paths that hold credentials / tokens / shadow data —
// any file_open under one of these is read-sensitive (T1552.001).
func isSensitivePath(p string) bool {
	if p == "" {
		return false
	}
	for _, prefix := range []string{
		"/etc/shadow",
		"/etc/passwd",
		"/etc/sudoers",
		"/etc/kubernetes",
		"/root/.ssh",
		"/home",
		"/run/secrets",
		"/var/lib/kubelet/pki",
		"/var/run/secrets/kubernetes.io",
		"/var/run/secrets/eks.amazonaws.com",
	} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// EventDTO is the read-side shape returned by GET /api/v1/events.
type EventDTO struct {
	ID               uuid.UUID       `json:"id"`
	At               time.Time       `json:"at"`
	Kind             string          `json:"kind"`
	Source           string          `json:"source"`
	Severity         string          `json:"severity"`
	Verdict          string          `json:"verdict"`
	NodeID           string          `json:"node_id"`
	WorkloadID       string          `json:"workload_id"`
	Namespace        string          `json:"namespace,omitempty"`
	ContainerID      string          `json:"container_id,omitempty"`
	AttackTechniques []string        `json:"attack_techniques"`
	Payload          json.RawMessage `json:"payload"`
}

// List handles GET /api/v1/events. Returns the most recent N events for the calling user's
// org, ordered newest-first. Query params:
//
//	limit       1..1000   default 100
//	kind        comma-separated list of kinds to filter
//	severity    "info" | "low" | "medium" | "high" | "critical" — minimum
//	workload    workload_id substring filter
func (h *EventsIngest) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	args := []any{subj.OrgID}
	where := []string{"org_id = $1"}
	if clusterArg != nil {
		args = append(args, clusterArg)
		where = append(where, "cluster_id = $"+strconv.Itoa(len(args)))
	}
	if kindList := q.Get("kind"); kindList != "" {
		args = append(args, splitCSV(kindList))
		where = append(where, "kind = ANY($"+strconv.Itoa(len(args))+")")
	}
	if wl := q.Get("workload"); wl != "" {
		args = append(args, "%"+wl+"%")
		where = append(where, "workload_id ILIKE $"+strconv.Itoa(len(args)))
	}
	if sev := q.Get("severity"); sev != "" {
		// Treat severity as a tier filter rather than equality so the UI can ask
		// for "show me high+".
		tier := severityTier(sev)
		args = append(args, tier)
		where = append(where, "(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) >= $"+strconv.Itoa(len(args)))
	}
	args = append(args, limit)
	sql := `
SELECT id, at, kind, source, severity, verdict, node_id, workload_id,
       COALESCE(namespace,''), COALESCE(container_id,''), attack_techniques, payload
  FROM events
 WHERE ` + strings.Join(where, " AND ") + `
 ORDER BY at DESC
 LIMIT $` + strconv.Itoa(len(args))
	rows, err := h.db.Pool().Query(r.Context(), sql, args...)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := make([]EventDTO, 0, limit)
	for rows.Next() {
		var d EventDTO
		var payload []byte
		if err := rows.Scan(&d.ID, &d.At, &d.Kind, &d.Source, &d.Severity, &d.Verdict,
			&d.NodeID, &d.WorkloadID, &d.Namespace, &d.ContainerID, &d.AttackTechniques, &payload); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		d.Payload = payload
		if d.AttackTechniques == nil {
			d.AttackTechniques = []string{}
		}
		out = append(out, d)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"events": out, "limit": limit})
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

func severityTier(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// The runtime-agent-token auth primitives (RuntimeAgentToken, RuntimeAgentTokenFrom,
// RuntimeAgentTokenMiddleware, IssueRuntimeAgentToken, ErrNoToken) were relocated to
// runtime_agent_token_seam.go so they remain in package handler after this file moved
// into internal/handler/runtime. See that file's doc comment.
