// Wave C4.5: agent-side DLP rule sync.
//
// Every interval (default 60s) the agent:
//  1. GET /api/v1/runtime/dlp-rules:bundle?cluster_id=<id>
//  2. Compares the (id, version) of each row against last-applied set
//  3. On any diff: builds a dp.DLPRule slice + calls Supervisor.BuildDLPRules
//     with the agent's current tap MACs as scope
//
// Why pull and not push:
//   - The agent already has CONSTELLATION_API_URL + a bearer token. No new
//     transport / auth surface.
//   - A 60s lag is acceptable for DLP rule provisioning ("operator added a
//     pattern, takes ~minute to fire"). Lower latency belongs in the
//     authoring UX, not the network path.
//   - Independent of dp's IPC — the sync loop survives dp restarts.
//
// Failure semantics: every step is best-effort. A failed fetch logs +
// retries next interval. A failed BuildDLPRules logs + retries next
// interval. The agent never blocks startup on this.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler/runtime"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// DLPSyncConfig — knobs for the worker.
type DLPSyncConfig struct {
	APIBaseURL string        // CONSTELLATION_API_URL (no trailing slash)
	Token      string        // RUNTIME_AGENT_TOKEN
	ClusterID  string        // CONSTELLATION_CLUSTER_ID
	Interval   time.Duration // Empty → 60s
	HTTPClient *http.Client  // Empty → 10s-timeout default
	Logger     *slog.Logger
	DPSup      *dp.Supervisor // for BuildDLPRules + TapMACs

	// EnforceEnabled is the fleet-level kill switch for DLP dropping. When
	// false (the default), enforce-mode rules are pushed as monitor/alert so
	// no live workload is ever blocked without an explicit opt-in. Set via
	// CONSTELLATION_DLP_ENFORCE=1 (see NewDLPSyncWorker) or by main.go.
	// SAFETY: this is the P0-1 "default enforce OFF at the fleet level" gate.
	EnforceEnabled bool
}

// dlpRuleWire mirrors handler.DLPRule's JSON shape. We deliberately
// re-declare the relevant fields here so the agent doesn't depend on the
// handler package (would pull in the entire server-side dependency graph).
type dlpRuleWire struct {
	ID       string   `json:"id"`
	DPRuleID int64    `json:"dp_rule_id"`
	Name     string   `json:"name"`
	Severity int16    `json:"severity"`
	Mode     string   `json:"mode"` // monitor | enforce | disabled
	Patterns []string `json:"patterns"`
	Version  int64    `json:"version"`
	// ScopeMACs is the optional per-workload scope (P1-5). Empty/nil means
	// "apply to every workload this agent taps" (the fleet-wide default). A
	// non-empty list restricts the rule to those workload MACs.
	ScopeMACs []string `json:"scope_macs,omitempty"`
}

type dlpListResponse struct {
	Rules []dlpRuleWire `json:"rules"`
}

// DLPSyncWorker periodically pulls runtime_dlp_rules and pushes diffs to
// dp via Supervisor.BuildDLPRules.
type DLPSyncWorker struct {
	cfg DLPSyncConfig

	// appliedSig is a hash of the last-pushed plan: rule (id, version, mode,
	// scope), the tap-MAC set, and the enforce gate. Any drift re-pushes.
	// A single signature is simpler than the old per-rule version map and
	// correctly catches scope/mode/enforce-gate changes that don't bump the
	// row version.
	mu         sync.Mutex
	appliedSig string
	// lastGen is the dp lifecycle generation the combined DLP+WAF plan was last
	// successfully pushed against. When the supervisor restarts dp after a
	// startup crash the generation bumps but the tap-MAC/enforce signature is
	// unchanged, so the plain signature check would never re-push to the fresh
	// (config-less) dp. A generation change forces a re-push even when the
	// signature matches; lastGen advances only after a fully successful push so
	// a mid-push failure retries next tick.
	//
	// WAF and DLP are now a SINGLE combined push (one shared dp detector, see
	// Supervisor.BuildDetector) rather than two independent legs, so one
	// signature + one generation marker covers both — the CRS pack varies only
	// by enforce gate and tap-MAC set, which dlpSyncSignature already includes.
	lastGen uint64

	// Telemetry — surfaced via Snapshot.
	syncs    atomic.Uint64
	pushes   atomic.Uint64
	errors   atomic.Uint64
	lastSync atomic.Int64 // unix seconds
}

// NewDLPSyncWorker builds an unstarted worker. The caller starts it via Run.
func NewDLPSyncWorker(cfg DLPSyncConfig) *DLPSyncWorker {
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	// Fleet-level enforce gate: OFF unless main.go set it or the operator
	// exported CONSTELLATION_DLP_ENFORCE truthy. Keeps enforce-mode rules
	// alert-only by default so nothing blocks live traffic on first rollout.
	if !cfg.EnforceEnabled {
		cfg.EnforceEnabled = envTruthy(os.Getenv("CONSTELLATION_DLP_ENFORCE"))
	}
	return &DLPSyncWorker{cfg: cfg}
}

// envTruthy treats 1/true/yes/on/enabled (any case) as enabled.
func envTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	}
	return false
}

// Run blocks until ctx is canceled, syncing on every Interval tick.
func (w *DLPSyncWorker) Run(ctx context.Context) {
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	// First sync 5s after startup so dp + taps have time to come up. We
	// don't fire immediately because BuildDLPRules with an empty MAC list
	// is wasted work.
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
	}
	w.SyncOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.SyncOnce(ctx)
		}
	}
}

// dpSyncGate is the shared readiness/restart decision every dp-pushing sync
// worker uses. skip is true when the current dp instance has not yet answered
// a keepalive — the worker must defer its push past dp's startup init race.
// force is true when dp's lifecycle generation has advanced since lastGen (dp
// was restarted and lost all prior config), so the caller must re-push even
// when its content signature is unchanged. Pure so it can be unit-tested
// without a live supervisor.
func dpSyncGate(ready bool, gen, lastGen uint64) (skip, force bool) {
	if !ready {
		return true, false
	}
	return false, gen != lastGen
}

// SyncOnce performs one fetch + push pass. Public for tests + manual
// triggering from an admin endpoint (future).
func (w *DLPSyncWorker) SyncOnce(ctx context.Context) {
	w.syncs.Add(1)
	w.lastSync.Store(time.Now().Unix())

	if w.cfg.ClusterID == "" {
		// Without a cluster_id the server has no way to scope results.
		// Skip; the env-var wiring in main.go logs this loudly.
		return
	}
	// Readiness + restart gate. Skip until the CURRENT dp instance has answered
	// a keepalive; a generation change forces a re-push of both the WAF and DLP
	// plans below even when their signatures are unchanged (the restarted dp
	// lost all prior config).
	gen := w.cfg.DPSup.Generation()
	ready := w.cfg.DPSup.Ready()
	w.mu.Lock()
	skip, force := dpSyncGate(ready, gen, w.lastGen)
	w.mu.Unlock()
	if skip {
		return
	}
	rules, err := w.fetch(ctx)
	if err != nil {
		w.errors.Add(1)
		w.cfg.Logger.Warn("dlp sync: fetch failed", slog.String("err", err.Error()))
		return
	}
	macs := w.cfg.DPSup.TapMACs()
	// Inline-only enforce workloads are skipped by the tap reconciler, so their
	// veths never appear in TapMACs(); their per-workload DPI opt-in rides the
	// enforce path instead. Pull it up BEFORE the guard so a node whose ONLY DPI
	// workload is inline-only still proceeds to the union below and binds the
	// detector to the verdict-capable ep — otherwise len(macs)==0 bails and
	// ENFORCE drop/reset never fires.
	var enfWaf, enfDlp map[string]bool
	if w.cfg.EnforceEnabled {
		enfWaf, enfDlp = w.cfg.DPSup.EnforceDPIScopeMACs()
	}
	if len(macs) == 0 && len(enfWaf) == 0 && len(enfDlp) == 0 {
		// No taps and no inline enforce opt-in → dp has no MACs to scope DLP to. Reschedule.
		return
	}

	// Per-workload DPI opt-in (from pod labels; default OFF). DLP binds only to
	// DLP-opted MACs and the CRS WAF pack only to WAF-opted MACs — NeuVector's
	// per-group waf_group/dlp_group model. Fleet-wide binding false-positives
	// (dp's check_sql_query runs the WAF SQLi rules on any workload's DB egress),
	// so DPI is off until a workload opts in via label.
	wafOpt, dlpOpt := w.cfg.DPSup.DPIScopeMACs()
	// nil when the tap manager is absent (pure inline-only node, no TapProvider);
	// the enforce union below writes into these, so they must be writable maps.
	if wafOpt == nil {
		wafOpt = map[string]bool{}
	}
	if dlpOpt == nil {
		dlpOpt = map[string]bool{}
	}

	// Bind DPI to the inline enforce (NFQUEUE) datapath so ENFORCE can actually
	// block. A DLP/WAF detector bound only to a mirror-tap ep sees a copy of the
	// packet and has NO verdict path, so DPIActionDrop/Reset are silent no-ops
	// there. When the fleet enforce gate is ON, UNION the enforce-managed ep MACs
	// (which carry their OWN per-workload waf/dlp opt-in via EnforceDPIScopeMACs)
	// into the opt-in sets: dp already knows these MACs (the enforce manager
	// AddMAC's each veth) and they carry an NFQUEUE queue, so a detector bound to
	// one yields an enforceable verdict. An inline-only workload is skipped by the
	// tap reconciler, so it is NEVER in the tap-derived wafOpt/dlpOpt — the old
	// tap-intersection bridge was a no-op for exactly the workloads that need it.
	// The opt-in still comes from the pod's labels (carried on the enforce path),
	// so no fleet-wide implicit DPI. enfOpted also feeds the change signature so a
	// workload entering/leaving enforce mode re-pushes.
	var enfOpted []string
	if w.cfg.EnforceEnabled {
		union := make(map[string]bool, len(enfWaf)+len(enfDlp))
		for m := range enfWaf {
			wafOpt[m] = true
			union[m] = true
		}
		for m := range enfDlp {
			dlpOpt[m] = true
			union[m] = true
		}
		enfOpted = sortedKeys(union)
	}

	// Pushed network-policy rule ids (nonzero DPPolicyID) currently programmed into
	// dp by the runtime-policy sync. dp gates DLP/WAF on the session's policy id, so
	// these get bound into ep->{dlp,waf}_rid_map (alongside the default id 0) — else
	// only default east-west sessions are scanned and positive-policy sessions are
	// missed (dpi_search.c OUTSIDE branch). Read every sync so a policy-id change
	// re-pushes the cfg (it's folded into the signature below).
	policyRIDs := loadPolicyRIDs()

	// Change detection: a signature over the fetched DLP rules, the enforce gate,
	// and BOTH opt-in sets (so relabelling a workload re-pushes even though the
	// tap-MAC set is unchanged). Re-push only on drift (or a dp generation bump).
	sig := dlpSyncSignature(rules, sortedKeys(dlpOpt), w.cfg.EnforceEnabled) + "|waf=" + strings.Join(sortedKeys(wafOpt), ",") + "|prids=" + joinUint32(policyRIDs) + "|enf=" + strings.Join(enfOpted, ",")
	w.mu.Lock()
	unchanged := sig == w.appliedSig
	w.mu.Unlock()
	if unchanged && !force {
		return
	}

	wafRules := runtime.WAFRuleTable(w.cfg.EnforceEnabled)

	// DLP + WAF compile into ONE dp detector per endpoint (two builds clobber —
	// dpi_dlp_detect_update replaces the ep's prior detector). So each MAC gets a
	// single BuildDetector carrying exactly the rule sets it opted into.
	// DLP rules are scoped per workload (P1-5); group by scope over DLP-opted MACs.
	pushes := planDLPPushes(rules, sortedKeys(dlpOpt), w.cfg.EnforceEnabled)
	covered := make(map[string]struct{}, len(dlpOpt))
	for _, p := range pushes {
		for _, m := range p.macs {
			covered[m] = struct{}{}
		}
		// A DLP-opted MAC may ALSO be WAF-opted → its one detector holds both.
		both, dlpOnly := splitByOptIn(p.macs, wafOpt)
		if len(both) > 0 {
			if err := w.cfg.DPSup.BuildDetector(p.rules, wafRules, both, nil, dp.ApplyDirBoth); err != nil {
				w.errors.Add(1)
				w.cfg.Logger.Warn("dlp+waf sync: BuildDetector (dlp+waf) failed", slog.String("err", err.Error()))
				return
			}
			if err := w.cfg.DPSup.ConfigureDetector(both, p.rules, wafRules, policyRIDs...); err != nil {
				w.errors.Add(1)
				w.cfg.Logger.Warn("dlp+waf sync: ConfigureDetector (dlp+waf) failed", slog.String("err", err.Error()))
				return
			}
		}
		if len(dlpOnly) > 0 {
			if err := w.cfg.DPSup.BuildDetector(p.rules, nil, dlpOnly, nil, dp.ApplyDirBoth); err != nil {
				w.errors.Add(1)
				w.cfg.Logger.Warn("dlp+waf sync: BuildDetector (dlp-only) failed", slog.String("err", err.Error()))
				return
			}
			if err := w.cfg.DPSup.ConfigureDetector(dlpOnly, p.rules, nil, policyRIDs...); err != nil {
				w.errors.Add(1)
				w.cfg.Logger.Warn("dlp+waf sync: ConfigureDetector (dlp-only) failed", slog.String("err", err.Error()))
				return
			}
		}
	}
	// WAF-opted MACs with no DLP rule → WAF-only detector.
	var wafOnly []string
	for m := range wafOpt {
		if _, ok := covered[m]; !ok {
			wafOnly = append(wafOnly, m)
		}
	}
	sort.Strings(wafOnly)
	if len(wafOnly) > 0 {
		if err := w.cfg.DPSup.BuildDetector(nil, wafRules, wafOnly, nil, dp.ApplyDirBoth); err != nil {
			w.errors.Add(1)
			w.cfg.Logger.Warn("dlp+waf sync: BuildDetector (waf-only) failed", slog.String("err", err.Error()))
			return
		}
		if err := w.cfg.DPSup.ConfigureDetector(wafOnly, nil, wafRules, policyRIDs...); err != nil {
			w.errors.Add(1)
			w.cfg.Logger.Warn("dlp+waf sync: ConfigureDetector (waf-only) failed", slog.String("err", err.Error()))
			return
		}
	}
	w.pushes.Add(1)
	w.mu.Lock()
	w.appliedSig = sig
	w.lastGen = gen
	w.mu.Unlock()
	w.cfg.Logger.Info("dlp+waf sync: applied",
		slog.Int("rules", len(rules)),
		slog.Int("waf_rules", len(wafRules)),
		slog.Int("dlp_macs", len(dlpOpt)),
		slog.Int("waf_macs", len(wafOpt)),
		slog.Int("groups", len(pushes)),
		slog.Int("enforce_bound_macs", len(enfOpted)),
		slog.Bool("enforce", w.cfg.EnforceEnabled))
}

// sortedKeys returns the keys of a set in sorted order (deterministic MAC lists
// and signatures).
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// joinUint32 renders a rid slice into a stable comma-joined string for the change
// signature. The slice is already sorted+deduped (policyRIDsFromMerged), so this
// is just a deterministic serialization.
func joinUint32(v []uint32) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = strconv.FormatUint(uint64(n), 10)
	}
	return strings.Join(parts, ",")
}

// splitByOptIn partitions macs into (in, out) by membership in set (e.g. the
// WAF-opted MAC set): `in` are also in set, `out` are not.
func splitByOptIn(macs []string, set map[string]bool) (in, out []string) {
	for _, m := range macs {
		if set[m] {
			in = append(in, m)
		} else {
			out = append(out, m)
		}
	}
	return in, out
}

// dlpPush is one (macs, rules) group destined for a single BuildDLPRules +
// ConfigureDLPRules pair. All MACs in a group share the same applicable rule
// set, so dp's full-replace-per-MAC-set semantics stay correct.
type dlpPush struct {
	macs  []string
	rules []*dp.DLPRule
}

// effectiveDLPMode applies the fleet enforce gate: enforce stays enforce only
// when enforcement is globally enabled, otherwise it degrades to monitor so
// the rule alerts instead of dropping. Any non-enforce mode passes through.
func effectiveDLPMode(mode string, enforceEnabled bool) string {
	if mode == "enforce" && !enforceEnabled {
		return "monitor"
	}
	return mode
}

// planDLPPushes partitions rules across the agent's tap MACs by scope.
//
//   - A rule with no ScopeMACs applies to every tap MAC (fleet-wide default).
//   - A scoped rule applies only to the tap MACs it names (case-insensitive).
//
// MACs that end up with the same applicable-rule set are grouped into one
// push. Deterministic ordering (sorted MACs, sorted groups) keeps the wire
// output and the change signature stable across syncs.
func planDLPPushes(rules []dlpRuleWire, tapMACs []string, enforceEnabled bool) []dlpPush {
	// Normalise the scope of each rule to lowercase for matching.
	type prepared struct {
		rule  *dp.DLPRule
		scope map[string]struct{} // nil ⇒ applies everywhere
	}
	prep := make([]prepared, 0, len(rules))
	for _, r := range rules {
		// dp rejects sig ids outside 20000-49999 and names with spaces
		// (dpi_sig.c). Our dp_rule_id sequence starts at 9000, so map it into
		// dp's user range; sanitize the name defensively.
		dr := &dp.DLPRule{
			Name:     dp.SanitizeSigName(r.Name),
			ID:       dp.DLPSigID(uint32(r.DPRuleID)),
			Patterns: r.Patterns,
			Mode:     effectiveDLPMode(r.Mode, enforceEnabled),
		}
		var scope map[string]struct{}
		if len(r.ScopeMACs) > 0 {
			scope = make(map[string]struct{}, len(r.ScopeMACs))
			for _, m := range r.ScopeMACs {
				scope[strings.ToLower(strings.TrimSpace(m))] = struct{}{}
			}
		}
		prep = append(prep, prepared{rule: dr, scope: scope})
	}

	// For each MAC, collect the ordered list of applicable rule indices and
	// key the group by that list so identical rule sets coalesce.
	sortedMACs := append([]string(nil), tapMACs...)
	sort.Strings(sortedMACs)
	groups := map[string]*dlpPush{}
	order := []string{} // group keys in first-seen order → then sorted
	for _, mac := range sortedMACs {
		lm := strings.ToLower(strings.TrimSpace(mac))
		key := ""
		var applicable []*dp.DLPRule
		for i := range prep {
			if prep[i].scope != nil {
				if _, ok := prep[i].scope[lm]; !ok {
					continue
				}
			}
			key += fmt.Sprintf("%d,", prep[i].rule.ID)
			applicable = append(applicable, prep[i].rule)
		}
		if len(applicable) == 0 {
			continue // this MAC has no rules → nothing to push for it
		}
		g, ok := groups[key]
		if !ok {
			g = &dlpPush{rules: applicable}
			groups[key] = g
			order = append(order, key)
		}
		g.macs = append(g.macs, mac)
	}
	sort.Strings(order)
	out := make([]dlpPush, 0, len(order))
	for _, k := range order {
		out = append(out, *groups[k])
	}
	return out
}

// dlpSyncSignature is a stable hash of everything that affects the pushed
// plan: each rule's id/version/mode/scope, the tap-MAC set, and the enforce
// gate. Two syncs with the same signature push nothing.
func dlpSyncSignature(rules []dlpRuleWire, tapMACs []string, enforceEnabled bool) string {
	parts := make([]string, 0, len(rules)+2)
	rs := append([]dlpRuleWire(nil), rules...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].DPRuleID < rs[j].DPRuleID })
	for _, r := range rs {
		scope := append([]string(nil), r.ScopeMACs...)
		sort.Strings(scope)
		parts = append(parts, fmt.Sprintf("%d:%d:%s:%s",
			r.DPRuleID, r.Version, r.Mode, strings.Join(scope, ",")))
	}
	macs := append([]string(nil), tapMACs...)
	sort.Strings(macs)
	parts = append(parts, "macs="+strings.Join(macs, ","))
	parts = append(parts, fmt.Sprintf("enforce=%t", enforceEnabled))
	return strings.Join(parts, "|")
}

// fetch issues the GET. Returns parsed rules slice.
func (w *DLPSyncWorker) fetch(ctx context.Context) ([]dlpRuleWire, error) {
	url := strings.TrimRight(w.cfg.APIBaseURL, "/") + "/api/v1/runtime/dlp-rules:bundle?cluster_id=" + w.cfg.ClusterID
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.cfg.Token)
	resp, err := w.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server %d", resp.StatusCode)
	}
	var out dlpListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return out.Rules, nil
}

// DLPSyncStats — telemetry exposed via /metrics.
type DLPSyncStats struct {
	Syncs    uint64
	Pushes   uint64
	Errors   uint64
	LastSync int64
}

func (w *DLPSyncWorker) Snapshot() DLPSyncStats {
	return DLPSyncStats{
		Syncs:    w.syncs.Load(),
		Pushes:   w.pushes.Load(),
		Errors:   w.errors.Load(),
		LastSync: w.lastSync.Load(),
	}
}
