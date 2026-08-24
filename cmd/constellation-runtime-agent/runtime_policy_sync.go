// H6 fix: agent-side runtime-policy sync — the missing caller of
// dp.Supervisor.PushPolicy.
//
// Before this worker existed, dp's per-workload policy engine was never
// programmed: PushPolicy had zero callers, so dp matched every connection
// against an empty rule table and only ever emitted its default action. An
// operator-created deny-egress / FQDN-allow was stored and audited by the
// control plane but never reached the datapath.
//
// Every interval the worker:
//  1. GET /api/v1/runtime/policies:bundle?cluster_id=<id>   (runtime-agent token)
//  2. Builds a single merged dp.WorkloadPolicy from every non-disabled policy
//     (mode mapping applied per source policy; each rule stamped with its
//     policy's dp_policy_id so DPMsgConnect.PolicyId joins back to the row).
//  3. On any change, programs dp via Supervisor.PushPolicy(..., CmdModify); when
//     the merged table goes empty it clears dp with an empty CmdDelete.
//  4. Feeds the FQDN allow-set (union of every FQDN-anchored rule) to the
//     resolver via Supervisor.SetAllowedFqdns so dp's FQDN→IP table only learns
//     names some active rule references.
//
// SCOPE NOTE (documented residual): dp matches packets to workloads by MAC,
// then walks that MAC's rule table. The agent does not yet expose a stable
// policy-workload→MAC map (the local tap/enforce layers know pod MACs, not the
// stored deployment/workload selector), so every policy's rules are merged into
// one node-level table scoped to this node's active dp MACs. Rules remain
// constrained by their own src/dst IP, port and FQDN selectors, so a rule only
// matches the traffic it targets; what is lost is per-pod isolation of the
// *table*. Pushing each policy separately is not safe until policies can be
// scoped to disjoint MAC sets: PushPolicy(CmdModify) replaces the table for its
// MAC set, so two policies sharing a MAC would clobber each other. Per-workload
// scoping needs a workload→MAC resolver wired through the tap/enforce providers.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// pushedPolicyRIDs is the set of nonzero network-policy rule ids (DPPolicyID)
// this agent last programmed into dp. The DLP/WAF sync reads it (loadPolicyRIDs)
// and binds these ids into ep->{dlp,waf}_rid_map so sessions matching a positive
// pushed rule are DLP/WAF-scanned, not just default (id 0) sessions — dp gates
// detection on the session's policy id (dpi_search.c OUTSIDE branch). A
// process-wide singleton because there is exactly one policy sync and one DLP
// sync worker per agent; the pointer swap is atomic so the reader never tears.
var pushedPolicyRIDs atomic.Pointer[[]uint32]

// storePolicyRIDs publishes the current pushed rule-id set (nil when the policy
// table is empty). loadPolicyRIDs reads it; a nil pointer yields nil.
func storePolicyRIDs(ids []uint32) { pushedPolicyRIDs.Store(&ids) }

func loadPolicyRIDs() []uint32 {
	if p := pushedPolicyRIDs.Load(); p != nil {
		return *p
	}
	return nil
}

// policyRIDsFromMerged returns the sorted, deduped set of nonzero rule ids in a
// merged workload policy — the sess->policy_desc.id values dp stamps on sessions
// that match a positive pushed rule. id 0 (the default east-west session) is
// bound separately by ConfigureDetector, so it is excluded here.
func policyRIDsFromMerged(p *dp.WorkloadPolicy) []uint32 {
	if p == nil {
		return nil
	}
	seen := map[uint32]struct{}{}
	var out []uint32
	for _, r := range p.Rules {
		if r == nil || r.ID == 0 {
			continue
		}
		if _, ok := seen[r.ID]; ok {
			continue
		}
		seen[r.ID] = struct{}{}
		out = append(out, r.ID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// RuntimePolicySyncConfig — knobs for the worker.
type RuntimePolicySyncConfig struct {
	APIBaseURL string
	Token      string
	ClusterID  string
	Interval   time.Duration
	HTTPClient *http.Client
	Logger     *slog.Logger
	DPSup      *dp.Supervisor
}

// runtimePolicyWire mirrors the JSON shape of handler/runtime.RuntimePolicy.
// Re-declared here (like dlp_sync.go's dlpRuleWire) so the agent doesn't pull
// in the server-side dependency graph. Only the fields the datapath needs are
// kept; rules decode straight into the dp.PolicyRule wire type.
type runtimePolicyWire struct {
	ID         string           `json:"id"`
	DPPolicyID int64            `json:"dp_policy_id"`
	Workload   string           `json:"workload"`
	Mode       string           `json:"mode"` // monitor | enforce | disabled
	DefAction  uint8            `json:"def_action"`
	ApplyDir   int              `json:"apply_dir"`
	Rules      []*dp.PolicyRule `json:"rules"`
	Version    int64            `json:"version"`
}

type runtimePolicyBundle struct {
	Policies []runtimePolicyWire `json:"policies"`
}

// RuntimePolicySyncWorker periodically pulls runtime_policies and programs dp.
type RuntimePolicySyncWorker struct {
	cfg RuntimePolicySyncConfig

	mu             sync.Mutex
	fingerprint    string
	pushedNonEmpty bool
	// lastGen is the dp lifecycle generation this worker last programmed
	// against. A generation change means dp was restarted and lost its policy
	// table, so we force a re-push even when the merged-policy fingerprint is
	// unchanged. lastGen advances only after a successful program/clear.
	lastGen uint64

	syncs    atomic.Uint64
	pushes   atomic.Uint64
	deletes  atomic.Uint64
	errors   atomic.Uint64
	lastSync atomic.Int64
}

func NewRuntimePolicySyncWorker(cfg RuntimePolicySyncConfig) *RuntimePolicySyncWorker {
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &RuntimePolicySyncWorker{cfg: cfg}
}

// Run blocks until ctx is canceled, syncing on every Interval tick. First sync
// is delayed so dp + taps have time to come up (an empty TapMACs push is wasted
// work).
func (w *RuntimePolicySyncWorker) Run(ctx context.Context) {
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
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

// SyncOnce performs one fetch + program pass. Public for tests + manual trigger.
func (w *RuntimePolicySyncWorker) SyncOnce(ctx context.Context) {
	w.syncs.Add(1)
	w.lastSync.Store(time.Now().Unix())
	if strings.TrimSpace(w.cfg.ClusterID) == "" || w.cfg.DPSup == nil {
		return
	}
	policies, err := w.fetch(ctx)
	if err != nil {
		w.errors.Add(1)
		w.cfg.Logger.Warn("runtime policy sync: fetch failed", slog.String("err", err.Error()))
		return
	}

	// Scope the merged table to tap MACs UNION inline-enforce MACs. An inline
	// (NFQUEUE) workload is skipped by the tap reconciler, so its verdict-capable
	// ep is absent from TapMACs; without unioning EnforceMACs the policy table
	// never reaches it and dp default-allows the very workload we put inline.
	merged := buildMergedWorkloadPolicy(policies, unionMACs(w.cfg.DPSup.TapMACs(), w.cfg.DPSup.EnforceMACs()))

	// Feed the FQDN allow-set every successful sync (cheap, idempotent) so the
	// resolver only learns IPs for names an active rule references. This is the
	// production caller of SetAllowedFqdns; the resolver's reconcile loop + the
	// DNS snoop (see dns_snoop) supply the actual IPs.
	w.cfg.DPSup.SetAllowedFqdns(dp.FqdnAllowSet(merged))

	// Readiness + restart gate for the dp policy push below. SetAllowedFqdns
	// above is resolver state (survives dp restarts) so it stays ungated; only
	// the PushPolicy write into the dp process is gated. Skip until the current
	// dp instance has answered a keepalive; a generation change forces a re-push
	// even when the merged-policy fingerprint is unchanged (restarted dp lost
	// its table).
	gen := w.cfg.DPSup.Generation()
	w.mu.Lock()
	skip, force := dpSyncGate(w.cfg.DPSup.Ready(), gen, w.lastGen)
	w.mu.Unlock()
	if skip {
		return
	}

	fp := fingerprintWorkloadPolicy(merged)
	w.mu.Lock()
	changed := fp != w.fingerprint
	prevNonEmpty := w.pushedNonEmpty
	w.mu.Unlock()
	if !changed && !force {
		return
	}

	if len(merged.Rules) == 0 {
		// Nothing to enforce now. Only clear dp if we previously installed a
		// non-empty table (CmdDelete on removal); otherwise there's nothing to
		// undo and we just record the new fingerprint.
		if prevNonEmpty {
			if err := w.cfg.DPSup.PushPolicy(merged, dp.CmdDelete); err != nil {
				w.errors.Add(1)
				w.cfg.Logger.Warn("runtime policy sync: clear failed", slog.String("err", err.Error()))
				return
			}
			w.deletes.Add(1)
			w.cfg.Logger.Info("runtime policy sync: cleared dp policy table")
		}
		// No positive rules in dp now → the DLP/WAF sync should bind only id 0.
		storePolicyRIDs(nil)
		w.mu.Lock()
		w.fingerprint = fp
		w.pushedNonEmpty = false
		w.lastGen = gen
		w.mu.Unlock()
		return
	}

	// NET-ICMP-47: arm dp's ICMP policy engine when — and only when — a pushed rule
	// actually targets ICMP. Off by default, dp blanket-allows ICMP and IPProtoAny rules
	// cover TCP+UDP only; enabling it lets IPProtoICMP rules bite. Sent with the (gated)
	// push so it re-asserts on rule change + dp restart. dp holds the flag globally.
	if err := w.cfg.DPSup.SetICMPPolicy(mergedHasICMP(merged)); err != nil {
		w.cfg.Logger.Debug("runtime policy sync: SetICMPPolicy", slog.String("err", err.Error()))
	}
	if err := w.cfg.DPSup.PushPolicy(merged, dp.CmdModify); err != nil {
		w.errors.Add(1)
		w.cfg.Logger.Warn("runtime policy sync: push failed", slog.String("err", err.Error()))
		return
	}
	// Publish the nonzero policy rule ids now live in dp so the DLP/WAF sync binds
	// them into ep->{dlp,waf}_rid_map (positive-policy sessions get scanned too).
	storePolicyRIDs(policyRIDsFromMerged(merged))
	w.pushes.Add(1)
	w.mu.Lock()
	w.fingerprint = fp
	w.pushedNonEmpty = true
	w.lastGen = gen
	w.mu.Unlock()
	w.cfg.Logger.Info("runtime policy sync: programmed dp",
		slog.Int("rules", len(merged.Rules)),
		slog.Int("macs", len(merged.MACs)),
		slog.Int("policies", len(policies)))
}

// buildMergedWorkloadPolicy folds every non-disabled policy into one node-level
// WorkloadPolicy. Mode mapping is applied per source policy: monitor demotes
// every deny → violate (logged, not dropped); enforce keeps deny; disabled
// contributes no rules. Each rule is stamped with its policy's dp_policy_id so
// the wire PolicyRule.ID echoes back through DPMsgConnect.PolicyId. Mirrors
// handler/runtime.RuntimePolicy.ToWorkloadPolicy, kept in sync by shape.
// mergedHasICMP reports whether any rule in the merged policy targets ICMP, so the
// caller arms dp's ICMP policy engine only when it's actually needed (NET-ICMP-47).
func mergedHasICMP(p *dp.WorkloadPolicy) bool {
	if p == nil {
		return false
	}
	for _, r := range p.Rules {
		if r != nil && r.IPProto == dp.IPProtoICMP {
			return true
		}
	}
	return false
}

// unionMACs merges two MAC lists, de-duplicated, preserving order (a first).
func unionMACs(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, m := range list {
			if m == "" || seen[m] {
				continue
			}
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

func buildMergedWorkloadPolicy(policies []runtimePolicyWire, macs []string) *dp.WorkloadPolicy {
	out := &dp.WorkloadPolicy{
		WorkloadID: "node",
		Mode:       "enforce",
		DefAction:  mergedDefaultAction(policies),
		ApplyDir:   dp.ApplyDirBoth,
		MACs:       macs,
	}
	for _, p := range policies {
		if p.Mode == "disabled" {
			continue
		}
		monitor := p.Mode == "monitor"
		var wireID uint32
		if p.DPPolicyID > 0 {
			wireID = uint32(p.DPPolicyID)
		}
		for _, r := range p.Rules {
			if r == nil {
				continue
			}
			rc := *r
			if monitor && rc.Action == dp.PolicyActionDeny {
				rc.Action = dp.PolicyActionViolate
			}
			if wireID > 0 {
				rc.ID = wireID
			}
			out.Rules = append(out.Rules, &rc)
		}
	}
	return out
}

func mergedDefaultAction(policies []runtimePolicyWire) uint8 {
	out := uint8(dp.PolicyActionAllow)
	for _, p := range policies {
		if p.Mode == "disabled" {
			continue
		}
		act := policyDefaultAction(p)
		if policyActionRank(act) > policyActionRank(out) {
			out = act
		}
	}
	return out
}

func policyDefaultAction(p runtimePolicyWire) uint8 {
	act := p.DefAction
	if act == 0 {
		// Older test fixtures and early agents omitted def_action. Treat the zero
		// wire value as the historic allow default instead of sending OPEN by accident.
		act = dp.PolicyActionAllow
	}
	if p.Mode == "monitor" && act == dp.PolicyActionDeny {
		return dp.PolicyActionViolate
	}
	return act
}

func policyActionRank(action uint8) int {
	switch action {
	case dp.PolicyActionDeny:
		return 3
	case dp.PolicyActionViolate:
		return 2
	case dp.PolicyActionLearn:
		return 1
	default:
		return 0
	}
}

// fingerprintWorkloadPolicy is a stable hash of the parts that, if changed,
// require a re-push: the MAC scope and every rule's match + action. Used to skip
// redundant dp writes.
func fingerprintWorkloadPolicy(p *dp.WorkloadPolicy) string {
	h := sha256.New()
	macs := append([]string(nil), p.MACs...)
	sort.Strings(macs)
	for _, m := range macs {
		_, _ = h.Write([]byte(m))
		_, _ = h.Write([]byte{0})
	}
	_, _ = h.Write([]byte{p.DefAction})
	var dir [8]byte
	binary.BigEndian.PutUint64(dir[:], uint64(p.ApplyDir))
	_, _ = h.Write(dir[:])
	for _, r := range p.Rules {
		if r == nil {
			continue
		}
		var idbuf [4]byte
		binary.BigEndian.PutUint32(idbuf[:], r.ID)
		_, _ = h.Write(idbuf[:])
		_, _ = h.Write([]byte(r.SrcIP))
		_, _ = h.Write([]byte(r.DstIP))
		_, _ = h.Write([]byte(r.SrcIPR))
		_, _ = h.Write([]byte(r.DstIPR))
		var pp [4]byte
		binary.BigEndian.PutUint16(pp[0:2], r.Port)
		binary.BigEndian.PutUint16(pp[2:4], r.PortR)
		_, _ = h.Write(pp[:])
		_, _ = h.Write([]byte{r.IPProto, r.Action})
		if r.Ingress {
			_, _ = h.Write([]byte{1})
		} else {
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(r.Fqdn))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (w *RuntimePolicySyncWorker) fetch(ctx context.Context) ([]runtimePolicyWire, error) {
	url := strings.TrimRight(w.cfg.APIBaseURL, "/") +
		"/api/v1/runtime/policies:bundle?cluster_id=" + w.cfg.ClusterID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.cfg.Token)
	resp, err := w.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server %d", resp.StatusCode)
	}
	var out runtimePolicyBundle
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return out.Policies, nil
}

// RuntimePolicySyncStats — telemetry.
type RuntimePolicySyncStats struct {
	Syncs    uint64
	Pushes   uint64
	Deletes  uint64
	Errors   uint64
	LastSync int64
}

func (w *RuntimePolicySyncWorker) Snapshot() RuntimePolicySyncStats {
	return RuntimePolicySyncStats{
		Syncs:    w.syncs.Load(),
		Pushes:   w.pushes.Load(),
		Deletes:  w.deletes.Load(),
		Errors:   w.errors.Load(),
		LastSync: w.lastSync.Load(),
	}
}
