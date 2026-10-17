// Runtime policies are programmed only onto exact current pod-generation MACs.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

var pushedPolicyRIDs atomic.Pointer[[]uint32]

func storePolicyRIDs(ids []uint32) { pushedPolicyRIDs.Store(&ids) }

func loadPolicyRIDs() []uint32 {
	if p := pushedPolicyRIDs.Load(); p != nil {
		return *p
	}
	return nil
}

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

type runtimePolicyWire struct {
	ID            string                    `json:"id"`
	DPPolicyID    int64                     `json:"dp_policy_id"`
	Workload      string                    `json:"workload"`
	Namespace     string                    `json:"namespace"`
	BindingStatus string                    `json:"binding_status"`
	PodBindings   []runtimePolicyPodBinding `json:"pod_bindings"`
	Mode          string                    `json:"mode"` // monitor | enforce | disabled
	DefAction     uint8                     `json:"def_action"`
	ApplyDir      int                       `json:"apply_dir"`
	Rules         []*dp.PolicyRule          `json:"rules"`
	Version       int64                     `json:"version"`
}

type runtimePolicyBundle struct {
	ProtocolVersion int                 `json:"protocol_version"`
	ClusterID       string              `json:"cluster_id"`
	SourceComplete  bool                `json:"source_complete"`
	Policies        []runtimePolicyWire `json:"policies"`
}

type runtimePolicyDataplane interface {
	Ready() bool
	Generation() uint64
	PolicyEndpoints() []dp.PolicyEndpoint
	PushEndpointPolicy(*dp.WorkloadPolicy, uint, *dp.PolicyEndpoint, uint64) error
	SetAllowedFqdns([]string)
	SetICMPPolicy(bool) error
}

type RuntimePolicySyncConfig struct {
	APIBaseURL string
	Token      string
	ClusterID  string
	Interval   time.Duration
	HTTPClient *http.Client
	Logger     *slog.Logger
	DPSup      runtimePolicyDataplane
}

type confirmedRuntimePolicy struct {
	Identity    string
	Generation  uint64
	Source      *dp.WorkloadPolicy
	Fingerprint string
	Dirty       bool
	Possible    *dp.WorkloadPolicy
}

type RuntimePolicySyncWorker struct {
	cfg            RuntimePolicySyncConfig
	mu             sync.Mutex
	confirmed      map[string]confirmedRuntimePolicy
	icmpGeneration uint64
	icmpEnabled    bool
	icmpDirty      bool
	syncs          atomic.Uint64
	pushes         atomic.Uint64
	deletes        atomic.Uint64
	errors         atomic.Uint64
	conflicts      atomic.Uint64
	lastSync       atomic.Int64
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
	return &RuntimePolicySyncWorker{cfg: cfg, confirmed: map[string]confirmedRuntimePolicy{}}
}

func (w *RuntimePolicySyncWorker) Run(ctx context.Context) {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			w.SyncOnce(ctx)
			timer.Reset(w.cfg.Interval)
		}
	}
}

// Serialize the complete pass: native policy fragments share one staging handle.
// A malformed/incomplete candidate is rejected before resolver or dataplane writes.
func (w *RuntimePolicySyncWorker) SyncOnce(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.syncs.Add(1)
	w.lastSync.Store(time.Now().Unix())
	if strings.TrimSpace(w.cfg.ClusterID) == "" || w.cfg.DPSup == nil {
		return
	}
	policies, err := w.fetch(ctx)
	if err != nil {
		w.failure("fetch", err)
		return
	}
	plan := buildRuntimePolicyScopePlan(policies, w.cfg.DPSup.PolicyEndpoints())
	if err := validatePolicyFingerprints(plan); err != nil {
		w.failure("candidate", err)
		return
	}
	if ctx.Err() != nil || !w.cfg.DPSup.Ready() {
		return
	}
	gen := w.cfg.DPSup.Generation()
	// Keep the ICMP engine armed for prior/uncertain tables until their removal
	// succeeds. Every other scope receives its historical ICMP allow semantics.
	gate := w.needsICMP(plan, true, gen)
	if !w.setICMP(ctx, gate, gen) {
		return
	}
	w.reconcile(ctx, plan, gen, gate)
	// Once old ICMP tables have actually been cleared/replaced, disabling the
	// global gate is safe. Re-render compatibility rules under the final gate.
	finalGate := w.needsICMP(plan, false, gen)
	if finalGate != gate && w.setICMP(ctx, finalGate, gen) {
		w.reconcile(ctx, plan, gen, finalGate)
	}
	if !w.dispatchCurrent(ctx, gen) {
		return
	}
	w.publishCurrent(buildRuntimePolicyScopePlan(policies, w.cfg.DPSup.PolicyEndpoints()), gen)
}

func (w *RuntimePolicySyncWorker) failure(operation string, err error) {
	w.errors.Add(1)
	w.cfg.Logger.Warn("runtime policy sync: "+operation+" failed", "error", err.Error())
}

func (w *RuntimePolicySyncWorker) setICMP(ctx context.Context, enabled bool, gen uint64) bool {
	if !w.dispatchCurrent(ctx, gen) {
		return false
	}
	if w.icmpGeneration == gen && w.icmpEnabled == enabled && !w.icmpDirty {
		return true
	}
	if err := w.cfg.DPSup.SetICMPPolicy(enabled); err != nil {
		w.icmpDirty = true
		w.failure("ICMP configuration", err)
		return false
	}
	w.icmpGeneration, w.icmpEnabled, w.icmpDirty = gen, enabled, false
	return true
}

func (w *RuntimePolicySyncWorker) needsICMP(plan runtimePolicyScopePlan, includeWanted bool, gen uint64) bool {
	if includeWanted {
		for _, policy := range plan.wanted {
			if mergedHasICMP(policy) {
				return true
			}
		}
	}
	for mac, previous := range w.confirmed {
		if previous.Generation != gen || previous.Identity == "" || previous.Identity != plan.identities[mac] {
			continue
		}
		if mergedHasICMP(previous.Source) || mergedHasICMP(previous.Possible) {
			return true
		}
	}
	return false
}

func (w *RuntimePolicySyncWorker) reconcile(ctx context.Context, plan runtimePolicyScopePlan, gen uint64, icmp bool) {
	// Clear removed/reassigned endpoints before any new workload can receive rules.
	for _, mac := range sortedPolicyMACs(w.confirmed) {
		previous := w.confirmed[mac]
		identity, exists := plan.identities[mac]
		if previous.Generation != gen {
			delete(w.confirmed, mac)
			continue
		}
		if exists && identity == previous.Identity {
			continue
		}
		if !w.dispatchCurrent(ctx, gen) {
			return
		}
		if w.clear(mac, identity, gen, plan.endpoints[mac]) {
			if !exists {
				delete(w.confirmed, mac)
			}
		}
	}
	for _, mac := range sortedPolicyMACs(plan.identities) {
		if !w.dispatchCurrent(ctx, gen) {
			return
		}
		w.reconcileMAC(mac, plan, gen, icmp)
	}
}

func (w *RuntimePolicySyncWorker) reconcileMAC(mac string, plan runtimePolicyScopePlan, gen uint64, icmp bool) {
	identity := plan.identities[mac]
	previous, known := w.confirmed[mac]
	if known && previous.Identity != identity {
		return
	} // Previous scope delete failed.
	wanted := plan.wanted[mac]
	conflict := plan.conflicts[mac] != "" || wanted == nil && previous.Source != nil && plan.blockedWorkloads[previous.Source.WorkloadID]
	if conflict {
		w.conflicts.Add(1)
		w.cfg.Logger.Warn("runtime policy scope unresolved; no candidate applied", "mac", mac)
		if identity != "" && known && previous.Identity == identity {
			wanted = previous.Source
		} else {
			wanted = nil
		}
	}
	if wanted == nil {
		if !known || previous.Source != nil || previous.Dirty {
			w.clear(mac, identity, gen, plan.endpoints[mac])
		}
		return
	}
	policy := scopedICMPPolicy(wanted, icmp)
	fingerprint := fingerprintWorkloadPolicy(policy)
	if known && !previous.Dirty && previous.Fingerprint == fingerprint {
		return
	}
	if err := w.cfg.DPSup.PushEndpointPolicy(policy, dp.CmdModify, plan.endpoints[mac], gen); err != nil {
		previous.Dirty, previous.Possible = true, wanted
		if !known {
			previous.Identity, previous.Generation = identity, gen
		}
		w.confirmed[mac] = previous
		w.failure("scoped policy submission", err)
		return
	}
	w.confirmed[mac] = confirmedRuntimePolicy{Identity: identity, Generation: gen, Source: wanted, Fingerprint: fingerprint}
	w.pushes.Add(1)
}

func (w *RuntimePolicySyncWorker) dispatchCurrent(ctx context.Context, gen uint64) bool {
	if ctx.Err() != nil || !w.cfg.DPSup.Ready() || w.cfg.DPSup.Generation() != gen {
		return false
	}
	return true
}

func (w *RuntimePolicySyncWorker) clear(mac, identity string, gen uint64, endpoint *dp.PolicyEndpoint) bool {
	previous := w.confirmed[mac]
	if err := w.cfg.DPSup.PushEndpointPolicy(&dp.WorkloadPolicy{MACs: []string{mac}}, dp.CmdDelete, endpoint, gen); err != nil {
		previous.Dirty = true
		if previous.Generation == 0 {
			previous.Identity, previous.Generation = identity, gen
		}
		w.confirmed[mac] = previous
		w.failure("scoped policy removal", err)
		return false
	}
	w.confirmed[mac] = confirmedRuntimePolicy{Identity: identity, Generation: gen}
	w.deletes.Add(1)
	return true
}

func (w *RuntimePolicySyncWorker) publishCurrent(plan runtimePolicyScopePlan, gen uint64) {
	names := map[string]bool{}
	ids := map[uint32]bool{}
	for mac, previous := range w.confirmed {
		if previous.Generation != gen || previous.Identity == "" || previous.Identity != plan.identities[mac] {
			continue
		}
		for _, policy := range []*dp.WorkloadPolicy{previous.Source, previous.Possible} {
			if policy == nil {
				continue
			}
			for _, id := range policyRIDsFromMerged(policy) {
				ids[id] = true
			}
		}
		if previous.Source != nil {
			for _, name := range dp.FqdnAllowSet(previous.Source) {
				names[name] = true
			}
		}
	}
	var ridSet []uint32
	for id := range ids {
		ridSet = append(ridSet, id)
	}
	sort.Slice(ridSet, func(i, j int) bool { return ridSet[i] < ridSet[j] })
	storePolicyRIDs(ridSet)
	w.cfg.DPSup.SetAllowedFqdns(sortedPolicyMACs(names))
}

func fingerprintWorkloadPolicy(policy *dp.WorkloadPolicy) string {
	if policy == nil {
		return ""
	}
	copy := *policy
	copy.MACs = append([]string(nil), policy.MACs...)
	sort.Strings(copy.MACs)
	encoded, err := json.Marshal(copy)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func (w *RuntimePolicySyncWorker) fetch(ctx context.Context) ([]runtimePolicyWire, error) {
	endpoint := strings.TrimRight(w.cfg.APIBaseURL, "/") + "/api/v1/runtime/policies:bundle?" + url.Values{"cluster_id": {w.cfg.ClusterID}, "protocol": {"2"}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.cfg.Token)
	client := *w.cfg.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.Join(fmt.Errorf("server %d", response.StatusCode), response.Body.Close())
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 16<<20+1))
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		return nil, err
	}
	if len(body) > 16<<20 {
		return nil, errors.New("runtime policy bundle exceeds size limit")
	}
	var bundle runtimePolicyBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return nil, err
	}
	if err := validateRuntimePolicyBundle(&bundle, w.cfg.ClusterID); err != nil {
		return nil, err
	}
	return bundle.Policies, nil
}

type RuntimePolicySyncStats struct {
	Syncs         uint64
	Pushes        uint64
	Deletes       uint64
	Errors        uint64
	Conflicts     uint64
	UncertainMACs int
	LastSync      int64
}

func (w *RuntimePolicySyncWorker) Snapshot() RuntimePolicySyncStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	uncertain := 0
	for _, scope := range w.confirmed {
		if scope.Dirty {
			uncertain++
		}
	}
	return RuntimePolicySyncStats{Syncs: w.syncs.Load(), Pushes: w.pushes.Load(), Deletes: w.deletes.Load(), Errors: w.errors.Load(), Conflicts: w.conflicts.Load(), UncertainMACs: uncertain, LastSync: w.lastSync.Load()}
}
