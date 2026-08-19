// Package group implements the NeuVector-style group taxonomy.
//
// A Group is a logical collection of workloads, defined by a set of Criteria entries
// (label key/value with an operator). The package supports three kinds:
//
//	Learned  — auto-synthesized from observed workload metadata after a learning window.
//	            See LearnFromObservations.
//	Ground   — user-defined ground-truth selectors.
//	Federated — synced from a federation master; read-only on joints.
//
// Membership evaluation is pure / in-memory; persistence lives in internal/handler.
package group

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Kind classifies a Group.
type Kind string

const (
	KindLearned   Kind = "learned"
	KindGround    Kind = "ground"
	KindFederated Kind = "federated"
)

// Mode is the policy/profile mode a group runs in, mirroring NeuVector's
// CLUSGroup.PolicyMode/ProfileMode triad: discover (=NV Learn), monitor, protect
// (=NV Enforce).
type Mode string

const (
	ModeDiscover Mode = "discover"
	ModeMonitor  Mode = "monitor"
	ModeProtect  Mode = "protect"
)

func validMode(m Mode) bool {
	switch m {
	case ModeDiscover, ModeMonitor, ModeProtect:
		return true
	}
	return false
}

// Op is the comparator on a Criterion.
type Op string

const (
	OpEq       Op = "eq"
	OpContains Op = "contains"
	OpRegex    Op = "regex"
)

// Criterion is one (key, value, op) match clause on workload metadata.
type Criterion struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Op    Op     `json:"op"`
}

// Group is a named selector.
type Group struct {
	ID          string      `json:"id,omitempty"`
	Name        string      `json:"name"`
	Kind        Kind        `json:"kind"`
	Comment     string      `json:"comment,omitempty"`
	Criteria    []Criterion `json:"criteria"`
	Members     []string    `json:"members,omitempty"`     // workload ids (server-computed from criteria)
	LearnedFrom string      `json:"learned_from,omitempty"` // workload id template for learned
	CfgType     string      `json:"cfg_type,omitempty"`     // user|learned|fed
	PolicyMode  Mode        `json:"policy_mode,omitempty"`  // discover|monitor|protect
	ProfileMode Mode        `json:"profile_mode,omitempty"` // discover|monitor|protect
}

// ComputeMembers returns the sorted ids of workloads matching this group's
// criteria — the eager equivalent of NeuVector's IsGroupMember/groupWorkloadJoin
// cache. Recomputed on group write AND by the live-membership reconcile
// (internal/handler/runtime.GroupMembershipReconciler), which re-evaluates every
// group against current deployments so a rule authored against a group follows
// future members like NeuVector's groupWorkloadJoin/Leave.
func (g *Group) ComputeMembers(wls []Workload) []string {
	out := make([]string, 0, len(wls))
	for i := range wls {
		if g.Matches(&wls[i]) {
			out = append(out, wls[i].ID)
		}
	}
	sort.Strings(out)
	return out
}

// MembersChanged reports whether newMembers differs (as a set) from the group's
// currently stored Members. Ordering and duplicates are ignored so a re-sort of
// the same ids never counts as a change. The live-membership reconcile uses this
// to decide whether a group's members need re-persisting and its group→group
// rules re-expanding.
func (g *Group) MembersChanged(newMembers []string) bool {
	if len(newMembers) != len(g.Members) {
		return true
	}
	have := make(map[string]struct{}, len(g.Members))
	for _, m := range g.Members {
		have[m] = struct{}{}
	}
	for _, m := range newMembers {
		if _, ok := have[m]; !ok {
			return true
		}
	}
	return false
}

// Workload is the minimal shape membership is evaluated against.
type Workload struct {
	ID        string
	Cluster   string
	Namespace string
	// Service is the workload template (deployment/daemonset) name. It is the
	// per-service bucketing key for the learner — mirroring NeuVector's
	// nv.<service> granularity. Empty means "bucket by namespace only" (the
	// original coarse behaviour). Not consulted by Matches.
	Service string
	Labels  map[string]string
}

// Matches returns true iff every criterion matches `wl`.
func (g *Group) Matches(wl *Workload) bool {
	for _, c := range g.Criteria {
		if !criterionMatches(c, wl) {
			return false
		}
	}
	return len(g.Criteria) > 0
}

func criterionMatches(c Criterion, wl *Workload) bool {
	got := workloadField(wl, c.Key)
	switch c.Op {
	case OpEq, "":
		return got == c.Value
	case OpContains:
		return strings.Contains(got, c.Value)
	case OpRegex:
		re, err := regexp.Compile(c.Value)
		if err != nil {
			return false
		}
		return re.MatchString(got)
	}
	return false
}

func workloadField(wl *Workload, key string) string {
	switch key {
	case "cluster":
		return wl.Cluster
	case "namespace":
		return wl.Namespace
	case "id":
		return wl.ID
	}
	if strings.HasPrefix(key, "label.") {
		return wl.Labels[strings.TrimPrefix(key, "label.")]
	}
	return wl.Labels[key]
}

// Observation is one observed workload sample feeding the learner.
type Observation struct {
	Workload Workload
	At       time.Time
}

// LearnFromObservations buckets observations by (cluster, namespace, service) and
// produces learned Group candidates for any bucket of >= minMembers workloads
// observed at least within `window` from the last observation. When Workload.Service
// is set it emits one group PER SERVICE (namespace + workload template) — matching
// NeuVector's nv.<service> granularity; when it is empty the bucket collapses to the
// namespace, preserving the original coarse behaviour. This is intentionally simple —
// the goal is parity with NeuVector's "auto-learn on first sight + promote at window
// end" flow; richer ML clustering can be added later.
func LearnFromObservations(obs []Observation, window time.Duration, minMembers int) []Group {
	if minMembers <= 0 {
		minMembers = 1
	}
	type bucket struct {
		cluster   string
		namespace string
		service   string
		members   map[string]struct{}
		labels    map[string]map[string]int // key -> value -> count
		last      time.Time
	}
	buckets := map[string]*bucket{}
	for _, o := range obs {
		key := o.Workload.Cluster + "\x00" + o.Workload.Namespace + "\x00" + o.Workload.Service
		b, ok := buckets[key]
		if !ok {
			b = &bucket{
				cluster: o.Workload.Cluster, namespace: o.Workload.Namespace, service: o.Workload.Service,
				members: map[string]struct{}{}, labels: map[string]map[string]int{},
			}
			buckets[key] = b
		}
		b.members[o.Workload.ID] = struct{}{}
		for k, v := range o.Workload.Labels {
			if b.labels[k] == nil {
				b.labels[k] = map[string]int{}
			}
			b.labels[k][v]++
		}
		if o.At.After(b.last) {
			b.last = o.At
		}
	}
	out := []Group{}
	now := time.Now()
	for _, b := range buckets {
		if len(b.members) < minMembers {
			continue
		}
		if window > 0 && now.Sub(b.last) > window {
			// Observations too stale — skip.
			continue
		}
		// Find the most-common label key/value as the seed criterion. Iterate in
		// sorted order so ties (e.g. a single-member bucket where every label has
		// count 1) resolve deterministically instead of by random map order — the
		// synthesizer re-runs each tick and must produce stable criteria.
		var bestKey, bestVal string
		bestCount := 0
		labelKeys := make([]string, 0, len(b.labels))
		for k := range b.labels {
			labelKeys = append(labelKeys, k)
		}
		sort.Strings(labelKeys)
		for _, k := range labelKeys {
			vmap := b.labels[k]
			vals := make([]string, 0, len(vmap))
			for v := range vmap {
				vals = append(vals, v)
			}
			sort.Strings(vals)
			for _, v := range vals {
				if vmap[v] > bestCount {
					bestCount = vmap[v]
					bestKey = k
					bestVal = v
				}
			}
		}
		criteria := []Criterion{{Key: "namespace", Value: b.namespace, Op: OpEq}}
		if bestKey != "" {
			criteria = append(criteria, Criterion{Key: "label." + bestKey, Value: bestVal, Op: OpEq})
		}
		members := make([]string, 0, len(b.members))
		for m := range b.members {
			members = append(members, m)
		}
		sort.Strings(members)
		name := "learned-" + b.cluster + "-" + b.namespace
		if b.service != "" {
			name += "-" + b.service
		}
		out = append(out, Group{
			Name:        name,
			Kind:        KindLearned,
			Criteria:    criteria,
			Members:     members,
			LearnedFrom: b.service,
			CfgType:     "learned",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Validate returns an error if g is malformed.
func (g *Group) Validate() error {
	if strings.TrimSpace(g.Name) == "" {
		return fmt.Errorf("group: name required")
	}
	switch g.Kind {
	case KindLearned, KindGround, KindFederated:
	default:
		return fmt.Errorf("group: invalid kind %q", g.Kind)
	}
	// Default empty modes to monitor; reject anything else.
	if g.PolicyMode == "" {
		g.PolicyMode = ModeMonitor
	}
	if g.ProfileMode == "" {
		g.ProfileMode = ModeMonitor
	}
	if !validMode(g.PolicyMode) {
		return fmt.Errorf("group: invalid policy_mode %q", g.PolicyMode)
	}
	if !validMode(g.ProfileMode) {
		return fmt.Errorf("group: invalid profile_mode %q", g.ProfileMode)
	}
	for i, c := range g.Criteria {
		switch c.Op {
		case OpEq, OpContains, OpRegex, "":
		default:
			return fmt.Errorf("group: criterion %d: invalid op %q", i, c.Op)
		}
		if c.Op == OpRegex {
			if _, err := regexp.Compile(c.Value); err != nil {
				return fmt.Errorf("group: criterion %d: bad regex: %w", i, err)
			}
		}
	}
	return nil
}
