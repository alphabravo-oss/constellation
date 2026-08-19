// P2-2: per-rule provenance + non-destructive merge.
//
// dp.PolicyRule is the wire shape dp consumes; it has no room for control-plane
// bookkeeping like "who authored this rule". We model provenance one layer up
// with SourcedRule, which embeds a *dp.PolicyRule and rides an extra `cfg` field
// through the same JSONB `rules` column. Because the field is additive and the
// dp decoder ignores unknown keys, a SourcedRule round-trips cleanly to both the
// stored JSONB (control-plane, keeps cfg) and the agent bundle (decodes into
// plain dp.PolicyRule, drops cfg) with no schema migration.
//
// The point of provenance is non-destructive regeneration: when we re-derive a
// workload's allow-list from freshly observed flows, we must REPLACE the
// learned rules but PRESERVE any rule a human (or a federation master) authored
// by hand. This mirrors NeuVector's CLUSPolicyRule.CfgType (Learned vs
// UserCreated vs FederatedPolicy) merge in controller/cache/learn.go.
package netpolicy

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// CfgType is the provenance of a single network rule.
type CfgType string

const (
	// CfgTypeUser — authored by an operator through the policy editor. Never
	// destroyed by regeneration.
	CfgTypeUser CfgType = "user"
	// CfgTypeLearned — synthesized from observed flows. Replaced wholesale on
	// each regeneration.
	CfgTypeLearned CfgType = "learned"
	// CfgTypeFed — pushed down from a federation master; read-only on joints.
	// Preserved like a user rule on regeneration.
	CfgTypeFed CfgType = "fed"
)

// preserved reports whether a rule of this provenance survives regeneration.
// Anything that is not explicitly learned is preserved — an unknown/empty
// CfgType is treated as user-authored so we never silently drop a rule whose
// origin we cannot prove.
func (c CfgType) preserved() bool { return c != CfgTypeLearned }

// SourcedRule is a dp.PolicyRule tagged with its provenance. The embedded rule
// is a pointer so JSON marshalling promotes its fields to the top level; CfgType
// serialises as an additional `cfg` sibling key.
type SourcedRule struct {
	*dp.PolicyRule
	CfgType CfgType `json:"cfg,omitempty"`
}

// ruleIdentity is the dedupe/conflict key: two rules "are the same edge" when
// they share direction, L4 proto, port, and peer (IP or FQDN). Action/mode are
// deliberately excluded so a user's deny for (tcp/443 → 10.0.0.5) shadows a
// freshly-learned allow for the same edge.
type ruleIdentity struct {
	ingress bool
	proto   uint8
	port    uint16
	portR   uint16
	peer    string
}

func identityOf(r *dp.PolicyRule) ruleIdentity {
	peer := strings.ToLower(strings.TrimSpace(r.Fqdn))
	if peer == "" {
		if r.Ingress && len(r.SrcIP) > 0 {
			peer = r.SrcIP.String()
		} else if !r.Ingress && len(r.DstIP) > 0 {
			peer = r.DstIP.String()
		}
	}
	return ruleIdentity{
		ingress: r.Ingress,
		proto:   r.IPProto,
		port:    r.Port,
		portR:   r.PortR,
		peer:    peer,
	}
}

// Tag stamps a plain dp rule slice with a single provenance, producing
// SourcedRules. Used when we know the whole slice shares one origin (eg. a fresh
// generation is entirely CfgTypeLearned, or an operator's editor submission is
// entirely CfgTypeUser).
func Tag(rules []*dp.PolicyRule, cfg CfgType) []*SourcedRule {
	out := make([]*SourcedRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, &SourcedRule{PolicyRule: r, CfgType: cfg})
	}
	return out
}

// Bare drops provenance, returning the underlying dp rules for the wire path.
func Bare(rules []*SourcedRule) []*dp.PolicyRule {
	out := make([]*dp.PolicyRule, 0, len(rules))
	for _, r := range rules {
		if r == nil || r.PolicyRule == nil {
			continue
		}
		out = append(out, r.PolicyRule)
	}
	return out
}

// DecodeSourced unmarshals a stored JSONB `rules` blob into SourcedRules. Rules
// written before provenance existed (or by the plain dp path) decode with an
// empty CfgType, which merge treats as user-authored (preserved).
func DecodeSourced(raw json.RawMessage) ([]*SourcedRule, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var out []*SourcedRule
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// MergeRules performs the non-destructive regeneration merge. Every preserved
// (user/fed/unknown) rule in `existing` is kept; every learned rule in existing
// is discarded and replaced by `learned`, EXCEPT where a learned rule collides
// with a preserved rule's identity — there the preserved rule wins and the
// duplicate learned rule is dropped. Output ordering is deterministic (preserved
// first in original order, then learned by identity) so the audit diff is stable.
func MergeRules(existing, learned []*SourcedRule) []*SourcedRule {
	out := make([]*SourcedRule, 0, len(existing)+len(learned))
	preserved := map[ruleIdentity]bool{}
	for _, r := range existing {
		if r == nil || r.PolicyRule == nil {
			continue
		}
		if !r.CfgType.preserved() {
			continue // learned rule: drop, the fresh set supersedes it
		}
		if r.CfgType == "" {
			r.CfgType = CfgTypeUser // normalise unknown provenance to user
		}
		preserved[identityOf(r.PolicyRule)] = true
		out = append(out, r)
	}
	fresh := make([]*SourcedRule, 0, len(learned))
	seen := map[ruleIdentity]bool{}
	for _, r := range learned {
		if r == nil || r.PolicyRule == nil {
			continue
		}
		id := identityOf(r.PolicyRule)
		if preserved[id] || seen[id] {
			continue // a user rule shadows this edge, or we already emitted it
		}
		seen[id] = true
		if r.CfgType == "" {
			r.CfgType = CfgTypeLearned
		}
		fresh = append(fresh, r)
	}
	sort.SliceStable(fresh, func(i, j int) bool {
		a, b := identityOf(fresh[i].PolicyRule), identityOf(fresh[j].PolicyRule)
		if a.ingress != b.ingress {
			return a.ingress
		}
		if a.port != b.port {
			return a.port < b.port
		}
		return a.peer < b.peer
	})
	return append(out, fresh...)
}
