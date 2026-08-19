// Wave B2 + B3: server-side policy evaluator.
//
// dp's policy engine is the authoritative matcher (it's the one running
// against live traffic), but we need a Go-side approximation that lets the
// UI answer:
//
//   - "What would this candidate policy drop if we promoted it?" (B2)
//   - "What does this saved policy currently match?" (B3 simulate)
//
// We don't need bit-perfect parity with dp. The bar is "close enough to
// spot bad rules before they hit the kernel." Concretely we model:
//
//   - Direction (ingress / egress) — picked from the flow's src/dst
//     workload (workload-side is the constellation pod; the other end is
//     external/cluster/<ip> or another workload).
//   - 5-tuple — src/dst IP + port + proto.
//   - IP CIDR / range — rule.SIP/DIP optionally widened by SIPR/DIPR
//     (NeuVector's range form: low/high pair).
//   - Port range — rule.Port plus optional rule.PortR.
//   - L7 — rule.Apps[] matches against flow.application_id (set by dp's
//     DPI parsers; 0 means unknown).
//
// Walking rules in order, first match wins. If no rule matches we return
// the policy's def_action. Mirrors dp's flat-list evaluation.
package runtime

import (
	"encoding/json"
	"net"
	"strings"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// EvaluatedFlow is the minimum shape the evaluator needs from a flow row.
// Maps onto network_flows columns + the agent's wire shape one-to-one.
type EvaluatedFlow struct {
	SrcWorkload string
	DstWorkload string
	SrcAddr     string // IPv4/IPv6 in canonical string form (Go net.IP roundtrip)
	DstAddr     string
	SrcPort     int
	DstPort     int
	Protocol    string // "tcp" | "udp" | ...
	L7Protocol  string
	Application int32 // dp APP_* id; 0 = unknown
	// Workload is the policy-target workload's identity ("<ns>/<deployment>").
	// Used to pick which side of the flow is "us" so direction maps correctly.
	Workload string
}

// EvalAction is the verdict bucket each flow falls into.
type EvalAction string

const (
	EvalActionAllow   EvalAction = "allow"
	EvalActionMonitor EvalAction = "monitor" // PolicyActionViolate (logged-only)
	EvalActionDeny    EvalAction = "deny"
	EvalActionDefault EvalAction = "default" // matched via def_action fallback
)

// evalActionForDP translates dp's numeric Action codes to the verdict
// vocabulary the UI uses. Demoted-by-monitor-mode rules show as "monitor"
// regardless of stored Action, since that's what dp would actually do.
func evalActionForDP(action uint8) EvalAction {
	switch action {
	case dp.PolicyActionAllow,
		dp.PolicyActionLearn,
		dp.PolicyActionOpen,
		dp.PolicyActionCheckVH,
		dp.PolicyActionCheckNbe,
		dp.PolicyActionCheckApp:
		return EvalActionAllow
	case dp.PolicyActionViolate:
		return EvalActionMonitor
	case dp.PolicyActionDeny:
		return EvalActionDeny
	default:
		return EvalActionAllow
	}
}

// EvaluateFlow walks rules in order and returns the verdict.  If no rule
// matches, returns the def_action mapped via evalActionForDP and a flag
// indicating the default was used (UI can render this differently — "no
// rule matched").  honorMonitorDemote=true rewrites deny→monitor in the
// same way ToWorkloadPolicy does for monitor-mode policies, so the eval
// shows what would actually be enforced rather than the raw rule action.
func EvaluateFlow(rules []*dp.PolicyRule, defAction uint8, honorMonitorDemote bool, f EvaluatedFlow) (EvalAction, bool) {
	for _, r := range rules {
		if !ruleMatches(r, f) {
			continue
		}
		act := r.Action
		if honorMonitorDemote && act == dp.PolicyActionDeny {
			act = dp.PolicyActionViolate
		}
		return evalActionForDP(act), false
	}
	return evalActionForDP(defAction), true
}

// ruleMatches encodes the dp matcher subset we care about for simulation.
// Each predicate short-circuits: any mismatched field disqualifies the rule.
func ruleMatches(r *dp.PolicyRule, f EvaluatedFlow) bool {
	// Direction. PolicyRule.Ingress=true means "the workload is the server".
	// Heuristic from the agent: the workload appears as DstWorkload for
	// ingress flows, SrcWorkload for egress. Two simple matches.
	if r.Ingress {
		if f.Workload != "" && f.DstWorkload != f.Workload {
			return false
		}
	} else {
		if f.Workload != "" && f.SrcWorkload != f.Workload {
			return false
		}
	}
	// Protocol (0 in rule = any).
	if r.IPProto != 0 && !protoMatches(int(r.IPProto), f.Protocol) {
		return false
	}
	// Port. Rule.Port = 0 means "any". With Port + PortR set, it's a range.
	if r.Port != 0 {
		if !portMatches(r.Port, r.PortR, f.DstPort) {
			return false
		}
	}
	// IP / IP range. Empty rule IPs = any.
	if !ipMatches(r.SrcIP, r.SrcIPR, f.SrcAddr) {
		return false
	}
	if !ipMatches(r.DstIP, r.DstIPR, f.DstAddr) {
		return false
	}
	// L7 app (rule.Apps[] is OR-of-app-ids; 0 = match-any).
	if len(r.Apps) > 0 {
		anyMatch := false
		for _, a := range r.Apps {
			if a.App == 0 || int32(a.App) == f.Application {
				anyMatch = true
				break
			}
		}
		if !anyMatch {
			return false
		}
	}
	return true
}

// protoMatches: int proto code (6=TCP, 17=UDP) vs flow's lowercase string.
func protoMatches(code int, name string) bool {
	switch strings.ToLower(name) {
	case "tcp":
		return code == 6
	case "udp":
		return code == 17
	case "icmp":
		return code == 1
	case "icmpv6":
		return code == 58
	}
	return false
}

func portMatches(low, high uint16, flowPort int) bool {
	if high == 0 || high < low {
		return int(low) == flowPort
	}
	return flowPort >= int(low) && flowPort <= int(high)
}

// ipMatches: a rule IP of nil/0.0.0.0/:: means "any". A rule with low+high
// is a range; without high it's a single IP. Both v4 and v6 OK because we
// compare via net.IP byte slices.
func ipMatches(low, high net.IP, flowAddr string) bool {
	if isUnspecifiedRuleIP(low) {
		return true
	}
	target := net.ParseIP(flowAddr)
	if target == nil {
		return false
	}
	target = canonicalize(target)
	lo := canonicalize(low)
	if isUnspecifiedRuleIP(high) {
		return lo.Equal(target)
	}
	hi := canonicalize(high)
	return bytesGE(target, lo) && bytesGE(hi, target)
}

func isUnspecifiedRuleIP(ip net.IP) bool {
	if ip == nil || len(ip) == 0 {
		return true
	}
	if ip.IsUnspecified() {
		return true
	}
	// Some callers pass net.IP(""). Treat as any.
	for _, b := range ip {
		if b != 0 {
			return false
		}
	}
	return true
}

func canonicalize(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// bytesGE returns a >= b for equal-length byte slices.
func bytesGE(a, b net.IP) bool {
	if len(a) != len(b) {
		// Different families; force IPv4-mapped form so we can compare.
		a4, b4 := a.To4(), b.To4()
		if a4 != nil && b4 != nil {
			a, b = a4, b4
		}
	}
	for i := range a {
		switch {
		case a[i] > b[i]:
			return true
		case a[i] < b[i]:
			return false
		}
	}
	return true
}

// MatchStats is the count-by-verdict shape returned by both /match-stats
// (existing policy) and /simulate (candidate policy).
type MatchStats struct {
	WindowHours int                      `json:"window_hours"`
	Workload    string                   `json:"workload"`
	Total       int                      `json:"total"`
	Allow       int                      `json:"allow"`
	Monitor     int                      `json:"monitor"`
	Deny        int                      `json:"deny"`
	Default     int                      `json:"default"`
	Samples     map[string][]MatchSample `json:"samples,omitempty"` // verdict → up to 10 flows
}

// MatchSample is a thin display shape per flow — enough for the UI to
// say "the rule would drop these specific connections" without
// re-fetching the full row.
type MatchSample struct {
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	DstPort  int    `json:"dst_port"`
	Proto    string `json:"protocol"`
	L7       string `json:"l7_protocol,omitempty"`
	Bytes    int64  `json:"bytes"`
	LastSeen string `json:"last_seen_at"`
}

// EvaluateBatch runs the evaluator over a slice of flows and returns
// counts + per-bucket samples (cap 10 per verdict so the JSON stays small).
func EvaluateBatch(rules []*dp.PolicyRule, defAction uint8, honorMonitorDemote bool, workload string, flows []EvaluatedFlow, raw []*FlowSampleRow) MatchStats {
	out := MatchStats{
		Workload: workload,
		Samples:  map[string][]MatchSample{},
	}
	for i, f := range flows {
		act, isDefault := EvaluateFlow(rules, defAction, honorMonitorDemote, f)
		out.Total++
		switch act {
		case EvalActionAllow:
			out.Allow++
		case EvalActionMonitor:
			out.Monitor++
		case EvalActionDeny:
			out.Deny++
		}
		if isDefault {
			out.Default++
		}
		// Attach up to 10 samples per verdict bucket. The raw slice is the
		// source of truth for display fields — it has columns the evaluator
		// doesn't need but the UI does (bytes, last_seen_at).
		bucket := string(act)
		if len(out.Samples[bucket]) < 10 && raw != nil && i < len(raw) {
			out.Samples[bucket] = append(out.Samples[bucket], rawToSample(raw[i]))
		}
	}
	return out
}

// FlowSampleRow is the raw shape pulled from network_flows for samples.
// Separate from EvaluatedFlow because the evaluator doesn't need
// display-only fields.
type FlowSampleRow struct {
	Src        string
	Dst        string
	SrcAddr    string
	DstAddr    string
	SrcPort    int
	DstPort    int
	Protocol   string
	L7Protocol string
	Bytes      int64
	LastSeenAt string
}

func rawToSample(r *FlowSampleRow) MatchSample {
	return MatchSample{
		Src: r.Src, Dst: r.Dst, DstPort: r.DstPort,
		Proto: r.Protocol, L7: r.L7Protocol,
		Bytes: r.Bytes, LastSeen: r.LastSeenAt,
	}
}

// ParseRulesJSON is a small re-decoder used by simulate's POST body when
// the caller hands in candidate rules as raw JSON.
func ParseRulesJSON(b json.RawMessage) ([]*dp.PolicyRule, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var rules []*dp.PolicyRule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}
