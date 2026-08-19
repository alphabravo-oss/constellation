// B6: cross-namespace network boundary enforcement (NBE).
//
// Pure decision logic modelling NeuVector's per-domain RESTDomain.Nbe flag
// (controller/api/apis.go). NBE is the coarse "each namespace is an isolation
// domain" guardrail: a flow whose source and destination live in different
// namespaces crosses a boundary and, depending on the destination namespace's
// NBE mode, is flagged (observe) or flagged-and-denied (protect).
//
// The decision here is deliberately free of DB/HTTP concerns so it can be
// unit-tested and reused by both the flow-ingest/eval path (this subsystem)
// and the runtime policy-bundle builder.
package netpolicy

import "strings"

// NBEMode is a namespace's cross-namespace boundary posture.
type NBEMode string

const (
	// NBEOff — the feature is disabled for the namespace (also the meaning of
	// "no row" in netpolicy_nbe_settings). Cross-namespace flows are not
	// flagged. This is the default so an untouched cluster is unchanged.
	NBEOff NBEMode = "off"
	// NBEObserve — cross-namespace flows are flagged (Flagged==true) but
	// allowed. Safe rollout default for a freshly-enabled namespace.
	NBEObserve NBEMode = "observe"
	// NBEProtect — cross-namespace flows are flagged AND denied.
	NBEProtect NBEMode = "protect"
)

// Valid reports whether m is a recognized mode.
func (m NBEMode) Valid() bool {
	switch m {
	case NBEOff, NBEObserve, NBEProtect:
		return true
	}
	return false
}

// NBEDecision is the outcome of evaluating one flow against a namespace's NBE
// mode.
type NBEDecision struct {
	// CrossNamespace is true when src and dst are in different, in-cluster
	// namespaces (both known, neither external/system-exempt).
	CrossNamespace bool
	// Flagged is true when the flow crosses a boundary AND NBE is enabled
	// (observe or protect) for the destination namespace. Corresponds to the
	// nbe=true marker NeuVector stamps on the connection.
	Flagged bool
	// Deny is true when the flow must be denied — only under protect, and only
	// for a genuinely cross-namespace flow. Never true by default.
	Deny bool
}

// nbeExemptNamespace lists namespaces whose flows never count as a boundary
// crossing: the cluster's own control-plane / DNS / observability plumbing must
// reach every namespace, and blocking it would break the cluster. Mirrors
// NeuVector treating platform namespaces as always-reachable.
func nbeExemptNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	// External/off-cluster peers are surfaced with a synthetic "external"
	// bucket (see network_flows ingest); they are not a namespace at all, so
	// NBE — which is about namespace-to-namespace isolation — does not apply.
	if ns == "" || ns == "external" || strings.HasPrefix(ns, "external/") {
		return true
	}
	return false
}

// EvaluateNBE decides whether a src->dst flow crosses a namespace boundary and,
// given the destination namespace's NBE mode, whether it should be flagged
// and/or denied. Both namespaces are the pod's namespace ("<ns>" from a
// "<ns>/<workload>" identity).
//
// Guarantees the safety invariant: Deny can only be true when mode==protect and
// the flow is a real cross-namespace crossing. For mode==off or any same-/
// exempt-namespace flow the zero decision (no flag, no deny) is returned.
func EvaluateNBE(srcNS, dstNS string, mode NBEMode) NBEDecision {
	cross := srcNS != dstNS &&
		!nbeExemptNamespace(srcNS) &&
		!nbeExemptNamespace(dstNS)
	if !cross {
		return NBEDecision{}
	}
	switch mode {
	case NBEObserve:
		return NBEDecision{CrossNamespace: true, Flagged: true}
	case NBEProtect:
		return NBEDecision{CrossNamespace: true, Flagged: true, Deny: true}
	default: // NBEOff / unknown -> observe-nothing, block-nothing
		return NBEDecision{CrossNamespace: true}
	}
}
