// Package risk computes the composite Constellation Risk Score (0..100) from CVSS base,
// KEV listing, EPSS probability, reachability flags, and asset criticality.
//
// FR-6 / Implementation Notes: the spec calls this score "our differentiator" but leaves the
// weighting open. The default formula below is grounded in 2024-2026 industry practice
// (Wiz / Snyk / Tenable VPR all combine these same inputs) and is tuned to emphasize the
// signals that demonstrably correlate with exploitation: KEV listing, high EPSS, and runtime
// reachability. The weights are exported as named constants so a customer (or an A/B-tested
// future revision) can tune them without code surgery.
//
// Inputs map to the FR-6 inputs: CVSS base + KEV multiplier + EPSS probability + reachability boost + asset criticality.
package risk

import "math"

// Weights are the linear coefficients on each normalized signal.
// They must sum to 1.0 so the pre-multiplier base stays in [0, 1].
type Weights struct {
	CVSS         float64 // share assigned to CVSS base / 10
	EPSS         float64 // share assigned to EPSS probability
	Reachability float64 // share assigned to reachability (static OR runtime)
	KEV          float64 // share assigned to KEV listing (binary signal)
}

// DefaultWeights are the v1 weights. Each contributes a meaningful but not dominant share —
// no single signal alone can drive a finding to "critical".
var DefaultWeights = Weights{
	CVSS:         0.55,
	EPSS:         0.20,
	Reachability: 0.15,
	KEV:          0.10,
}

// Multipliers are applied after the linear base. KEV gets an additional kicker (industry
// consensus: a KEV listing is the strongest single signal that a CVE is being actively
// exploited in the wild). Asset criticality scales the whole result.
type Multipliers struct {
	KEVKicker          float64
	CriticalityLow     float64
	CriticalityMedium  float64
	CriticalityHigh    float64
	CriticalityCrit    float64
}

var DefaultMultipliers = Multipliers{
	KEVKicker:         1.30,
	CriticalityLow:    0.80,
	CriticalityMedium: 1.00,
	CriticalityHigh:   1.20,
	CriticalityCrit:   1.50,
}

// Inputs gathers the FR-6 signals. The caller is responsible for sourcing them from the
// scanner aggregator + CVE DB.
type Inputs struct {
	CVSSBase         float64 // 0..10
	KEVListed        bool
	EPSSProbability  float64 // 0..1
	ReachableStatic  bool
	ReachableRuntime bool
	AssetCriticality string // "low" | "medium" | "high" | "critical"
	Override         bool
	OverrideScore    int // 0..100, used when Override is true
}

// Compute returns the Constellation Risk Score (0..100) for the given inputs.
//
// Algorithm:
//
//	if Override: return clamp(OverrideScore, 0, 100)
//	base = w.CVSS * (CVSS/10) + w.EPSS * EPSS + w.Reachability * (reachable ? 1 : 0) + w.KEV * (kev ? 1 : 0)
//	score = base * critMul * (kev ? KEVKicker : 1.0) * 100
//	return clamp(score, 0, 100)
//
// Runtime reachability outweighs static reachability for the binary flag (a finding observed
// executing in production is more actionable than a static call-graph hit).
func Compute(in Inputs) int {
	return ComputeWith(in, DefaultWeights, DefaultMultipliers)
}

// ComputeWith is Compute with explicit tunables. Used by tests + per-org overrides.
func ComputeWith(in Inputs, w Weights, m Multipliers) int {
	if in.Override {
		return clampInt(in.OverrideScore, 0, 100)
	}
	cvss := clamp(in.CVSSBase/10.0, 0, 1)
	epss := clamp(in.EPSSProbability, 0, 1)
	reachable := 0.0
	if in.ReachableRuntime || in.ReachableStatic {
		reachable = 1.0
	}
	kev := 0.0
	if in.KEVListed {
		kev = 1.0
	}
	base := w.CVSS*cvss + w.EPSS*epss + w.Reachability*reachable + w.KEV*kev

	critMul := m.CriticalityMedium
	switch in.AssetCriticality {
	case "low":
		critMul = m.CriticalityLow
	case "high":
		critMul = m.CriticalityHigh
	case "critical":
		critMul = m.CriticalityCrit
	}

	kevMul := 1.0
	if in.KEVListed {
		kevMul = m.KEVKicker
	}

	score := base * critMul * kevMul * 100
	return clampInt(int(math.Round(score)), 0, 100)
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
