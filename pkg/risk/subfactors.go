package risk

import "math"

// Subfactor is a single component contribution to the overall composite risk.
// Each subfactor is reported as a 0..100 value so the UI can render bar charts
// without further normalization. Score is the contribution this subfactor adds
// to the composite (already weighted), Raw is the un-weighted 0..100 magnitude.
type Subfactor struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Score       int     `json:"score"`        // weighted contribution to composite
	Raw         int     `json:"raw"`          // raw 0..100 magnitude before weighting
	Weight      float64 `json:"weight"`       // 0..1 share of composite
}

// Decomposition is the per-finding subfactor breakdown returned by the API.
// Composite equals Compute(in) and is included for client convenience.
type Decomposition struct {
	Composite  int         `json:"composite"`
	Subfactors []Subfactor `json:"factors"`
}

// SubfactorInputs extends Inputs with the additional signals the decomposition
// needs (policy violation count, network exposure, etc). Callers can leave
// the extras zero — they degrade gracefully.
type SubfactorInputs struct {
	Inputs
	PolicyViolationCount int // number of distinct policies the finding violates
	NetworkExposed       bool // workload exposes a port to public network
	IngressFromInternet  bool // ingress traffic observed from outside the cluster
}

// Decompose returns the composite score plus per-subfactor breakdown.
// Subfactor weights are derived from DefaultWeights so the four reported
// factors sum to the composite.
func Decompose(in SubfactorInputs) Decomposition {
	composite := Compute(in.Inputs)
	w := DefaultWeights

	cvssRaw := clampPct(in.CVSSBase * 10) // 0..10 -> 0..100
	cveScore := round(float64(cvssRaw) * w.CVSS)

	policyRaw := clampPct(float64(in.PolicyViolationCount) * 25.0)
	policyScore := round(float64(policyRaw) * 0.25)

	netRaw := 0
	if in.NetworkExposed {
		netRaw += 50
	}
	if in.IngressFromInternet {
		netRaw += 50
	}
	netRaw = clampPct(float64(netRaw))
	netScore := round(float64(netRaw) * 0.20)

	critRaw := criticalityRaw(in.AssetCriticality)
	critScore := round(float64(critRaw) * 0.20)

	return Decomposition{
		Composite: composite,
		Subfactors: []Subfactor{
			{Name: "cve_risk", Description: "CVE severity × KEV × EPSS contribution.", Score: cveScore, Raw: cvssRaw, Weight: w.CVSS},
			{Name: "policy_violation_risk", Description: "Distinct enabled policies this finding violates.", Score: policyScore, Raw: policyRaw, Weight: 0.25},
			{Name: "network_exposure_risk", Description: "Network reachability — public ports and observed ingress.", Score: netScore, Raw: netRaw, Weight: 0.20},
			{Name: "asset_criticality_risk", Description: "Configured criticality of the underlying asset.", Score: critScore, Raw: critRaw, Weight: 0.20},
		},
	}
}

func criticalityRaw(c string) int {
	switch c {
	case "critical":
		return 100
	case "high":
		return 75
	case "medium":
		return 50
	case "low":
		return 25
	}
	return 50
}

func clampPct(v float64) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return int(math.Round(v))
}

func round(v float64) int { return int(math.Round(v)) }
