package risk

import "testing"

func TestComputeBoundary(t *testing.T) {
	if got := Compute(Inputs{}); got != 0 {
		t.Fatalf("empty inputs should be 0, got %d", got)
	}
	// CVSS 10 + KEV + EPSS 1.0 + reachable + critical asset = ceiling
	got := Compute(Inputs{
		CVSSBase: 10, KEVListed: true, EPSSProbability: 1.0,
		ReachableRuntime: true, AssetCriticality: "critical",
	})
	if got != 100 {
		t.Fatalf("max inputs should clamp to 100, got %d", got)
	}
}

func TestKEVKicker(t *testing.T) {
	// Two identical findings, one KEV, one not. KEV should score higher.
	noKEV := Compute(Inputs{CVSSBase: 7.5, EPSSProbability: 0.5, AssetCriticality: "high"})
	withKEV := Compute(Inputs{CVSSBase: 7.5, EPSSProbability: 0.5, AssetCriticality: "high", KEVListed: true})
	if withKEV <= noKEV {
		t.Fatalf("KEV listing must raise score: %d <= %d", withKEV, noKEV)
	}
}

func TestOverride(t *testing.T) {
	got := Compute(Inputs{CVSSBase: 10, Override: true, OverrideScore: 5})
	if got != 5 {
		t.Fatalf("override should win, got %d", got)
	}
}

func TestReachabilityShift(t *testing.T) {
	cold := Compute(Inputs{CVSSBase: 8, EPSSProbability: 0.2})
	hot := Compute(Inputs{CVSSBase: 8, EPSSProbability: 0.2, ReachableRuntime: true})
	if hot <= cold {
		t.Fatalf("reachable-confirmed must raise score: %d <= %d", hot, cold)
	}
}
