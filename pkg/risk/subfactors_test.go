package risk

import "testing"

func TestDecomposeFourFactors(t *testing.T) {
	d := Decompose(SubfactorInputs{
		Inputs: Inputs{
			CVSSBase: 9.5, KEVListed: true, EPSSProbability: 0.8,
			ReachableRuntime: true, AssetCriticality: "high",
		},
		PolicyViolationCount: 2,
		NetworkExposed:       true,
	})
	if d.Composite <= 0 {
		t.Fatalf("composite zero: %+v", d)
	}
	if len(d.Subfactors) != 4 {
		t.Fatalf("expected 4 subfactors, got %d", len(d.Subfactors))
	}
	names := map[string]bool{}
	for _, s := range d.Subfactors {
		names[s.Name] = true
		if s.Raw < 0 || s.Raw > 100 {
			t.Fatalf("subfactor %s raw out of range: %d", s.Name, s.Raw)
		}
	}
	for _, want := range []string{"cve_risk", "policy_violation_risk", "network_exposure_risk", "asset_criticality_risk"} {
		if !names[want] {
			t.Fatalf("missing subfactor %s", want)
		}
	}
}
