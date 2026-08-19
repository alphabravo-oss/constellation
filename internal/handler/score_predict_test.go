package handler

import "testing"

func TestComputeRiskScore_ZeroIsClean(t *testing.T) {
	if got := computeRiskScore(severityCounts{}); got != 0 {
		t.Fatalf("empty findings should score 0, got %d", got)
	}
}

func TestComputeRiskScore_Bounded0To100(t *testing.T) {
	// A huge backlog must saturate, never exceed 100.
	got := computeRiskScore(severityCounts{Critical: 10000})
	if got < 0 || got > 100 {
		t.Fatalf("score out of range: %d", got)
	}
	if got != 100 {
		t.Fatalf("massive backlog should asymptote to 100, got %d", got)
	}
}

func TestComputeRiskScore_SeverityOrdering(t *testing.T) {
	// One critical must weigh strictly more than one high, which weighs more
	// than one medium, which weighs more than one low.
	crit := computeRiskScore(severityCounts{Critical: 1})
	high := computeRiskScore(severityCounts{High: 1})
	med := computeRiskScore(severityCounts{Medium: 1})
	low := computeRiskScore(severityCounts{Low: 1})
	if !(crit > high && high > med && med > low && low >= 0) {
		t.Fatalf("severity ordering violated: crit=%d high=%d med=%d low=%d", crit, high, med, low)
	}
}

func TestComputeRiskScore_ResolvingLowersScore(t *testing.T) {
	before := computeRiskScore(severityCounts{Critical: 3, High: 5, Medium: 10})
	after := computeRiskScore(severityCounts{Critical: 0, High: 5, Medium: 10}) // fixed 3 crits
	if !(after < before) {
		t.Fatalf("resolving criticals must lower the score: before=%d after=%d", before, after)
	}
}

func TestScoreGrade_Bands(t *testing.T) {
	cases := map[int]string{0: "good", 20: "good", 21: "fair", 50: "fair", 51: "poor", 100: "poor"}
	for score, want := range cases {
		if got := scoreGrade(score); got != want {
			t.Errorf("scoreGrade(%d) = %q, want %q", score, got, want)
		}
	}
}

func TestSeverityCounts_AddAndClamp(t *testing.T) {
	c := severityCounts{Critical: 2}
	c.add("critical", -5)
	clampCounts(&c)
	if c.Critical != 0 {
		t.Fatalf("clamp should floor at 0, got %d", c.Critical)
	}
	c.add("bogus", 3) // unknown severity → info bucket
	if c.Info != 3 {
		t.Fatalf("unknown severity should land in info bucket, got %d", c.Info)
	}
}
