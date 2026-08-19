package vulnprofile

import (
	"testing"
	"time"
)

func TestProfile_Evaluate_SuppressAccept(t *testing.T) {
	p := &Profile{Name: "p", Active: true, Entries: []Entry{
		{Name: "old-ignored", NameRegex: "^CVE-2019-.*", Action: ActionSuppress},
	}}
	cves := []CVE{
		{ID: "CVE-2019-1", Severity: "high", BaseScore: 7.5},
		{ID: "CVE-2024-1", Severity: "high", BaseScore: 7.5},
	}
	out := p.Evaluate(cves)
	if out[0].Decision != DecisionSuppressAccept {
		t.Fatalf("CVE-2019: want suppress_accept, got %s", out[0].Decision)
	}
	if out[1].Decision != DecisionNone {
		t.Fatalf("CVE-2024: want none, got %s", out[1].Decision)
	}
}

func TestProfile_Evaluate_SuppressDefer(t *testing.T) {
	p := &Profile{Name: "p", Entries: []Entry{
		{Name: "grace", NameRegex: "CVE-.*", Action: ActionSuppress, DaysToFix: 30},
	}}
	out := p.Evaluate([]CVE{{ID: "CVE-2024-1"}})
	if out[0].Decision != DecisionSuppressDefer {
		t.Fatalf("want suppress_defer, got %s", out[0].Decision)
	}
}

func TestProfile_Evaluate_RecentEscalate(t *testing.T) {
	Now = func() time.Time { return time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC) }
	defer func() { Now = time.Now }()

	p := &Profile{Name: "p", Entries: []Entry{
		{Name: "recent-crit", Reserved: "_recent", RecentDays: 14, SeverityFloor: "critical", Action: ActionEscalate},
	}}
	recent := CVE{ID: "CVE-2026-A", Severity: "critical", BaseScore: 9.8, PublishedAt: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)}
	old := CVE{ID: "CVE-2025-B", Severity: "critical", BaseScore: 9.8, PublishedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
	out := p.Evaluate([]CVE{recent, old})
	if out[0].Decision != DecisionEscalate {
		t.Fatalf("recent: want escalate, got %s", out[0].Decision)
	}
	if out[1].Decision != DecisionNone {
		t.Fatalf("old: want none, got %s", out[1].Decision)
	}
}

func TestProfile_DomainScope(t *testing.T) {
	p := &Profile{
		Name:        "p",
		DomainScope: DomainScope{Namespaces: []string{"prod"}},
		Entries:     []Entry{{Name: "all", NameRegex: ".*", Action: ActionSuppress}},
	}
	out := p.Evaluate([]CVE{
		{ID: "CVE-A", Namespace: "prod"},
		{ID: "CVE-B", Namespace: "dev"},
	})
	if out[0].Decision != DecisionSuppressAccept {
		t.Fatalf("prod: want suppress, got %s", out[0].Decision)
	}
	if out[1].Decision != DecisionNone {
		t.Fatalf("dev: want none, got %s", out[1].Decision)
	}
}

func TestProfile_ImageGlobAndScoreFloor(t *testing.T) {
	p := &Profile{Name: "p", Entries: []Entry{
		{Name: "stripe", Images: []string{"stripe/*"}, ScoreFloor: 9.0, Action: ActionEscalate},
	}}
	out := p.Evaluate([]CVE{
		{ID: "CVE-A", Image: "stripe/api", BaseScore: 9.5},
		{ID: "CVE-B", Image: "stripe/api", BaseScore: 7.0},
		{ID: "CVE-C", Image: "other/api", BaseScore: 9.9},
	})
	if out[0].Decision != DecisionEscalate {
		t.Fatalf("stripe high: want escalate, got %s", out[0].Decision)
	}
	if out[1].Decision != DecisionNone {
		t.Fatalf("low score: want none, got %s", out[1].Decision)
	}
	if out[2].Decision != DecisionNone {
		t.Fatalf("other image: want none, got %s", out[2].Decision)
	}
}

func TestProfile_Validate(t *testing.T) {
	if err := (&Profile{Name: ""}).Validate(); err == nil {
		t.Fatal("expected error for empty name")
	}
	if err := (&Profile{Name: "p", Entries: []Entry{{Name: "x", Action: "wat"}}}).Validate(); err == nil {
		t.Fatal("expected error for bad action")
	}
	if err := (&Profile{Name: "p", Entries: []Entry{{Name: "x", Action: ActionSuppress, NameRegex: "[bad"}}}).Validate(); err == nil {
		t.Fatal("expected error for bad regex")
	}
	if err := (&Profile{Name: "p", Entries: []Entry{{Name: "x", Action: ActionSuppress, Reserved: "nope"}}}).Validate(); err == nil {
		t.Fatal("expected error for bad reserved")
	}
	if err := (&Profile{Name: "p", Entries: []Entry{{Name: "ok", Action: ActionSuppress}}}).Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
