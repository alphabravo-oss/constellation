package complianceevidence

import "testing"

func TestInventoryQueryValidation(t *testing.T) {
	q, err := ValidateQuery(Query{Scope: "all", Framework: "all", Targets: []string{}})
	if err != nil || q.Scope != "" || q.Framework != "" || q.Limit != 1000 || q.Sort != "observed" || q.Order != "desc" || q.Targets == nil {
		t.Fatalf("defaults/empty scope changed: %+v %v", q, err)
	}
	for _, bad := range []Query{{Scope: "other"}, {Status: "graded"}, {Sort: "title"}, {Order: "drop"}, {Offset: -1}, {Offset: 1000001}, {Limit: 100001}} {
		if _, err := ValidateQuery(bad); err == nil {
			t.Fatalf("invalid query accepted: %+v", bad)
		}
	}
	for _, sort := range []string{"observed", "scope", "target", "framework", "control", "status", "severity"} {
		if _, err := ValidateQuery(Query{Sort: sort, Order: "asc"}); err != nil {
			t.Fatal(err)
		}
	}
}
