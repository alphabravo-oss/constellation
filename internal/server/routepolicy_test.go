package server

import "testing"

// Fail closed: every registered route is either verb-gated or explicitly public.
func TestRoutePolicyTableHasNoBlankEntries(t *testing.T) {
	t.Parallel()
	table := RoutePolicy()
	if len(table) == 0 {
		t.Fatal("routepolicy.json is empty; run the integration test with UPDATE_ROUTE_POLICY=1")
	}
	counts := map[string]int{}
	for route, verb := range table {
		if verb == "" {
			t.Fatalf("%s has no policy", route)
		}
		counts[verb]++
	}
	t.Logf("%d routes: public=%d authn-only=%d verb-gated=%d", len(table), counts["public"], counts["authn"], len(table)-counts["public"]-counts["authn"])
}
