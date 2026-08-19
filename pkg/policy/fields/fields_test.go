package fields

import "testing"

func TestAllSorted(t *testing.T) {
	all := All()
	if len(all) < 10 {
		t.Fatalf("expected catalogue to be populated, got %d", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Name > all[i].Name {
			t.Fatalf("not sorted: %s > %s", all[i-1].Name, all[i].Name)
		}
	}
}

func TestByName(t *testing.T) {
	if _, ok := ByName("container.securityContext.privileged"); !ok {
		t.Fatalf("missing privileged field")
	}
	if _, ok := ByName("nonsense"); ok {
		t.Fatalf("unexpected hit")
	}
}
