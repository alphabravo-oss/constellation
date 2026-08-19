package federation

import "testing"

func TestStateMachine(t *testing.T) {
	m := Membership{State: StateStandalone}
	m2, err := Promote(m)
	if err != nil || m2.State != StateMaster {
		t.Fatalf("promote: %v %s", err, m2.State)
	}
	if _, err := Promote(m2); err == nil {
		t.Fatal("expected error promoting twice")
	}
	m3, err := Demote(m2)
	if err != nil || m3.State != StateStandalone {
		t.Fatalf("demote: %v %s", err, m3.State)
	}
	j, err := Join(m3, "master-1", "c1")
	if err != nil || j.State != StateJoint || j.MasterID != "master-1" {
		t.Fatalf("join: %v %+v", err, j)
	}
	if _, err := Join(m3, "", "c"); err == nil {
		t.Fatal("expected error on empty master_id")
	}
	out, err := Leave(j)
	if err != nil || out.State != StateStandalone {
		t.Fatalf("leave: %v %s", err, out.State)
	}
}

func TestFilterSinceAndNextRevision(t *testing.T) {
	rev := []RuleRevision{
		{Revision: 1}, {Revision: 5}, {Revision: 3}, {Revision: 2},
	}
	got := FilterSince(rev, 2)
	if len(got) != 2 || got[0].Revision != 3 || got[1].Revision != 5 {
		t.Fatalf("filter unexpected: %+v", got)
	}
	if NextRevision(rev) != 6 {
		t.Fatalf("next revision: want 6, got %d", NextRevision(rev))
	}
}

func TestMember_Validate(t *testing.T) {
	if err := (&Member{}).Validate(); err == nil {
		t.Fatal("expected error")
	}
	if err := (&Member{ClusterID: "c", Role: "wat"}).Validate(); err == nil {
		t.Fatal("expected error")
	}
	if err := (&Member{ClusterID: "c", Role: "master"}).Validate(); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}
