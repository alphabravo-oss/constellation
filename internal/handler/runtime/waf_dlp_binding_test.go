package runtime

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// TestResolveSensorMACs_ResolvesGroupMembersToMACs is the NET-43 core: a
// group→sensor binding must resolve down to exactly the tap MACs of the group's
// member workloads, so the sync side can scope the sensor to those MACs (not a
// fleet-wide opt-in).
func TestResolveSensorMACs_ResolvesGroupMembersToMACs(t *testing.T) {
	groupA := uuid.New()
	groupB := uuid.New()
	dlpSensor := uuid.New()
	wafSensor := uuid.New()

	bindings := []GroupSensorBinding{
		{GroupID: groupA, Kind: SensorKindDLP, SensorID: dlpSensor},
		{GroupID: groupB, Kind: SensorKindWAF, SensorID: wafSensor},
	}
	groupMembers := map[uuid.UUID][]string{
		groupA: {"ns/web", "ns/api"},
		groupB: {"ns/api"},
	}
	workloadMACs := map[string][]string{
		"ns/web": {"AA:AA:AA:AA:AA:AA"},          // upper-case → normalised
		"ns/api": {"bb:bb:bb:bb:bb:bb", "cc:cc:cc:cc:cc:cc"},
	}

	got := resolveSensorMACs(bindings, groupMembers, workloadMACs)

	wantDLP := []string{"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", "cc:cc:cc:cc:cc:cc"}
	if macs := got[SensorKey{Kind: SensorKindDLP, ID: dlpSensor}]; !reflect.DeepEqual(macs, wantDLP) {
		t.Fatalf("dlp sensor MACs = %v, want %v", macs, wantDLP)
	}
	wantWAF := []string{"bb:bb:bb:bb:bb:bb", "cc:cc:cc:cc:cc:cc"}
	if macs := got[SensorKey{Kind: SensorKindWAF, ID: wafSensor}]; !reflect.DeepEqual(macs, wantWAF) {
		t.Fatalf("waf sensor MACs = %v, want %v", macs, wantWAF)
	}
}

// TestResolveSensorMACs_UnionsAndDedups: two groups bound to the SAME sensor
// union their members, and a workload shared between them appears once.
func TestResolveSensorMACs_UnionsAndDedups(t *testing.T) {
	g1, g2 := uuid.New(), uuid.New()
	sensor := uuid.New()
	bindings := []GroupSensorBinding{
		{GroupID: g1, Kind: SensorKindWAF, SensorID: sensor},
		{GroupID: g2, Kind: SensorKindWAF, SensorID: sensor},
	}
	members := map[uuid.UUID][]string{
		g1: {"ns/a", "ns/shared"},
		g2: {"ns/shared", "ns/b"},
	}
	macs := map[string][]string{
		"ns/a":      {"11:11:11:11:11:11"},
		"ns/shared": {"22:22:22:22:22:22"},
		"ns/b":      {"33:33:33:33:33:33"},
	}
	got := resolveSensorMACs(bindings, members, macs)
	want := []string{"11:11:11:11:11:11", "22:22:22:22:22:22", "33:33:33:33:33:33"}
	if g := got[SensorKey{Kind: SensorKindWAF, ID: sensor}]; !reflect.DeepEqual(g, want) {
		t.Fatalf("union MACs = %v, want %v", g, want)
	}
}

// TestResolveSensorMACs_EmptyMembershipContributesNothing: a binding whose
// group has no members (or whose members have no observed MACs) is dropped, not
// an error — the workload simply hasn't been seen on the datapath yet.
func TestResolveSensorMACs_EmptyMembershipContributesNothing(t *testing.T) {
	g := uuid.New()
	sensor := uuid.New()
	bindings := []GroupSensorBinding{{GroupID: g, Kind: SensorKindDLP, SensorID: sensor}}
	got := resolveSensorMACs(bindings, map[uuid.UUID][]string{g: {"ns/none"}}, map[string][]string{})
	if len(got[SensorKey{Kind: SensorKindDLP, ID: sensor}]) != 0 {
		t.Fatalf("expected no MACs for an unobserved member, got %v", got)
	}
}
