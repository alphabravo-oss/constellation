package main

import (
	"reflect"
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

func TestUnionMACs(t *testing.T) {
	// dedup across lists, drop empties, preserve order (a first)
	got := unionMACs([]string{"aa", "bb", ""}, []string{"bb", "cc", ""})
	want := []string{"aa", "bb", "cc"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unionMACs = %v, want %v", got, want)
	}
	if got := unionMACs(nil, nil); len(got) != 0 {
		t.Fatalf("unionMACs(nil,nil) = %v, want empty", got)
	}
}

func TestMergedHasICMP(t *testing.T) {
	icmp := &dp.WorkloadPolicy{Rules: []*dp.PolicyRule{{IPProto: dp.IPProtoTCP}, {IPProto: dp.IPProtoICMP}}}
	if !mergedHasICMP(icmp) {
		t.Fatal("expected ICMP rule detected")
	}
	tcp := &dp.WorkloadPolicy{Rules: []*dp.PolicyRule{{IPProto: dp.IPProtoTCP}, {IPProto: dp.IPProtoAny}}}
	if mergedHasICMP(tcp) {
		t.Fatal("no ICMP rule; want false")
	}
	if mergedHasICMP(nil) {
		t.Fatal("nil policy; want false")
	}
}
