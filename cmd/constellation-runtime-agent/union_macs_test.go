package main

import (
	"reflect"
	"testing"
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
