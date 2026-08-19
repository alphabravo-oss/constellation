package attack

import "testing"

func TestMap_EventToTechniques(t *testing.T) {
	if got := Map(EventShellSpawn); len(got) != 1 || got[0] != "T1059.004" {
		t.Fatalf("shell-spawn: %v", got)
	}
	if got := Map(EventReverseShell); len(got) != 2 {
		t.Fatalf("reverse-shell: %v", got)
	}
	if got := Map("unknown-kind"); got != nil {
		t.Fatalf("unknown kind should return nil: %v", got)
	}
}

func TestGet_SubTechniqueFallback(t *testing.T) {
	if _, ok := Get("T1059.004"); !ok {
		t.Fatal("known sub-technique not found")
	}
	if _, ok := Get("T1059.999"); !ok {
		t.Fatal("unknown sub-technique should fall back to parent")
	}
	if _, ok := Get("Tbogus"); ok {
		t.Fatal("totally bogus id should not resolve")
	}
}

func TestByTactic_GroupsByCanonicalTactic(t *testing.T) {
	g := ByTactic()
	if len(g["Execution"]) == 0 {
		t.Fatal("Execution tactic empty")
	}
	if len(g["Defense Evasion"]) == 0 {
		t.Fatal("Defense Evasion tactic empty")
	}
}
