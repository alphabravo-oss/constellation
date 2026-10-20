package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func mustOpenResponseJournal(t *testing.T, dir, scope string) *responseJournal {
	t.Helper()
	j, err := openResponseJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func fixtureProcessResult(a processActionV2) processResultV2 {
	return processResultV2{Version: 2, ID: a.ID, ActionToken: a.ActionToken, Node: a.Node, Type: a.Type, Outcome: "applied", At: time.Now().UTC()}
}
func TestResponseJournalRetainsExactIntentAndResult(t *testing.T) {
	dir := t.TempDir()
	a := responseFixtureAction()
	j := mustOpenResponseJournal(t, dir, "scope-a")
	if fresh, err := j.Prepare(a); err != nil || !fresh {
		t.Fatalf("prepare fresh=%v error=%v", fresh, err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = mustOpenResponseJournal(t, dir, "scope-a")
	defer func() { _ = j.Close() }()
	if fresh, err := j.Prepare(a); err != nil || fresh {
		t.Fatalf("prepared action can repeat: %v %v", fresh, err)
	}
	result := fixtureProcessResult(a)
	if err := j.Complete(a, result); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = mustOpenResponseJournal(t, dir, "scope-a")
	entries := j.Entries()
	if len(entries) != 1 || entries[0].Result == nil || *entries[0].Result != result {
		t.Fatalf("result not durable: %+v", entries)
	}
	changed := a
	changed.ActionToken = uuid.NewString()
	if _, err := j.Prepare(changed); err == nil {
		t.Fatal("changed action replaced prepared identity")
	}
	for _, name := range []string{"scope.json", a.ID + ".json"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("private journal mode: %v %v", info, err)
		}
	}
	if err := j.Forget(a.ID); err != nil {
		t.Fatal(err)
	}
	if len(j.Entries()) != 0 {
		t.Fatal("acknowledged action retained")
	}
}
func TestResponseJournalRejectsRebindingCorruptionAndOverflow(t *testing.T) {
	dir := t.TempDir()
	j := mustOpenResponseJournal(t, dir, "scope-a")
	if other, err := openResponseJournal(dir, "scope-a"); err == nil {
		_ = other.Close()
		t.Fatal("journal permitted concurrent executor")
	}
	j.maxEntries = 1
	if _, err := j.Prepare(responseFixtureAction()); err != nil {
		t.Fatal(err)
	}
	other := responseFixtureAction()
	other.ID = uuid.NewString()
	if _, err := j.Prepare(other); err == nil {
		t.Fatal("full journal allowed a new effect")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if other, err := openResponseJournal(dir, "scope-b"); err == nil {
		_ = other.Close()
		t.Fatal("pending actions rebound to another owner")
	}
	if err := os.WriteFile(filepath.Join(dir, "invalid.json"), []byte(`{"action":null}`), 0600); err != nil {
		t.Fatal(err)
	}
	if other, err := openResponseJournal(dir, "scope-a"); err == nil {
		_ = other.Close()
		t.Fatal("corrupt journal silently reset")
	}
}
func TestResponseJournalNeverAcceptsMismatchedResult(t *testing.T) {
	j := mustOpenResponseJournal(t, t.TempDir(), "scope-a")
	defer func() { _ = j.Close() }()
	a := responseFixtureAction()
	if _, err := j.Prepare(a); err != nil {
		t.Fatal(err)
	}
	result := fixtureProcessResult(a)
	result.Node = "node-b"
	if err := j.Complete(a, result); err == nil {
		t.Fatal("foreign result accepted")
	}
	body, err := json.Marshal(j.Entries())
	if err != nil || len(body) == 0 {
		t.Fatal(err)
	}
	if j.Entries()[0].Result != nil {
		t.Fatal("mismatched result changed intent")
	}
}

func TestResponseJournalDrainedCredentialRotation(t *testing.T) {
	dir := t.TempDir()
	old := "https://control.example|cluster|node|old-token-hash"
	rotated := "https://control.example|cluster|node|new-token-hash"
	j := mustOpenResponseJournal(t, dir, old)
	a := responseFixtureAction()
	if _, err := j.Prepare(a); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if other, err := openResponseJournal(dir, rotated); err == nil {
		_ = other.Close()
		t.Fatal("pending intent rebound after token rotation")
	}
	j = mustOpenResponseJournal(t, dir, old)
	if err := j.Complete(a, fixtureProcessResult(a)); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if other, err := openResponseJournal(dir, rotated); err == nil {
		_ = other.Close()
		t.Fatal("unacknowledged result rebound after token rotation")
	}
	j = mustOpenResponseJournal(t, dir, old)
	if err := j.Forget(a.ID); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = mustOpenResponseJournal(t, dir, rotated)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = mustOpenResponseJournal(t, dir, rotated)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if other, err := openResponseJournal(dir, "https://other.example|cluster|node|new-token-hash"); err == nil {
		_ = other.Close()
		t.Fatal("drained journal silently changed control plane")
	}
}

func TestResponseJournalSizeBoundsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	j := mustOpenResponseJournal(t, dir, "scope")
	a := responseFixtureAction()
	a.WorkloadID = strings.Repeat("x", 4096)
	if fresh, err := j.Prepare(a); err != nil || !fresh {
		t.Fatalf("maximum action rejected: %v", err)
	}
	result := fixtureProcessResult(a)
	result.Reason = strings.Repeat("x", 4096)
	if err := j.Complete(a, result); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = mustOpenResponseJournal(t, dir, "scope")
	defer func() { _ = j.Close() }()
	if entries := j.Entries(); len(entries) != 1 || entries[0].Action != a || entries[0].Result == nil || *entries[0].Result != result {
		t.Fatal("accepted maximum entry cannot restart")
	}
	for _, size := range []int{4097, 70 << 10} {
		oversized := responseFixtureAction()
		oversized.WorkloadID = strings.Repeat("x", size)
		if _, err := j.Prepare(oversized); err == nil {
			t.Fatalf("oversized action %d became durable", size)
		}
	}
	tooLarge := responseFixtureAction()
	if err := j.persist(responseJournalEntry{Action: tooLarge, Result: &processResultV2{Reason: strings.Repeat("x", responseJournalEntryLimit)}}); err == nil {
		t.Fatal("oversized serialized entry bypassed durable bound")
	}
	if len(j.Entries()) != 1 {
		t.Fatal("rejected entry changed journal")
	}
}
