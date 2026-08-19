package forensics

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCapture_RoundTrip(t *testing.T) {
	env := Envelope{
		Trigger:    "quarantine",
		CapturedAt: time.Now().UTC(),
		Pod:        json.RawMessage(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"x"}}`),
		Events: []Event{
			{Time: time.Now(), Type: "Warning", Reason: "BackOff", Message: "Back-off restart"},
		},
		Logs:  map[string][]string{"main": {"started", "shell -c id", "exit"}},
		Flows: []Flow{{Peer: "external.api.com", Port: 443, Protocol: "TCP", Count: 12}},
	}
	gz, sha, err := Capture(env)
	if err != nil {
		t.Fatal(err)
	}
	if sha == "" {
		t.Fatal("missing sha256")
	}
	got, err := Restore(gz)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "ConstellationForensicSnapshot/v1" {
		t.Fatalf("kind: %q", got.Kind)
	}
	if got.Trigger != "quarantine" {
		t.Fatalf("trigger: %q", got.Trigger)
	}
	if len(got.Events) != 1 || got.Events[0].Reason != "BackOff" {
		t.Fatalf("events: %+v", got.Events)
	}
	if len(got.Flows) != 1 || got.Flows[0].Port != 443 {
		t.Fatalf("flows: %+v", got.Flows)
	}
}
