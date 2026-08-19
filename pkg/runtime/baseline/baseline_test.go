package baseline

import (
	"testing"
	"time"
)

func TestLearnThenMonitor_AlertsOnUnbaselinedProcess(t *testing.T) {
	e := NewEngine()
	wl := "default/api-service"
	e.StartLearn(wl, time.Hour)

	for _, p := range []string{"node", "sh", "ps"} {
		if a := e.IngestProcess(ProcessSample{WorkloadID: wl, Process: p, At: time.Now()}); a != nil {
			t.Fatalf("learn mode shouldn't alert; got %+v", a)
		}
	}
	if _, err := e.Promote(wl); err != nil {
		t.Fatal(err)
	}
	// Monitor: known process passes, unknown alerts.
	if a := e.IngestProcess(ProcessSample{WorkloadID: wl, Process: "node", At: time.Now()}); a != nil {
		t.Fatalf("known process should pass: %+v", a)
	}
	a := e.IngestProcess(ProcessSample{WorkloadID: wl, Process: "bash", FullCmd: "bash -i", At: time.Now()})
	if a == nil {
		t.Fatal("bash should alert as unbaselined")
	}
	if a.Block {
		t.Fatal("monitor mode shouldn't block")
	}
}

func TestEnforce_BlockFlagSet(t *testing.T) {
	e := NewEngine()
	wl := "default/api"
	e.StartLearn(wl, time.Hour)
	if _, err := e.Promote(wl); err != nil { // → Monitor
		t.Fatal(err)
	}
	if _, err := e.Promote(wl); err != nil { // → Enforce
		t.Fatal(err)
	}
	a := e.IngestProcess(ProcessSample{WorkloadID: wl, Process: "unknown", At: time.Now()})
	if a == nil || !a.Block {
		t.Fatalf("enforce mode should produce Block=true alert; got %+v", a)
	}
}

func TestEndpointBaseline_NormalizedKeys(t *testing.T) {
	e := NewEngine()
	wl := "default/web"
	e.StartLearn(wl, time.Hour)
	e.IngestEndpoint(EndpointSample{WorkloadID: wl, Method: "GET", Path: "/v1/users/:id"})
	_, _ = e.Promote(wl)
	if a := e.IngestEndpoint(EndpointSample{WorkloadID: wl, Method: "GET", Path: "/v1/users/:id"}); a != nil {
		t.Fatalf("baselined endpoint shouldn't alert: %+v", a)
	}
	if a := e.IngestEndpoint(EndpointSample{WorkloadID: wl, Method: "POST", Path: "/admin/delete-all"}); a == nil {
		t.Fatal("new endpoint should alert")
	}
}
