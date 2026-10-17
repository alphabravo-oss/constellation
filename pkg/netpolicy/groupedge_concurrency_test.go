package netpolicy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestGroupEdgeValidateCopiedInputsDoNotShareNormalization(t *testing.T) {
	original := GroupEdge{FromGroup: "frontend", ToGroup: "backend", Ports: []PortSpec{{Protocol: " tcp ", Port: 443}, {Protocol: "", Port: 80}}}
	before := []PortSpec{{Protocol: " tcp ", Port: 443}, {Protocol: "", Port: 80}}
	start := make(chan struct{})
	failures := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			candidate := original
			<-start
			for range 100 {
				if err := candidate.Validate(); err != nil {
					failures <- err
					return
				}
				// Marshaling is the real store's next step after normalization.
				if _, err := json.Marshal(candidate); err != nil {
					failures <- err
					return
				}
				if candidate.Mode != "monitor" || candidate.Ports[0].Protocol != "TCP" || candidate.Ports[1].Protocol != "TCP" {
					failures <- fmt.Errorf("normalized copied edge=%+v", candidate)
					return
				}
			}
			// Later mutations of this normalized value must stay private too.
			candidate.Ports[0].Protocol = "UDP"
		})
	}
	close(start)
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if original.Mode != "" || !reflect.DeepEqual(original.Ports, before) {
		t.Fatalf("caller input mutated: mode=%q ports=%+v", original.Mode, original.Ports)
	}
}
