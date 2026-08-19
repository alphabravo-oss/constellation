package main

import (
	"sync/atomic"
	"testing"
)

func TestRuntimeAgentHeartbeatMetadataIncludesEnforcerCounters(t *testing.T) {
	var (
		execEvents      atomic.Uint64
		fileEvents      atomic.Uint64
		totalEvents     atomic.Uint64
		uploadedEvents  atomic.Uint64
		droppedEvents   atomic.Uint64
		flowsUploaded   atomic.Uint64
		flowsDropped    atomic.Uint64
		threatsUploaded atomic.Uint64
		threatsDropped  atomic.Uint64
		dpConn          atomic.Uint64
		dpThreat        atomic.Uint64
		dpKeepalive     atomic.Uint64
		dpOther         atomic.Uint64
	)
	execEvents.Store(7)
	fileEvents.Store(11)
	totalEvents.Store(18)
	uploadedEvents.Store(16)
	droppedEvents.Store(2)
	flowsUploaded.Store(5)
	flowsDropped.Store(1)
	threatsUploaded.Store(3)
	threatsDropped.Store(4)
	dpConn.Store(6)
	dpThreat.Store(5)
	dpKeepalive.Store(4)
	dpOther.Store(3)

	metadata := runtimeAgentHeartbeatMetadata(&metricsSource{
		Node:             "node-a",
		NExec:            &execEvents,
		NFile:            &fileEvents,
		NTotal:           &totalEvents,
		NUploaded:        &uploadedEvents,
		NDropped:         &droppedEvents,
		BPFDropped:       func() uint64 { return 9 },
		NDPConn:          &dpConn,
		NDPThreat:        &dpThreat,
		NDPKeepAlive:     &dpKeepalive,
		NDPOther:         &dpOther,
		NFlowsUploaded:   &flowsUploaded,
		NFlowsDropped:    &flowsDropped,
		NThreatsUploaded: &threatsUploaded,
		NThreatsDropped:  &threatsDropped,
	}, runtimeAgentHeartbeatOptions{
		UploadEnabled:   true,
		BatchSize:       200,
		BatchIntervalMS: 2000,
		ClusterID:       "cluster-id",
		ClusterName:     "local",
	})

	if metadata["processed_events"] != uint64(18) || metadata["dropped_events"] != uint64(2) || metadata["bpf_dropped"] != uint64(9) {
		t.Fatalf("event metadata = %+v", metadata)
	}
	if metadata["flows_uploaded"] != uint64(5) || metadata["threats_dropped"] != uint64(4) {
		t.Fatalf("flow/threat metadata = %+v", metadata)
	}
	dpMeta := metadata["dp"].(map[string]any)
	if dpMeta["enabled"] != false || dpMeta["status"] != "disabled" {
		t.Fatalf("dp metadata = %+v", dpMeta)
	}
	enforcer := metadata["enforcer"].(map[string]any)
	if enforcer["node"] != "node-a" || enforcer["dp_status"] != "disabled" || enforcer["ebpf_status"] != "degraded" {
		t.Fatalf("enforcer metadata = %+v", enforcer)
	}
	if enforcer["processed_events"] != uint64(36) || enforcer["dropped_events"] != uint64(7) {
		t.Fatalf("enforcer counters = %+v", enforcer)
	}
}

func TestRuntimeAgentDPStatus(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{name: "not started", got: runtimeAgentDPStatus(0, 0, 0, 0, 0, 0, 0), want: "starting"},
		{name: "no keepalive", got: runtimeAgentDPStatus(1, 0, 0, 0, 0, 0, 0), want: "starting"},
		{name: "ready", got: runtimeAgentDPStatus(1, 0, 0, 1, 0, 0, 0), want: "ready"},
		{name: "crash", got: runtimeAgentDPStatus(1, 1, 0, 1, 0, 0, 0), want: "degraded"},
		{name: "keepalive timeout", got: runtimeAgentDPStatus(1, 0, 0, 1, 1, 0, 0), want: "degraded"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, tc.got, tc.want)
		}
	}
}
