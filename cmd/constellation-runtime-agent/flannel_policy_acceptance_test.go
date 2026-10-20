//go:build integration && linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

type flannelScenario struct {
	t             *testing.T
	identity      flannelIdentity
	supervisor    *dp.Supervisor
	worker        *RuntimePolicySyncWorker
	payload       *atomic.Pointer[runtimePolicyBundle]
	policies      []runtimePolicyWire
	events        *flannelEvents
	probes        []flannelProbe
	endpoints     []dp.PolicyEndpoint
	sourcePort    uint16
	previousStart int64
}

func TestFlannelRuntimePolicyPacketAcceptance(t *testing.T) {
	t.Parallel()
	if os.Getenv("CONSTELLATION_FLANNEL_POLICY_RUN") != "1" {
		t.Skip("requires explicit root-reviewed disposable Flannel fixture; see scripts/test-flannel-policy.sh")
	}
	identity, err := loadFlannelIdentity()
	if err != nil {
		t.Fatal(err)
	}
	scenario := &flannelScenario{t: t, identity: identity, events: &flannelEvents{}, sourcePort: 40000}
	t.Cleanup(scenario.writeEvidence)
	scenario.phase("baseline", false)
	scenario.start()
	scenario.publish()
	scenario.phase("monitor", true)
	scenario.setMode("server-a", "enforce")
	scenario.publish()
	scenario.phase("protect-a", true)
	scenario.setMode("server-b", "enforce")
	scenario.publish()
	scenario.phase("protect-b", true)
	scenario.changeAllowedPort("server-a", 18081)
	scenario.publish()
	scenario.phase("change-a", true)
	scenario.failOpen()
}

func (s *flannelScenario) start() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	provider, ok := dp.NewContainerTapProvider(logger, flannelLister(s.identity)).(*dp.ContainerTapProvider)
	if !ok {
		s.t.Fatal("production container provider unavailable")
	}
	s.supervisor = dp.New(dp.Options{Binary: "/usr/local/bin/dp", Logger: logger, TapProvider: provider, EnforceProvider: dp.NewContainerEnforceProvider(provider), TapReconcileInterval: 250 * time.Millisecond, RestartBackoff: 60 * time.Second, SessionPollInterval: time.Second})
	ctx, cancel := context.WithCancel(s.t.Context())
	result := make(chan error, 1)
	go func() { result <- s.supervisor.Start(ctx) }()
	s.t.Cleanup(func() {
		cancel()
		select {
		case err := <-result:
			if err != nil {
				s.t.Errorf("supervisor shutdown: %v", err)
			}
		case <-time.After(15 * time.Second):
			s.t.Error("owned supervisor did not stop")
		}
	})
	done := make(chan struct{})
	go s.events.drain(s.supervisor.Events(), done)
	s.t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			s.t.Error("native event reader did not stop")
		}
	})
	s.wait("real native readiness and two exact registered workloads", func() bool { return s.supervisor.Ready() && len(s.supervisor.PolicyEndpoints()) == 2 })
	s.endpoints = s.supervisor.PolicyEndpoints()
	s.policies = flannelPolicies(s.identity)
	s.payload = &atomic.Pointer[runtimePolicyBundle]{}
	cluster := uuid.NewString()
	s.payload.Store(&runtimePolicyBundle{ProtocolVersion: 2, ClusterID: cluster, SourceComplete: true, Policies: s.policies})
	server := flannelBundleServer(cluster, s.payload, logger)
	s.t.Cleanup(server.Close)
	s.worker = NewRuntimePolicySyncWorker(RuntimePolicySyncConfig{APIBaseURL: server.URL, ClusterID: cluster, Token: "isolated-fixture", DPSup: s.supervisor, Logger: logger, HTTPClient: server.Client()})
}

func (s *flannelScenario) publish() {
	if err := checkFlannelPods(s.identity.Pods); err != nil {
		s.t.Fatal(err)
	}
	current := s.payload.Load()
	s.payload.Store(&runtimePolicyBundle{ProtocolVersion: 2, ClusterID: current.ClusterID, SourceComplete: true, Policies: s.policies})
	s.worker.SyncOnce(s.t.Context())
	stats := s.worker.Snapshot()
	if stats.Errors != 0 || stats.Conflicts != 0 || stats.UncertainMACs != 0 || stats.Pushes < 2 {
		s.t.Fatalf("candidate not confirmed: %+v", stats)
	}
	// Submission is not native application proof. Every phase below requires real
	// native packet verdicts and server observations before it can pass.
}

func (s *flannelScenario) setMode(name, mode string) {
	for index := range s.policies {
		if s.policies[index].PodBindings[0].PodName == name {
			s.policies[index].Mode = mode
			s.policies[index].Version++
		}
	}
}
func (s *flannelScenario) changeAllowedPort(name string, port uint16) {
	for index := range s.policies {
		if s.policies[index].PodBindings[0].PodName == name {
			s.policies[index].Rules[0].Port = port
			s.policies[index].Version++
		}
	}
}

func (s *flannelScenario) phase(name string, native bool) {
	client := s.pod("client")
	for _, pod := range s.identity.Pods {
		if pod.Name == "client" {
			continue
		}
		for _, port := range []uint16{18080, 18081} {
			s.probe(name, client, pod, port, native)
		}
	}
}
func (s *flannelScenario) probe(phase string, client, pod flannelPod, port uint16, native bool) {
	s.sourcePort++
	s.wait("fresh native timestamp bucket", func() bool { return time.Now().Unix() > s.previousStart })
	probe := flannelProbe{Phase: phase, Pod: pod.Name, Nonce: fmt.Sprintf("%s-%s-%d-%d", phase, pod.Name, port, s.sourcePort), Port: port, SourcePort: s.sourcePort, Allowed: true, RequireNative: native, Action: dp.PolicyActionAllow, StartedAt: time.Now().Unix(), EventCursor: s.events.cursor()}
	s.previousStart = probe.StartedAt
	mac := ""
	if native {
		mac = s.expectedVerdict(pod, port, &probe)
	}
	err := flannelProbeOnce(s.t.Context(), client, pod, &probe)
	if err == nil && native {
		err = waitFlannelNative(s.t.Context(), s.events, client, pod, mac, &probe)
	}
	if native {
		probe.Observed, probe.ObservedLimit = s.events.observed(probe, client.IP, pod.IP)
	}
	s.probes = append(s.probes, probe)
	if err != nil {
		s.t.Fatal(err)
	}
}
func (s *flannelScenario) expectedVerdict(pod flannelPod, port uint16, probe *flannelProbe) string {
	for _, policy := range s.policies {
		if policy.PodBindings[0].PodName != pod.Name {
			continue
		}
		if policy.Rules[0].Port == port {
			id, err := networkPolicyWireID(policy.DPPolicyID)
			if err != nil {
				s.t.Fatal(err)
			}
			probe.PolicyID = id
			probe.Application = 1001
		} else {
			probe.Action = dp.PolicyActionViolate
			if policy.Mode == "enforce" {
				probe.Action = dp.PolicyActionDeny
				probe.Allowed = false
			}
		}
	}
	for _, endpoint := range s.supervisor.PolicyEndpoints() {
		if endpoint.PodUID == pod.UID && endpoint.Namespace == pod.Namespace && endpoint.PodName == pod.Name {
			return endpoint.MAC
		}
	}
	s.t.Fatal("exact current endpoint missing")
	return ""
}

func (s *flannelScenario) failOpen() {
	if err := stopOwnedFlannelDP(s.t.Context()); err != nil {
		s.t.Fatal(err)
	}
	s.wait("owned DP stopped, queue listener gone, no restart", s.queueListenersGone)
	s.phase("dp-stopped-bypass", false)
	for _, probe := range s.probes {
		if probe.Phase == "dp-stopped-bypass" && probe.After <= probe.Before {
			s.t.Fatal("fail-open did not traverse retained queue-bypass rules")
		}
	}
	life, _, _, _, _ := s.supervisor.StatsAll()
	if life.StartCount != 1 {
		s.t.Fatal("unexpected native restart during fail-open proof")
	}
}
func (s *flannelScenario) queueListenersGone() bool {
	if s.supervisor.Ready() {
		return false
	}
	for _, pod := range s.identity.Pods {
		if pod.Name == "client" {
			continue
		}
		present, err := flannelQueueListener(pod)
		if err != nil {
			s.t.Fatal(err)
		}
		if present {
			return false
		}
	}
	return true
}

func (s *flannelScenario) wait(description string, condition func() bool) {
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-s.t.Context().Done():
			s.t.Fatal(s.t.Context().Err())
		case <-deadline.C:
			s.t.Fatal("timeout: " + description)
		case <-ticker.C:
		}
	}
}
func (s *flannelScenario) pod(name string) flannelPod {
	for _, pod := range s.identity.Pods {
		if pod.Name == name {
			return pod
		}
	}
	s.t.Fatal("missing owned fixture pod")
	return flannelPod{}
}
func (s *flannelScenario) writeEvidence() {
	root, err := os.OpenRoot("/evidence")
	if err != nil {
		s.t.Error(err)
		return
	}
	body, encodeErr := json.MarshalIndent(struct {
		Identity  flannelIdentity     `json:"identity"`
		Endpoints []dp.PolicyEndpoint `json:"endpoints"`
		Probes    []flannelProbe      `json:"probes"`
		Passed    bool                `json:"passed"`
	}{s.identity, s.endpoints, s.probes, !s.t.Failed()}, "", "  ")
	if err := errors.Join(encodeErr, root.WriteFile("packet-evidence.json", body, 0o600), root.Close()); err != nil {
		s.t.Error(err)
	}
}
