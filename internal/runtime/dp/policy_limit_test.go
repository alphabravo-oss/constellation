package dp

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestEndpointPolicyExpandedLimitBeforeAnyIPC(t *testing.T) {
	server := newCaptureServer(t)
	client := newClientPointedAt(t, server)
	supervisor, endpoint := boundedPolicySupervisor(client)
	policy := &WorkloadPolicy{MACs: []string{endpoint.MAC}, DefAction: PolicyActionDeny, Rules: make([]*PolicyRule, MaxExpandedPolicyRules+1)}
	if err := supervisor.PushEndpointPolicy(policy, CmdModify, &endpoint, 1); err == nil || !strings.Contains(err.Error(), "65536") {
		t.Fatalf("over-limit real dispatch accepted: %v", err)
	}
	if messages := server.drain(1); len(messages) != 0 {
		t.Fatal("over-limit candidate emitted IPC")
	}
	policy.Rules = policy.Rules[:MaxExpandedPolicyRules]
	rule := &PolicyRule{ID: 11, Action: PolicyActionAllow, SrcIP: net.ParseIP("10.0.0.1").To4(), DstIP: net.ParseIP("203.0.113.8").To4(), Port: 443, PortR: 443, IPProto: IPProtoTCP}
	for index := range policy.Rules {
		policy.Rules[index] = rule
	}
	result := make(chan error, 1)
	go func() { result <- supervisor.PushEndpointPolicy(policy, CmdModify, &endpoint, 1) }()
	count := 0
	for {
		messages := server.drain(1)
		if len(messages) != 1 || len(messages[0]) > maxPolicyMsgSize {
			t.Fatal("limit table missing/oversized fragment")
		}
		var request policyCfgReq
		if err := json.Unmarshal(messages[0], &request); err != nil {
			t.Fatal(err)
		}
		count += len(request.Cfg.IPRules)
		if request.Cfg.Flag&MsgEnd != 0 {
			break
		}
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if count != MaxExpandedPolicyRules {
		t.Fatalf("transferred%d expected%d", count, MaxExpandedPolicyRules)
	}
}

func boundedPolicySupervisor(client *dpClient) (*Supervisor, PolicyEndpoint) {
	manager := newTapManager(client, &fakeTapProvider{}, newSilentLogger(), time.Second)
	endpoint := PolicyEndpoint{MAC: "02:00:00:00:00:01", Namespace: "ns", PodName: "pod", PodUID: "uid", Registration: 1}
	manager.current["test"] = TapTarget{EPMAC: endpoint.MAC, Namespace: endpoint.Namespace, PodName: endpoint.PodName, PodUID: endpoint.PodUID, Registration: 1}
	supervisor := &Supervisor{client: client, taps: manager}
	supervisor.generation.Store(1)
	supervisor.activeGen.Store(1)
	supervisor.readyGen.Store(1)
	return supervisor, endpoint
}
