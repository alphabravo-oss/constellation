package runtime

import (
	"net"
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

func TestEvaluateFlow_FirstMatchWins(t *testing.T) {
	// Two rules: first allows port 80, second denies all. A port-80 flow
	// should hit the first rule and return allow.
	rules := []*dp.PolicyRule{
		{Ingress: false, IPProto: 6, Port: 80, Action: dp.PolicyActionAllow},
		{Ingress: false, IPProto: 6, Port: 0 /* any */, Action: dp.PolicyActionDeny},
	}
	flow := EvaluatedFlow{
		Workload: "default/api", SrcWorkload: "default/api",
		DstWorkload: "external", Protocol: "tcp", DstPort: 80,
	}
	got, isDefault := EvaluateFlow(rules, dp.PolicyActionAllow, false, flow)
	if got != EvalActionAllow {
		t.Errorf("port 80 got %s want allow", got)
	}
	if isDefault {
		t.Errorf("isDefault true but rule matched")
	}
	// Port 443 misses the first rule, hits the deny-all.
	flow.DstPort = 443
	got, _ = EvaluateFlow(rules, dp.PolicyActionAllow, false, flow)
	if got != EvalActionDeny {
		t.Errorf("port 443 got %s want deny", got)
	}
}

func TestEvaluateFlow_DefaultWhenNoMatch(t *testing.T) {
	// Rule only matches port 22; an http flow should hit def_action=Allow.
	rules := []*dp.PolicyRule{
		{Ingress: false, IPProto: 6, Port: 22, Action: dp.PolicyActionDeny},
	}
	flow := EvaluatedFlow{
		Workload: "default/api", SrcWorkload: "default/api",
		Protocol: "tcp", DstPort: 80,
	}
	got, isDefault := EvaluateFlow(rules, dp.PolicyActionAllow, false, flow)
	if got != EvalActionAllow {
		t.Errorf("default got %s want allow", got)
	}
	if !isDefault {
		t.Errorf("expected isDefault=true (no rule matched)")
	}
}

func TestEvaluateFlow_MonitorDemote(t *testing.T) {
	// honorMonitorDemote=true rewrites deny → monitor on the wire so the
	// simulation shows what would actually be enforced under monitor mode.
	rules := []*dp.PolicyRule{
		{Ingress: false, IPProto: 6, Port: 80, Action: dp.PolicyActionDeny},
	}
	flow := EvaluatedFlow{
		Workload: "default/api", SrcWorkload: "default/api",
		Protocol: "tcp", DstPort: 80,
	}
	got, _ := EvaluateFlow(rules, dp.PolicyActionAllow, true /* demote */, flow)
	if got != EvalActionMonitor {
		t.Errorf("monitor demote got %s want monitor", got)
	}
	// Without demote, same rule shows deny.
	got, _ = EvaluateFlow(rules, dp.PolicyActionAllow, false, flow)
	if got != EvalActionDeny {
		t.Errorf("enforce mode got %s want deny", got)
	}
}

func TestEvaluateFlow_DirectionFilter(t *testing.T) {
	// Ingress rule should not match egress traffic.
	ingressRule := []*dp.PolicyRule{
		{Ingress: true, IPProto: 6, Port: 80, Action: dp.PolicyActionDeny},
	}
	egress := EvaluatedFlow{
		Workload: "default/api", SrcWorkload: "default/api",
		DstWorkload: "external", Protocol: "tcp", DstPort: 80,
	}
	got, isDefault := EvaluateFlow(ingressRule, dp.PolicyActionAllow, false, egress)
	if got != EvalActionAllow || !isDefault {
		t.Errorf("ingress rule should not match egress flow: got %s default=%v", got, isDefault)
	}
	// Same rule on an ingress flow matches.
	ingress := EvaluatedFlow{
		Workload: "default/api", SrcWorkload: "external", DstWorkload: "default/api",
		Protocol: "tcp", DstPort: 80,
	}
	got, _ = EvaluateFlow(ingressRule, dp.PolicyActionAllow, false, ingress)
	if got != EvalActionDeny {
		t.Errorf("ingress flow with matching ingress rule: got %s want deny", got)
	}
}

func TestEvaluateFlow_PortRange(t *testing.T) {
	rules := []*dp.PolicyRule{
		{Ingress: false, IPProto: 6, Port: 8000, PortR: 8999, Action: dp.PolicyActionDeny},
	}
	cases := map[int]EvalAction{
		7999: EvalActionAllow, // below range
		8000: EvalActionDeny,  // lower bound
		8500: EvalActionDeny,
		8999: EvalActionDeny,  // upper bound
		9000: EvalActionAllow, // above
	}
	for port, want := range cases {
		flow := EvaluatedFlow{
			Workload: "default/api", SrcWorkload: "default/api",
			Protocol: "tcp", DstPort: port,
		}
		got, _ := EvaluateFlow(rules, dp.PolicyActionAllow, false, flow)
		if got != want {
			t.Errorf("port %d got %s want %s", port, got, want)
		}
	}
}

func TestEvaluateFlow_IPMatchAndRange(t *testing.T) {
	rules := []*dp.PolicyRule{
		{
			Ingress: false, IPProto: 6, Port: 0,
			DstIP:  net.ParseIP("10.0.0.0"),
			DstIPR: net.ParseIP("10.0.0.255"),
			Action: dp.PolicyActionDeny,
		},
	}
	cases := map[string]EvalAction{
		"10.0.0.0":   EvalActionDeny,
		"10.0.0.128": EvalActionDeny,
		"10.0.0.255": EvalActionDeny,
		"10.0.1.0":   EvalActionAllow, // outside range
		"8.8.8.8":    EvalActionAllow,
	}
	for ip, want := range cases {
		flow := EvaluatedFlow{
			Workload: "default/api", SrcWorkload: "default/api",
			Protocol: "tcp", DstPort: 80, DstAddr: ip,
		}
		got, _ := EvaluateFlow(rules, dp.PolicyActionAllow, false, flow)
		if got != want {
			t.Errorf("ip %s got %s want %s", ip, got, want)
		}
	}
}

func TestEvaluateBatch_CountsAndSamples(t *testing.T) {
	rules := []*dp.PolicyRule{
		{Ingress: false, IPProto: 6, Port: 80, Action: dp.PolicyActionAllow},
		{Ingress: false, IPProto: 6, Port: 443, Action: dp.PolicyActionDeny},
	}
	wl := "default/api"
	make := func(port int) EvaluatedFlow {
		return EvaluatedFlow{
			Workload: wl, SrcWorkload: wl, DstWorkload: "external",
			Protocol: "tcp", DstPort: port,
		}
	}
	flows := []EvaluatedFlow{
		make(80), make(80), make(443), make(443), make(443),
		make(9999), // no rule matches → def_action allow
	}
	rows := []*FlowSampleRow{
		{Src: wl, Dst: "external", DstPort: 80, Protocol: "tcp", Bytes: 100},
		{Src: wl, Dst: "external", DstPort: 80, Protocol: "tcp", Bytes: 200},
		{Src: wl, Dst: "external", DstPort: 443, Protocol: "tcp", Bytes: 50},
		{Src: wl, Dst: "external", DstPort: 443, Protocol: "tcp", Bytes: 60},
		{Src: wl, Dst: "external", DstPort: 443, Protocol: "tcp", Bytes: 70},
		{Src: wl, Dst: "external", DstPort: 9999, Protocol: "tcp", Bytes: 5},
	}
	got := EvaluateBatch(rules, dp.PolicyActionAllow, false, wl, flows, rows)
	if got.Total != 6 {
		t.Errorf("total=%d want 6", got.Total)
	}
	if got.Allow != 3 { // 2 port-80 + 1 default
		t.Errorf("allow=%d want 3", got.Allow)
	}
	if got.Deny != 3 {
		t.Errorf("deny=%d want 3", got.Deny)
	}
	if got.Default != 1 {
		t.Errorf("default=%d want 1", got.Default)
	}
	if len(got.Samples["allow"]) != 3 {
		t.Errorf("allow samples=%d want 3", len(got.Samples["allow"]))
	}
	if len(got.Samples["deny"]) != 3 {
		t.Errorf("deny samples=%d want 3", len(got.Samples["deny"]))
	}
}

func TestEvaluateFlow_L7AppFilter(t *testing.T) {
	// Rule that only matches HTTP (app id 1001).
	rules := []*dp.PolicyRule{
		{
			Ingress: false, IPProto: 6, Port: 0,
			Apps:   []dp.PolicyApp{{App: 1001, Action: dp.PolicyActionDeny}},
			Action: dp.PolicyActionDeny,
		},
	}
	httpFlow := EvaluatedFlow{
		Workload: "default/api", SrcWorkload: "default/api",
		Protocol: "tcp", DstPort: 8080, Application: 1001,
	}
	got, _ := EvaluateFlow(rules, dp.PolicyActionAllow, false, httpFlow)
	if got != EvalActionDeny {
		t.Errorf("http flow got %s want deny", got)
	}
	// A non-HTTP flow on the same port misses the rule.
	mysqlFlow := httpFlow
	mysqlFlow.Application = 2001 // mysql
	got, _ = EvaluateFlow(rules, dp.PolicyActionAllow, false, mysqlFlow)
	if got != EvalActionAllow {
		t.Errorf("mysql flow got %s want allow (default)", got)
	}
}
