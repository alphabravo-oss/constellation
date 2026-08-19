package k8saudit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// mkEvent builds a minimal AuditEvent for classify() tests.
func mkEvent(verb, group, resource, sub string) *AuditEvent {
	ev := &AuditEvent{Verb: verb}
	ev.ObjectRef.APIGroup = group
	ev.ObjectRef.Resource = resource
	ev.ObjectRef.Subresource = sub
	return ev
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name       string
		ev         *AuditEvent
		wantSignal string
		wantHigh   bool
	}{
		{"pod exec", mkEvent("create", "", "pods", "exec"), SignalPodExec, true},
		{"pod attach", mkEvent("create", "", "pods", "attach"), SignalPodExec, true},
		{"secret get", mkEvent("get", "", "secrets", ""), SignalSecretAccess, true},
		{"secret list", mkEvent("list", "", "secrets", ""), SignalSecretAccess, true},
		{"secret create (write, not read)", mkEvent("create", "", "secrets", ""), "", false},
		{"rbac rolebinding create", mkEvent("create", "rbac.authorization.k8s.io", "rolebindings", ""), SignalRBACChange, true},
		{"rbac clusterrole delete", mkEvent("delete", "rbac.authorization.k8s.io", "clusterroles", ""), SignalRBACChange, true},
		{"rbac get (read, not change)", mkEvent("get", "rbac.authorization.k8s.io", "roles", ""), "", false},
		{"plain pod create without spec", mkEvent("create", "", "pods", ""), "", false},
		{"pod log read is not exec", mkEvent("get", "", "pods", "log"), "", false},
		{"routine configmap get", mkEvent("get", "", "configmaps", ""), "", false},
		{"uppercase verb normalized", mkEvent("GET", "", "secrets", ""), SignalSecretAccess, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signal, severity, high := classify(tc.ev)
			if signal != tc.wantSignal || high != tc.wantHigh {
				t.Fatalf("classify()=(%q,%q,%v), want signal=%q high=%v", signal, severity, high, tc.wantSignal, tc.wantHigh)
			}
			if high && severity != "high" {
				t.Fatalf("high-signal event should be severity=high, got %q", severity)
			}
		})
	}
}

func TestClassifyPrivilegedCreate(t *testing.T) {
	priv := true
	spec := map[string]any{
		"spec": map[string]any{
			"containers": []any{
				map[string]any{"securityContext": map[string]any{"privileged": priv}},
			},
		},
	}
	raw, _ := json.Marshal(spec)
	ev := mkEvent("create", "", "pods", "")
	ev.RequestObject = raw
	signal, _, high := classify(ev)
	if signal != SignalPrivilegedCreate || !high {
		t.Fatalf("privileged pod create should classify, got signal=%q high=%v", signal, high)
	}

	// hostNetwork pod is also privileged posture.
	hostNet, _ := json.Marshal(map[string]any{"spec": map[string]any{"hostNetwork": true}})
	ev2 := mkEvent("create", "", "pods", "")
	ev2.RequestObject = hostNet
	if s, _, h := classify(ev2); s != SignalPrivilegedCreate || !h {
		t.Fatalf("hostNetwork pod should classify, got signal=%q high=%v", s, h)
	}

	// Non-privileged pod spec => not high-signal.
	safe, _ := json.Marshal(map[string]any{"spec": map[string]any{"containers": []any{map[string]any{}}}})
	ev3 := mkEvent("create", "", "pods", "")
	ev3.RequestObject = safe
	if s, _, h := classify(ev3); s != "" || h {
		t.Fatalf("safe pod should not classify, got signal=%q high=%v", s, h)
	}
}

func TestDecisionAndSourceIP(t *testing.T) {
	ev := &AuditEvent{
		Annotations: map[string]string{"authorization.k8s.io/decision": "Forbid"},
		SourceIPs:   []string{"10.1.2.3", "10.9.9.9"},
	}
	if got := ev.decision(); got != "forbid" {
		t.Fatalf("decision()=%q, want forbid", got)
	}
	if got := ev.sourceIP(); got != "10.1.2.3" {
		t.Fatalf("sourceIP()=%q, want 10.1.2.3", got)
	}
	empty := &AuditEvent{}
	if empty.decision() != "" || empty.sourceIP() != "" {
		t.Fatalf("empty event should yield empty decision/sourceIP")
	}
}

func TestDedupCollapsesRepeats(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	d := newAuditDedup(60 * time.Second)
	d.now = func() time.Time { return base }

	p := &pendingAlert{signal: SignalSecretAccess, ev: mkEvent("get", "", "secrets", "")}
	p.ev.User.Username = "system:serviceaccount:kube-system:controller"
	p.ev.ObjectRef.Namespace = "kube-system"
	p.ev.ObjectRef.Name = "sa-token"
	org := uuid.New()
	key := dedupKey(org, p)

	if !d.allow(key) {
		t.Fatal("first hit should alert")
	}
	if d.allow(key) {
		t.Fatal("identical hit within window should be suppressed")
	}
	// After the window elapses the next hit re-fires.
	d.now = func() time.Time { return base.Add(61 * time.Second) }
	if !d.allow(key) {
		t.Fatal("hit after window should re-fire")
	}
}

func TestDecodeAuditItemsEventListAndArray(t *testing.T) {
	list := `{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[{"verb":"get"},{"verb":"list"}]}`
	items, err := decodeAuditItems(strings.NewReader(list))
	if err != nil || len(items) != 2 {
		t.Fatalf("EventList decode: items=%d err=%v", len(items), err)
	}
	arr := `[{"verb":"get"}]`
	items, err = decodeAuditItems(strings.NewReader(arr))
	if err != nil || len(items) != 1 {
		t.Fatalf("array decode: items=%d err=%v", len(items), err)
	}
}
