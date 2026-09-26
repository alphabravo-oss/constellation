package k8saudit

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/response"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

func TestLegacyTagOutcomePreservesSuppressLog(t *testing.T) {
	databaseURL := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://test:test@localhost:15433/constellation_test?sslmode=disable"
	}
	database, err := db.Connect(context.Background(), databaseURL)
	if err != nil {
		t.Skipf("skipping: cannot reach test DB (%v)", err)
	}
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "legacy-tag-k8saudit-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID) })

	for _, suppressed := range []bool{false, true} {
		name := "unsuppressed"
		if suppressed {
			name = "suppressed"
		}
		t.Run(name, func(t *testing.T) {
			auditID := uuid.NewString()
			responded := 0
			h := NewIngest(database).WithAudit(audit.New(pool)).WithResponseRuleEngine(func(_ context.Context, _ uuid.UUID, ev *responserule.Event) ([]responserule.Action, error) {
				if ev.Type != responserule.EventAdmission || ev.Fields["kind"] != "k8s_audit" {
					t.Fatalf("unexpected rule event: %+v", ev)
				}
				actions := []responserule.Action{{Type: responserule.ActionTag, Params: map[string]string{"key": "team", "value": "sec"}}}
				if suppressed {
					actions = append([]responserule.Action{{Type: responserule.ActionSuppressLog}}, actions...)
				}
				return actions, nil
			})
			h.WithResponseEngine(func(_ context.Context, _, _ uuid.UUID, _ response.Event) { responded++ })
			pending := &pendingAlert{ev: &AuditEvent{AuditID: auditID, Verb: "get"}, signal: SignalSecretAccess, severity: "high"}
			alerted := h.fanOutOne(ctx, orgID, pending)
			if alerted == suppressed || responded != 1 {
				t.Fatalf("alerted=%v responded=%d, suppressed=%v", alerted, responded, suppressed)
			}
			var enforced, reason, key, value string
			var order int
			if err := pool.QueryRow(ctx, `
SELECT after->>'enforced', after->>'enforce_error', after->>'param_key', after->>'param_value', (after->>'order')::int
  FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action='response_rule.action.tag'`, orgID, auditID).
				Scan(&enforced, &reason, &key, &value, &order); err != nil {
				t.Fatalf("query tag outcome: %v", err)
			}
			wantOrder := 0
			if suppressed {
				wantOrder = 1
			}
			if enforced != "unsupported" || reason == "" || key != "team" || value != "sec" || order != wantOrder {
				t.Fatalf("tag outcome=(%q,%q,%q,%q,%d), want unsupported with reason, params and order %d", enforced, reason, key, value, order, wantOrder)
			}
			var signalRows int
			if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action=$3`, orgID, auditID, "k8s.audit."+SignalSecretAccess).Scan(&signalRows); err != nil {
				t.Fatal(err)
			}
			if (signalRows == 0) != suppressed {
				t.Fatalf("signal audit rows=%d, suppressed=%v", signalRows, suppressed)
			}
		})
	}
}

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
