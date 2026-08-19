package admission

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestEvaluate_MonitorMatchFiresHook proves a MONITOR-mode rule match now fires
// the DenyHook with Monitor=true (the parity gap P0-02: monitor violations were
// previously only transient kubectl warnings, never audited or counted). It fails
// against the old code, where the monitor branch only appended a warning.
func TestEvaluate_MonitorMatchFiresHook(t *testing.T) {
	e := NewEngine() // DefaultRules ships require-image-signature in monitor mode
	var events []DenyEvent
	e.OnDeny = func(_ context.Context, ev DenyEvent) { events = append(events, ev) }

	// An unsigned, read-only-rootfs pod: it violates only the two monitor rules
	// (require-image-signature, require-read-only-rootfs) and no enforce rule, so
	// the request is admitted but must produce monitor events.
	ro := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app", Image: "ghcr.io/acme/web:1.0",
				SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: &ro},
			}},
		},
	}

	resp := e.Evaluate(context.Background(), reviewFor(pod))
	if !resp.Allowed {
		t.Fatalf("monitor-only match must still admit; got denied: %v", resp.Result)
	}
	if len(events) != 1 {
		t.Fatalf("expected exactly one monitor event, got %d: %+v", len(events), events)
	}
	ev := events[0]
	if !ev.Monitor {
		t.Fatalf("event must be flagged Monitor=true: %+v", ev)
	}
	if ev.RuleID != "require-image-signature" {
		t.Fatalf("rule id = %q, want require-image-signature", ev.RuleID)
	}
	if ev.Namespace != "prod" || ev.Pod != "web" {
		t.Fatalf("target = %s/%s, want prod/web", ev.Namespace, ev.Pod)
	}
}

// TestEvaluate_EnforceDenyIsNotMonitor guards the discriminator: an enforce deny
// must still fire with Monitor=false so response rules keep running for it.
func TestEvaluate_EnforceDenyIsNotMonitor(t *testing.T) {
	e := NewEngine()
	var events []DenyEvent
	e.OnDeny = func(_ context.Context, ev DenyEvent) { events = append(events, ev) }

	priv := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "evil", Namespace: "prod"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "c", Image: "alpine:3.18",
				SecurityContext: &corev1.SecurityContext{Privileged: &priv},
			}},
		},
	}

	resp := e.Evaluate(context.Background(), reviewFor(pod))
	if resp.Allowed {
		t.Fatalf("privileged pod must be denied")
	}
	if len(events) != 1 || events[0].Monitor {
		t.Fatalf("enforce deny must fire exactly one non-monitor event: %+v", events)
	}
}
