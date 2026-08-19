package admission

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/alphabravocompany/constellation/pkg/quarantine"
)

// fakeLoader returns a fixed entry slice.
type fakeLoader struct{ entries []quarantine.Entry }

func (f *fakeLoader) Load(_ context.Context, _ uuid.UUID) ([]quarantine.Entry, error) {
	return f.entries, nil
}

func newSourceWith(t *testing.T, entries []quarantine.Entry) *quarantine.Source {
	t.Helper()
	src := quarantine.NewSource(&fakeLoader{entries: entries}, uuid.New(), time.Second)
	if err := src.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	return src
}

func TestEvaluate_Quarantine_DeniesNamespace(t *testing.T) {
	e := NewEngine()
	e.SetQuarantine(newSourceWith(t, []quarantine.Entry{{
		ID: uuid.New(), Scope: quarantine.ScopeNamespace, MatchKey: "tainted",
		Reason: "active incident", Origin: "manual", CreatedAt: time.Now(),
	}}))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tainted", Name: "any"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "alpine:3"}}},
	}
	resp := e.Evaluate(context.Background(), reviewFor(pod))
	if resp.Allowed {
		t.Fatal("quarantined namespace pod must be denied")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "quarantined by constellation") {
		t.Errorf("expected quarantine-branded message, got: %+v", resp.Result)
	}
	if !strings.Contains(resp.Result.Message, "active incident") {
		t.Error("deny message should carry the quarantine reason")
	}
}

func TestEvaluate_Quarantine_DeniesImage(t *testing.T) {
	e := NewEngine()
	e.SetQuarantine(newSourceWith(t, []quarantine.Entry{{
		ID: uuid.New(), Scope: quarantine.ScopeImage,
		MatchKey: "evil.example.com/", Reason: "untrusted registry",
		Origin: "auto", CreatedAt: time.Now(),
	}}))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "any"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "ok", Image: "alpine:3.18"},
			{Name: "bad", Image: "evil.example.com/payload:latest"},
		}},
	}
	resp := e.Evaluate(context.Background(), reviewFor(pod))
	if resp.Allowed {
		t.Fatal("image-quarantined pod must be denied")
	}
}

func TestEvaluate_Quarantine_BypassesMonitorMode(t *testing.T) {
	// Even if no enforce rules match the pod, quarantine still denies.
	// Tests the architectural claim that quarantine is not subject to
	// the policy state machine.
	e := NewEngine()
	// Pod is otherwise compliant — would only get monitor-mode warnings.
	t1 := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "any",
			Name:        "good",
			Annotations: map[string]string{SignatureAnnotation: "true"},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "c", Image: "alpine:3.18",
			SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: &t1},
		}}},
	}
	e.SetQuarantine(newSourceWith(t, []quarantine.Entry{{
		ID: uuid.New(), Scope: quarantine.ScopeNamespace,
		MatchKey: "any", Reason: "ns-wide block", Origin: "manual",
		CreatedAt: time.Now(),
	}}))
	resp := e.Evaluate(context.Background(), reviewFor(pod))
	if resp.Allowed {
		t.Fatal("quarantine must deny even when no rule would")
	}
}

func TestEvaluate_Quarantine_FiresOnDenyHook(t *testing.T) {
	e := NewEngine()
	got := make(chan DenyEvent, 1)
	e.OnDeny = func(_ context.Context, ev DenyEvent) { got <- ev }
	id := uuid.New()
	e.SetQuarantine(newSourceWith(t, []quarantine.Entry{{
		ID: id, Scope: quarantine.ScopeNamespace, MatchKey: "x",
		Reason: "incident-123", Origin: "auto", CreatedAt: time.Now(),
	}}))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "x", Name: "p"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "alpine:3"}}},
	}
	e.Evaluate(context.Background(), reviewFor(pod))
	select {
	case ev := <-got:
		if !strings.HasPrefix(ev.RuleID, "quarantine:") {
			t.Errorf("deny event RuleID should be prefixed with quarantine:, got %q", ev.RuleID)
		}
		if !strings.Contains(ev.RuleID, id.String()) {
			t.Errorf("deny event RuleID should carry the entry UUID, got %q", ev.RuleID)
		}
		if ev.Reason != "incident-123" {
			t.Errorf("deny event reason should be the quarantine reason, got %q", ev.Reason)
		}
	case <-time.After(time.Second):
		t.Fatal("OnDeny hook was not invoked")
	}
}

func TestEvaluate_Quarantine_NilSourceIsNoop(t *testing.T) {
	e := NewEngine()
	// e.Quarantine is nil by default — engine should behave exactly as
	// before E4 (this guards against accidentally requiring the source).
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "any", Name: "p"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "alpine:3"}}},
	}
	resp := e.Evaluate(context.Background(), reviewFor(pod))
	// Default rules will warn (monitor mode), not deny.
	if !resp.Allowed {
		t.Errorf("nil quarantine source should not affect existing rules; pod was denied: %+v", resp.Result)
	}
}
