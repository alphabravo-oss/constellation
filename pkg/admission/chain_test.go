package admission

import (
	"context"
	"sync/atomic"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// regoDenyByImage denies any pod whose first container image contains
// "forbidden/". No built-in rule cares about image names, so a deny here can
// ONLY come from the Rego engine running through the chain.
const regoDenyByImage = `
package constellation.admission

deny[msg] {
  input.request.kind.kind == "Pod"
  contains(input.request.object.spec.containers[_].image, "forbidden/")
  msg := "image from forbidden registry"
}
`

// TestChainEngine_RegoDenyDenies is the regression guard for ADM-1: an
// engine='opa' deny rule must actually deny through the composite chain. Before
// the chain existed the webhook only ran the built-in PolicyEngine, so a Rego
// deny silently failed open.
func TestChainEngine_RegoDenyDenies(t *testing.T) {
	ctx := context.Background()
	rego, errs, err := NewRegoEngine(ctx,
		map[string]string{"block-forbidden-registry": regoDenyByImage},
		map[string]string{"block-forbidden-registry": "enforce"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 0 {
		t.Fatalf("compile errs: %v", errs)
	}

	chain := NewChainEngine(NewEngine())

	// A pod the built-in catalog allows (not privileged, no hostNet/hostPID,
	// signed-annotation/rootfs rules are monitor-mode) but that the Rego rule
	// denies on its image name.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "evil", Annotations: map[string]string{SignatureAnnotation: "true"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "x", Image: "forbidden/app:1.0"}}},
	}

	// Without Rego attached the chain must allow it: proves the deny is the
	// Rego engine's doing, not a built-in rule.
	if resp := chain.Evaluate(ctx, reviewFor(pod)); !resp.Allowed {
		t.Fatalf("built-in engine should allow this pod; got deny %+v", resp.Result)
	}

	chain.SetRego(rego)
	resp := chain.Evaluate(ctx, reviewFor(pod))
	if resp.Allowed {
		t.Fatalf("chain must deny when an engine='opa' rule denies; result: %+v", resp.Result)
	}

	// Detaching Rego restores allow.
	chain.SetRego(nil)
	if resp := chain.Evaluate(ctx, reviewFor(pod)); !resp.Allowed {
		t.Fatalf("pod should pass once Rego detached: %+v", resp.Result)
	}
}

// TestChainEngine_RegoDenyFiresOnDeny is the regression guard for the
// half-wired finding: a Rego (engine='opa') enforce deny went through the chain
// without ever invoking the DenyHook, so it wrote no admission.deny audit row
// and fired no EventAdmission response rule. The chain must now fan the deny out
// to its DenyHook with the offending policy id.
func TestChainEngine_RegoDenyFiresOnDeny(t *testing.T) {
	ctx := context.Background()
	rego, _, err := NewRegoEngine(ctx,
		map[string]string{"block-forbidden-registry": regoDenyByImage},
		map[string]string{"block-forbidden-registry": "enforce"},
	)
	if err != nil {
		t.Fatal(err)
	}

	got := make(chan DenyEvent, 1)
	chain := NewChainEngine(NewEngine())
	chain.SetOnDeny(func(_ context.Context, ev DenyEvent) { got <- ev })
	chain.SetRego(rego)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "evil", Namespace: "team-a", Annotations: map[string]string{SignatureAnnotation: "true"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "x", Image: "forbidden/app:1.0"}}},
	}
	req := reviewFor(pod)
	req.Namespace = "team-a"
	req.Operation = "CREATE"
	req.UserInfo = authenticationv1.UserInfo{Username: "dev@corp"}

	resp := chain.Evaluate(ctx, req)
	if resp.Allowed {
		t.Fatalf("chain must deny the rego-forbidden pod: %+v", resp.Result)
	}
	select {
	case ev := <-got:
		if ev.RuleID != "block-forbidden-registry" {
			t.Fatalf("deny event rule id = %q, want block-forbidden-registry", ev.RuleID)
		}
		if ev.Namespace != "team-a" || ev.Pod != "evil" {
			t.Fatalf("deny event target = %s/%s, want team-a/evil", ev.Namespace, ev.Pod)
		}
		if ev.Operation != "CREATE" || ev.UserInfo != "dev@corp" {
			t.Fatalf("deny event op/user = %s/%s", ev.Operation, ev.UserInfo)
		}
		if ev.Reason == "" {
			t.Fatalf("deny event reason should carry the rego message")
		}
	default:
		t.Fatal("OnDeny hook was not invoked for a rego deny")
	}
}

// TestChainEngine_CELDenyFiresOnDeny is the CEL counterpart: a CEL enforce deny
// must also reach the chain's DenyHook.
func TestChainEngine_CELDenyFiresOnDeny(t *testing.T) {
	ctx := context.Background()
	// Deny on image name — something no built-in rule cares about — so the deny
	// can only come from the CEL engine (proving the chain fired the hook, not
	// the PolicyEngine).
	cel, errs, err := NewCELEngine([]*CELRule{{
		ID:                "block-forbidden-image",
		Expression:        `object.spec.containers.all(c, !c.image.contains("forbidden/"))`,
		MessageExpression: `"image from forbidden registry"`,
		Mode:              "enforce",
	}})
	if err != nil || len(errs) != 0 {
		t.Fatalf("cel compile: %v %v", err, errs)
	}

	got := make(chan DenyEvent, 1)
	chain := NewChainEngine(NewEngine())
	chain.SetOnDeny(func(_ context.Context, ev DenyEvent) { got <- ev })
	chain.SetCEL(cel)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "evil", Namespace: "team-b", Annotations: map[string]string{SignatureAnnotation: "true"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "x", Image: "forbidden/app:1.0"}}},
	}
	req := reviewFor(pod)
	req.Namespace = "team-b"

	// Sanity: built-ins alone allow this pod.
	if resp := NewChainEngine(NewEngine()).Evaluate(ctx, req); !resp.Allowed {
		t.Fatalf("built-ins should allow this pod; got deny %+v", resp.Result)
	}

	resp := chain.Evaluate(ctx, req)
	if resp.Allowed {
		t.Fatalf("chain must deny the forbidden-image pod via CEL: %+v", resp.Result)
	}
	select {
	case ev := <-got:
		if ev.RuleID != "block-forbidden-image" {
			t.Fatalf("deny event rule id = %q, want block-forbidden-image", ev.RuleID)
		}
		if ev.Namespace != "team-b" || ev.Pod != "evil" {
			t.Fatalf("deny event target = %s/%s", ev.Namespace, ev.Pod)
		}
	default:
		t.Fatal("OnDeny hook was not invoked for a cel deny")
	}
}

// TestChainEngine_PolicyDenyDoesNotDoubleFire guards against the chain
// re-firing OnDeny for a built-in PolicyEngine deny — the PolicyEngine already
// fires its own OnDeny, so the chain must stay silent on that path (exactly one
// event total).
func TestChainEngine_PolicyDenyDoesNotDoubleFire(t *testing.T) {
	ctx := context.Background()
	var count int32
	policy := NewEngine()
	policy.OnDeny = func(_ context.Context, _ DenyEvent) { atomic.AddInt32(&count, 1) }
	chain := NewChainEngine(policy)
	// Same hook on the chain — a correct implementation still fires only once
	// because the policy deny short-circuits before the chain's own fan-out.
	chain.SetOnDeny(func(_ context.Context, _ DenyEvent) { atomic.AddInt32(&count, 1) })

	priv := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "c", Image: "alpine", SecurityContext: &corev1.SecurityContext{Privileged: &priv},
		}}},
	}
	if resp := chain.Evaluate(ctx, reviewFor(pod)); resp.Allowed {
		t.Fatal("privileged pod must be denied by the built-in engine")
	}
	if got := atomic.LoadInt32(&count); got != 1 {
		t.Fatalf("OnDeny fired %d times for a built-in deny, want exactly 1", got)
	}
}
