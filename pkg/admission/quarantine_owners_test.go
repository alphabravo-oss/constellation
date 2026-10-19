package admission

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/alphabravocompany/constellation/pkg/quarantine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"time"
)

type ownerStub struct {
	calls int
	err   error
}

func (r *ownerStub) Parent(ctx context.Context, ns string, owner metav1.OwnerReference) (*metav1.OwnerReference, error) {
	r.calls++
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > time.Second {
		panic("lookup must be bounded")
	}
	if r.err != nil {
		return nil, r.err
	}
	if owner.Name == "web-hash" {
		return &metav1.OwnerReference{Kind: "Deployment", Name: "web"}, nil
	}
	return &metav1.OwnerReference{Kind: "Deployment", Name: "api"}, nil
}
func TestDeploymentQuarantineFollowsVerifiedReplicaSetOwner(t *testing.T) {
	yes := true
	for _, tc := range []struct {
		namespace, rs string
		resolverError bool
		allowed       bool
	}{{"payments", "api-old", false, false}, {"payments", "api-new", false, false}, {"payments", "api-new", true, false}, {"other", "api-new", true, true}, {"payments", "web-hash", false, true}} {
		e := NewEngine()
		e.SetQuarantine(newSourceWith(t, []quarantine.Entry{{Scope: quarantine.ScopeWorkload, MatchKey: "payments/api"}}))
		r := &ownerStub{}
		if tc.resolverError {
			r.err = errors.New("owner lookup failed")
		}
		e.SetWorkloadOwners(r)
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: tc.namespace, Name: "pod-new", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: tc.rs, UID: "uid", Controller: &yes}}}}
		result := e.Evaluate(t.Context(), reviewFor(pod))
		if result.Allowed != tc.allowed {
			t.Fatalf("%+v allowed=%v", tc, result.Allowed)
		}
		if tc.namespace == "other" && r.calls != 0 {
			t.Fatal("lookup ran without a workload quarantine in namespace")
		}
	}
	e := NewEngine()
	e.SetQuarantine(newSourceWith(t, []quarantine.Entry{{Scope: quarantine.ScopeWorkload, MatchKey: "payments/api"}}))
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "pod", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api-hash", UID: "uid", Controller: &yes}}}}
	if e.Evaluate(t.Context(), reviewFor(pod)).Allowed {
		t.Fatal("missing resolver bypassed workload quarantine")
	}
}

func TestControllerQuarantineUsesObjectIdentityNotTemplateName(t *testing.T) {
	yes := true
	for _, kind := range []string{"Deployment", "ReplicaSet", "Job"} {
		e := NewEngine()
		e.SetQuarantine(newSourceWith(t, []quarantine.Entry{{Scope: quarantine.ScopeWorkload, MatchKey: "payments/api"}}))
		metadata := metav1.ObjectMeta{Name: "api", Namespace: "payments"}
		if kind != "Deployment" {
			metadata.Name = "generated-child"
			metadata.OwnerReferences = []metav1.OwnerReference{{Name: "api", Kind: "Deployment", Controller: &yes}}
		}
		raw, _ := json.Marshal(map[string]any{"metadata": metadata, "spec": map[string]any{"template": corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "elsewhere"}}}})
		request := reviewForKind(kind, raw)
		request.Namespace = "payments"
		if e.Evaluate(t.Context(), request).Allowed {
			t.Fatalf("%s template metadata bypassed controller quarantine", kind)
		}
	}
}

func TestQuarantineAcceptsRuntimeTypedWorkloadKeys(t *testing.T) {
	yes := true
	for _, key := range []string{"payments/api", "payments/Deployment/api", "payments/deployment/api"} {
		e := NewEngine()
		e.SetQuarantine(newSourceWith(t, []quarantine.Entry{{Scope: quarantine.ScopeWorkload, MatchKey: key}}))
		e.SetWorkloadOwners(&ownerStub{})
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "pod", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "new-rs", UID: "uid", Controller: &yes}}}}
		if e.Evaluate(t.Context(), reviewFor(pod)).Allowed {
			t.Fatalf("typed quarantine key missed: %s", key)
		}
	}
}
