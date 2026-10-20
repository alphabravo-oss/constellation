package admission

import (
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func reductionReview(t *testing.T, kind string, before, after any) *admissionv1.AdmissionRequest {
	t.Helper()
	resources := map[string]string{"ReplicaSet": "replicasets", "Deployment": "deployments", "StatefulSet": "statefulsets"}
	object := func(count any) []byte {
		spec := map[string]any{"replicas": count, "selector": map[string]any{"matchLabels": map[string]any{"app": "test"}}, "template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "test"}}, "spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "registry.invalid/stale:v1"}}}}}
		if count == nil {
			delete(spec, "replicas")
		}
		b, err := json.Marshal(map[string]any{"apiVersion": "apps/v1", "kind": kind, "metadata": map[string]any{"uid": "controller-id", "name": "test", "namespace": "test"}, "spec": spec})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return &admissionv1.AdmissionRequest{UID: "review-id", Operation: admissionv1.Update, Name: "test", Namespace: "test", Kind: metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: kind}, Resource: metav1.GroupVersionResource{Group: "apps", Version: "v1", Resource: resources[kind]}, OldObject: runtime.RawExtension{Raw: object(before)}, Object: runtime.RawExtension{Raw: object(after)}}
}

func TestReplicaReductionAllowsStaleTemplateRetirement(t *testing.T) {
	e := &PolicyEngine{Rules: []Rule{mustProfileRule(t, "critical-vulnerabilities-blocked", "block-critical-vulnerabilities")}, Evidence: fakeEvidenceSource{reason: "scan result is stale"}}
	for _, kind := range []string{"ReplicaSet", "Deployment", "StatefulSet"} {
		for _, counts := range [][2]any{{2, 1}, {1, 0}, {nil, 0}, {2, nil}} {
			req := reductionReview(t, kind, counts[0], counts[1])
			if !isReplicaReduction(req) {
				t.Fatalf("not recognized: %s %v", kind, counts)
			}
			if r := e.Evaluate(t.Context(), req); !r.Allowed || r.UID != req.UID {
				t.Fatalf("retirement denied: %+v", r)
			}
		}
	}
	for _, counts := range [][2]any{{0, 1}, {1, 1}, {0, 0}, {1, 2}} {
		if r := e.Evaluate(t.Context(), reductionReview(t, "ReplicaSet", counts[0], counts[1])); r.Allowed {
			t.Fatalf("stale template admitted for %v", counts)
		}
	}
}

func TestReplicaReductionRejectsOtherChanges(t *testing.T) {
	mutations := map[string]func(*admissionv1.AdmissionRequest){
		"create":               func(r *admissionv1.AdmissionRequest) { r.Operation = admissionv1.Create },
		"subresource":          func(r *admissionv1.AdmissionRequest) { r.SubResource = "status" },
		"foreign kind group":   func(r *admissionv1.AdmissionRequest) { r.Kind.Group = "other" },
		"foreign resource":     func(r *admissionv1.AdmissionRequest) { r.Resource.Resource = "other" },
		"missing old object":   func(r *admissionv1.AdmissionRequest) { r.OldObject.Raw = nil },
		"malformed old object": func(r *admissionv1.AdmissionRequest) { r.OldObject.Raw = []byte("{") },
	}
	edit := func(r *admissionv1.AdmissionRequest, fn func(map[string]any)) {
		var x map[string]any
		if err := json.Unmarshal(r.Object.Raw, &x); err != nil {
			t.Fatal(err)
		}
		fn(x)
		r.Object.Raw, _ = json.Marshal(x)
	}
	for name, fn := range map[string]func(map[string]any){
		"image": func(x map[string]any) {
			x["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["image"] = "evil/new:v2"
		},
		"new spec field": func(x map[string]any) { x["spec"].(map[string]any)["futureOption"] = true },
		"selector":       func(x map[string]any) { x["spec"].(map[string]any)["selector"] = map[string]any{} },
		"template labels": func(x map[string]any) {
			x["spec"].(map[string]any)["template"].(map[string]any)["metadata"] = map[string]any{}
		},
		"uid":                 func(x map[string]any) { x["metadata"].(map[string]any)["uid"] = "different" },
		"namespace":           func(x map[string]any) { x["metadata"].(map[string]any)["namespace"] = "different" },
		"fractional replicas": func(x map[string]any) { x["spec"].(map[string]any)["replicas"] = 0.5 },
		"negative replicas":   func(x map[string]any) { x["spec"].(map[string]any)["replicas"] = -1 },
		"null replicas":       func(x map[string]any) { x["spec"].(map[string]any)["replicas"] = nil },
	} {
		mutations[name] = func(r *admissionv1.AdmissionRequest) { edit(r, fn) }
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := reductionReview(t, "ReplicaSet", 2, 1)
			mutate(r)
			if isReplicaReduction(r) {
				t.Fatal("unrelated or malformed update exempted")
			}
		})
	}
}

func TestReplicaReductionStillEvaluatesCustomRego(t *testing.T) {
	rego, errs, err := NewRegoEngine(t.Context(), map[string]string{"block-reduction": `package constellation.admission
 deny[msg] {
 input.request.operation == "UPDATE"
 input.request.namespace == "test"
 input.request.resource.resource == "replicasets"
 input.request.oldObject.spec.replicas > input.request.object.spec.replicas
 msg := "custom update gate"
 }`}, map[string]string{"block-reduction": "enforce"})
	if err != nil || len(errs) > 0 {
		t.Fatalf("compile: %v %v", err, errs)
	}
	chain := NewChainEngine(NewEngine())
	chain.SetRego(rego)
	if chain.Evaluate(t.Context(), reductionReview(t, "ReplicaSet", 1, 0)).Allowed {
		t.Fatal("custom policy bypassed")
	}
}

func TestReplicaReductionStillEvaluatesCustomCEL(t *testing.T) {
	cel, errs, err := NewCELEngine([]*CELRule{{ID: "block-update", Expression: `request.operation != "UPDATE"`, MessageExpression: `"custom update gate"`, Mode: "enforce"}})
	if err != nil || len(errs) > 0 {
		t.Fatalf("compile: %v %v", err, errs)
	}
	chain := NewChainEngine(NewEngine())
	chain.SetCEL(cel)
	if chain.Evaluate(t.Context(), reductionReview(t, "ReplicaSet", 1, 0)).Allowed {
		t.Fatal("custom CEL policy bypassed")
	}
}

func TestReplicaReductionPreservesLargeUnknownNumbers(t *testing.T) {
	req := reductionReview(t, "ReplicaSet", 2, 1)
	for i, raw := range []*runtime.RawExtension{&req.OldObject, &req.Object} {
		var obj map[string]any
		if err := json.Unmarshal(raw.Raw, &obj); err != nil {
			t.Fatal(err)
		}
		obj["spec"].(map[string]any)["futureCounter"] = int64(9007199254740992) + int64(i)
		raw.Raw, _ = json.Marshal(obj)
	}
	if isReplicaReduction(req) {
		t.Fatal("large unrelated integer change rounded away")
	}
}
