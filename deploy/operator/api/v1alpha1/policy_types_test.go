package v1alpha1

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// TestAdmissionRuleDeepCopyRoundTrip verifies the hand-written DeepCopy produces an
// independent, equal copy (no shared backing arrays/maps) for ConstellationAdmissionRule.
func TestAdmissionRuleDeepCopyRoundTrip(t *testing.T) {
	orig := &ConstellationAdmissionRule{
		ObjectMeta: metav1.ObjectMeta{Name: "block-privileged", Labels: map[string]string{"team": "sec"}},
		Spec: ConstellationAdmissionRuleSpec{
			OrgID:       "11111111-1111-1111-1111-111111111111",
			Description: "block privileged containers",
			Engine:      "kyverno",
			Mode:        "enforce",
			Enabled:     true,
			SpecYAML:    "apiVersion: constellation.alphabravo.io/v1alpha1\nkind: AdmissionRule\n",
		},
		Status: PolicyStatus{
			Phase:              "Synced",
			ObservedGeneration: 7,
			Conditions: []metav1.Condition{{
				Type: ConditionSynced, Status: metav1.ConditionTrue, Reason: "Reconciled", Message: "applied",
			}},
		},
	}

	cp := orig.DeepCopy()
	if !reflect.DeepEqual(orig, cp) {
		t.Fatalf("DeepCopy not equal to original:\n got=%#v\nwant=%#v", cp, orig)
	}

	// Mutating the copy must not affect the original (independent backing storage).
	cp.Spec.Mode = "monitor"
	cp.Status.Conditions[0].Reason = "changed"
	cp.ObjectMeta.Labels["team"] = "ops"
	if orig.Spec.Mode != "enforce" || orig.Status.Conditions[0].Reason != "Reconciled" || orig.Labels["team"] != "sec" {
		t.Fatalf("mutating copy leaked into original: %#v", orig)
	}

	// DeepCopyObject must return a runtime.Object of the same concrete type.
	var obj runtime.Object = orig.DeepCopyObject()
	if _, ok := obj.(*ConstellationAdmissionRule); !ok {
		t.Fatalf("DeepCopyObject returned %T, want *ConstellationAdmissionRule", obj)
	}
}

// TestResponseRuleDeepCopyRoundTrip verifies DeepCopy for ConstellationResponseRule,
// including the nested condition/action slices and the action params map.
func TestResponseRuleDeepCopyRoundTrip(t *testing.T) {
	orig := &ConstellationResponseRule{
		ObjectMeta: metav1.ObjectMeta{Name: "quarantine-crypto-miner"},
		Spec: ConstellationResponseRuleSpec{
			OrgID:     "22222222-2222-2222-2222-222222222222",
			Enabled:   true,
			Priority:  100,
			EventType: "process",
			Conditions: []ResponseRuleCondition{
				{Field: "process_name", Op: "eq", Value: "xmrig"},
				{Field: "severity", Op: "gt", Value: "7"},
			},
			Actions: []ResponseRuleAction{
				{Type: "quarantine"},
				{Type: "webhook", Params: map[string]string{"receiver": "sec-webhook"}},
			},
		},
		Status: PolicyStatus{
			ObservedGeneration: 3,
			Conditions: []metav1.Condition{{
				Type: ConditionError, Status: metav1.ConditionFalse, Reason: "OK", Message: "",
			}},
		},
	}

	cp := orig.DeepCopy()
	if !reflect.DeepEqual(orig, cp) {
		t.Fatalf("DeepCopy not equal to original:\n got=%#v\nwant=%#v", cp, orig)
	}

	// Mutate nested slice + map on the copy; the original must be untouched.
	cp.Spec.Conditions[0].Value = "monero"
	cp.Spec.Actions[1].Params["receiver"] = "other"
	if orig.Spec.Conditions[0].Value != "xmrig" {
		t.Fatalf("condition slice shared backing array: %#v", orig.Spec.Conditions)
	}
	if orig.Spec.Actions[1].Params["receiver"] != "sec-webhook" {
		t.Fatalf("action params map shared: %#v", orig.Spec.Actions[1].Params)
	}

	if _, ok := orig.DeepCopyObject().(*ConstellationResponseRule); !ok {
		t.Fatalf("DeepCopyObject returned wrong type")
	}
}

// TestPolicyTypesRegisteredInScheme verifies the new kinds (and their List types) are
// registered in the group-version SchemeBuilder so the operator manager can serve them.
func TestPolicyTypesRegisteredInScheme(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	for _, obj := range []runtime.Object{
		&ConstellationAdmissionRule{}, &ConstellationAdmissionRuleList{},
		&ConstellationResponseRule{}, &ConstellationResponseRuleList{},
	} {
		gvks, _, err := scheme.ObjectKinds(obj)
		if err != nil {
			t.Fatalf("ObjectKinds(%T): %v", obj, err)
		}
		if len(gvks) == 0 || gvks[0].Group != GroupVersion.Group || gvks[0].Version != GroupVersion.Version {
			t.Fatalf("%T registered under unexpected gvk %v", obj, gvks)
		}
	}

	// List types must deep-copy their items independently too.
	list := &ConstellationResponseRuleList{Items: []ConstellationResponseRule{{
		Spec: ConstellationResponseRuleSpec{OrgID: "x", EventType: "file", Actions: []ResponseRuleAction{{Type: "tag"}}},
	}}}
	cp := list.DeepCopy()
	cp.Items[0].Spec.OrgID = "y"
	if list.Items[0].Spec.OrgID != "x" {
		t.Fatalf("list DeepCopy shared item backing array")
	}
}
