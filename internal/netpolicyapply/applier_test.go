package netpolicyapply

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeResourceClient struct {
	applied []ManifestResource
	deleted []ManifestResource
	err     error
}

func (f *fakeResourceClient) Apply(_ context.Context, resource ManifestResource, _ []byte) error {
	f.applied = append(f.applied, resource)
	return f.err
}

func (f *fakeResourceClient) Delete(_ context.Context, resource ManifestResource) error {
	f.deleted = append(f.deleted, resource)
	return f.err
}

func TestParseManifestMapsSupportedFlavors(t *testing.T) {
	tests := []struct {
		name       string
		flavor     Flavor
		manifest   string
		wantRef    string
		namespaced bool
	}{
		{
			name:   "native",
			flavor: FlavorNative,
			manifest: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-policy
  namespace: default
spec: {}`,
			wantRef:    "networking.k8s.io/v1/NetworkPolicy:default/api-policy",
			namespaced: true,
		},
		{
			name:   "cilium",
			flavor: FlavorCilium,
			manifest: `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: api-cilium
  namespace: default
spec: {}`,
			wantRef:    "cilium.io/v2/CiliumNetworkPolicy:default/api-cilium",
			namespaced: true,
		},
		{
			name:   "calico",
			flavor: FlavorCalico,
			manifest: `apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: api-calico
spec: {}`,
			wantRef:    "projectcalico.org/v3/GlobalNetworkPolicy:api-calico",
			namespaced: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, manifestJSON, err := ParseManifest(tt.flavor, tt.manifest)
			if err != nil {
				t.Fatalf("ParseManifest: %v", err)
			}
			if resource.Ref() != tt.wantRef || resource.Namespaced != tt.namespaced {
				t.Fatalf("resource = %+v, want ref=%s namespaced=%v", resource, tt.wantRef, tt.namespaced)
			}
			if !strings.Contains(string(manifestJSON), `"kind":"`+resource.Kind+`"`) {
				t.Fatalf("manifest json missing kind: %s", manifestJSON)
			}
		})
	}
}

func TestReconcileStateAppliesOnlyProtectRows(t *testing.T) {
	client := &fakeResourceClient{}
	result := ReconcileState(context.Background(), client, LifecycleState{
		CurrentMode:    "protect",
		ApprovalStatus: "applied",
		Manifests: map[string]string{"native": `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-policy
  namespace: default
spec: {}`},
	}, FlavorNative)
	if result.Status != StatusOK || result.Action != ActionApply || result.ResourceRef == "" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(client.applied) != 1 || client.applied[0].Name != "frontend-policy" {
		t.Fatalf("apply not called correctly: %+v", client.applied)
	}
}

func TestReconcileStateDeletesDemotedRows(t *testing.T) {
	client := &fakeResourceClient{}
	result := ReconcileState(context.Background(), client, LifecycleState{
		CurrentMode:    "monitor",
		ApprovalStatus: "demoted",
		Manifests: map[string]string{"native": `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-policy
  namespace: default
spec: {}`},
	}, FlavorNative)
	if result.Status != StatusOK || result.Action != ActionDelete {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(client.deleted) != 1 || client.deleted[0].Name != "frontend-policy" {
		t.Fatalf("delete not called correctly: %+v", client.deleted)
	}
}

func TestReconcileStateSkipsUnappliedRows(t *testing.T) {
	client := &fakeResourceClient{}
	result := ReconcileState(context.Background(), client, LifecycleState{
		CurrentMode:    "monitor",
		ApprovalStatus: "approved",
		Manifests:      map[string]string{"native": "ignored"},
	}, FlavorNative)
	if result.Status != StatusSkipped || result.Action != ActionSkip {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(client.applied) != 0 || len(client.deleted) != 0 {
		t.Fatalf("client should not be called: %+v %+v", client.applied, client.deleted)
	}
}

func TestReconcileStateReportsClientErrors(t *testing.T) {
	client := &fakeResourceClient{err: errors.New("forbidden")}
	result := ReconcileState(context.Background(), client, LifecycleState{
		CurrentMode:    "protect",
		ApprovalStatus: "applied",
		Manifests: map[string]string{"native": `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-policy
  namespace: default
spec: {}`},
	}, FlavorNative)
	if result.Status != StatusError || !strings.Contains(result.Error, "forbidden") {
		t.Fatalf("unexpected result: %+v", result)
	}
}
