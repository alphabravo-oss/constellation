package netpolicyapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"
)

type Flavor string

const (
	FlavorNative Flavor = "native"
	FlavorCilium Flavor = "cilium"
	FlavorCalico Flavor = "calico"
)

type Action string

const (
	ActionApply  Action = "apply"
	ActionDelete Action = "delete"
	ActionSkip   Action = "skip"
)

type Status string

const (
	StatusOK      Status = "ok"
	StatusSkipped Status = "skipped"
	StatusError   Status = "error"
)

type LifecycleState struct {
	OrgID          string
	ClusterID      string
	Workload       string
	Namespace      string
	CurrentMode    string
	ApprovalStatus string
	CandidateHash  string
	AppliedRef     string
	RollbackRef    string
	Manifests      map[string]string
}

type ManifestResource struct {
	GVR        schema.GroupVersionResource
	Namespaced bool
	Namespace  string
	Name       string
	APIVersion string
	Kind       string
}

func (r ManifestResource) Ref() string {
	if r.Namespace == "" {
		return r.APIVersion + "/" + r.Kind + ":" + r.Name
	}
	return r.APIVersion + "/" + r.Kind + ":" + r.Namespace + "/" + r.Name
}

type Result struct {
	Action      Action
	Status      Status
	ResourceRef string
	Error       string
}

type ResourceClient interface {
	Apply(ctx context.Context, resource ManifestResource, manifestJSON []byte) error
	Delete(ctx context.Context, resource ManifestResource) error
}

type KubernetesResourceClient struct {
	Client       dynamic.Interface
	FieldManager string
}

func (c KubernetesResourceClient) Apply(ctx context.Context, resource ManifestResource, manifestJSON []byte) error {
	if c.Client == nil {
		return errors.New("kubernetes dynamic client is nil")
	}
	manager := strings.TrimSpace(c.FieldManager)
	if manager == "" {
		manager = "constellation-netpolicy-applier"
	}
	force := true
	_, err := resourceInterface(c.Client, resource).Patch(ctx, resource.Name, types.ApplyPatchType, manifestJSON, metav1.PatchOptions{
		FieldManager: manager,
		Force:        &force,
	})
	return err
}

func (c KubernetesResourceClient) Delete(ctx context.Context, resource ManifestResource) error {
	if c.Client == nil {
		return errors.New("kubernetes dynamic client is nil")
	}
	err := resourceInterface(c.Client, resource).Delete(ctx, resource.Name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func resourceInterface(client dynamic.Interface, resource ManifestResource) dynamic.ResourceInterface {
	base := client.Resource(resource.GVR)
	if resource.Namespaced {
		return base.Namespace(resource.Namespace)
	}
	return base
}

func ParseFlavor(raw string) (Flavor, error) {
	switch Flavor(strings.ToLower(strings.TrimSpace(raw))) {
	case "", FlavorNative:
		return FlavorNative, nil
	case FlavorCilium:
		return FlavorCilium, nil
	case FlavorCalico:
		return FlavorCalico, nil
	default:
		return "", fmt.Errorf("unsupported network policy flavor %q", raw)
	}
}

func DesiredAction(state LifecycleState) Action {
	switch strings.ToLower(strings.TrimSpace(state.ApprovalStatus)) {
	case "applied", "demoted", "rolled_back":
		if strings.EqualFold(strings.TrimSpace(state.CurrentMode), "protect") {
			return ActionApply
		}
		return ActionDelete
	default:
		return ActionSkip
	}
}

func ReconcileState(ctx context.Context, client ResourceClient, state LifecycleState, flavor Flavor) Result {
	action := DesiredAction(state)
	if action == ActionSkip {
		return Result{Action: ActionSkip, Status: StatusSkipped}
	}
	manifest := strings.TrimSpace(state.Manifests[string(flavor)])
	if manifest == "" {
		return Result{Action: action, Status: StatusError, Error: "manifest flavor not present: " + string(flavor)}
	}
	resource, manifestJSON, err := ParseManifest(flavor, manifest)
	if err != nil {
		return Result{Action: action, Status: StatusError, Error: err.Error()}
	}
	result := Result{Action: action, ResourceRef: resource.Ref()}
	switch action {
	case ActionApply:
		err = client.Apply(ctx, resource, manifestJSON)
	case ActionDelete:
		err = client.Delete(ctx, resource)
	}
	if err != nil {
		result.Status = StatusError
		result.Error = err.Error()
		return result
	}
	result.Status = StatusOK
	return result
}

func ParseManifest(flavor Flavor, manifest string) (ManifestResource, []byte, error) {
	manifestJSON, err := yaml.YAMLToJSON([]byte(manifest))
	if err != nil {
		return ManifestResource{}, nil, fmt.Errorf("convert manifest to json: %w", err)
	}
	var obj unstructured.Unstructured
	if err := json.Unmarshal(manifestJSON, &obj.Object); err != nil {
		return ManifestResource{}, nil, fmt.Errorf("decode manifest: %w", err)
	}
	if obj.GetName() == "" {
		return ManifestResource{}, nil, errors.New("manifest metadata.name is required")
	}
	resource, err := resourceForFlavor(flavor, obj.GetAPIVersion(), obj.GetKind())
	if err != nil {
		return ManifestResource{}, nil, err
	}
	if resource.Namespaced && obj.GetNamespace() == "" {
		return ManifestResource{}, nil, errors.New("manifest metadata.namespace is required for " + string(flavor))
	}
	resource.Name = obj.GetName()
	resource.Namespace = obj.GetNamespace()
	resource.APIVersion = obj.GetAPIVersion()
	resource.Kind = obj.GetKind()
	return resource, manifestJSON, nil
}

func resourceForFlavor(flavor Flavor, apiVersion, kind string) (ManifestResource, error) {
	switch flavor {
	case FlavorNative:
		if apiVersion != "networking.k8s.io/v1" || kind != "NetworkPolicy" {
			return ManifestResource{}, fmt.Errorf("native flavor requires networking.k8s.io/v1 NetworkPolicy, got %s %s", apiVersion, kind)
		}
		return ManifestResource{
			GVR:        schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
			Namespaced: true,
		}, nil
	case FlavorCilium:
		if apiVersion != "cilium.io/v2" || kind != "CiliumNetworkPolicy" {
			return ManifestResource{}, fmt.Errorf("cilium flavor requires cilium.io/v2 CiliumNetworkPolicy, got %s %s", apiVersion, kind)
		}
		return ManifestResource{
			GVR:        schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"},
			Namespaced: true,
		}, nil
	case FlavorCalico:
		if apiVersion != "projectcalico.org/v3" || kind != "GlobalNetworkPolicy" {
			return ManifestResource{}, fmt.Errorf("calico flavor requires projectcalico.org/v3 GlobalNetworkPolicy, got %s %s", apiVersion, kind)
		}
		return ManifestResource{
			GVR:        schema.GroupVersionResource{Group: "projectcalico.org", Version: "v3", Resource: "globalnetworkpolicies"},
			Namespaced: false,
		}, nil
	default:
		return ManifestResource{}, fmt.Errorf("unsupported network policy flavor %q", flavor)
	}
}
