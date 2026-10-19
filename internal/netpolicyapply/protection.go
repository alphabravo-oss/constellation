package netpolicyapply

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Protection is independent of presentation labels and request-supplied workload
// attribution. The applier's namespace comes from the Kubernetes downward API.
// Configuration can only add protected namespaces.
type Protection struct {
	namespaces              map[string]bool
	communicationNamespaces map[string]bool
}

func NewProtection(own string, extra []string) (*Protection, error) {
	own = strings.TrimSpace(own)
	if own == "" {
		return nil, errors.New("own namespace required for network policy self-protection")
	}
	p := &Protection{namespaces: map[string]bool{}, communicationNamespaces: map[string]bool{}}
	for _, raw := range append([]string{own, "kube-system", "kube-public", "kube-node-lease"}, extra...) {
		ns := strings.TrimSpace(raw)
		if ns == "" {
			continue
		}
		if len(validation.IsDNS1123Label(ns)) != 0 {
			return nil, fmt.Errorf("invalid protected namespace %q", ns)
		}
		p.namespaces[ns] = true
	}
	// Core namespaces are protected targets, but are not blanket communication
	// peers: they may contain ingress proxies carrying ordinary application traffic.
	for _, raw := range append([]string{own}, extra...) {
		if ns := strings.TrimSpace(raw); ns != "" {
			p.communicationNamespaces[ns] = true
		}
	}
	return p, nil
}

// Guard is called immediately before the Kubernetes write, including direct
// isolation actions that bypass lifecycle reconciliation. Deletion is intentionally
// unguarded so operators can lift a policy even after protection configuration changes.
func (p *Protection) Guard(resource ManifestResource, data []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("network policy protection is not initialized")
	}
	var obj unstructured.Unstructured
	if err := json.Unmarshal(data, &obj.Object); err != nil {
		return nil, err
	}
	if obj.GetNamespace() != resource.Namespace || obj.GetName() != resource.Name || obj.GetKind() != resource.Kind || obj.GetAPIVersion() != resource.APIVersion {
		return nil, errors.New("network policy resource identity does not match manifest")
	}
	if resource.Namespaced {
		if resource.Namespace == "" || p.namespaces[resource.Namespace] {
			return nil, fmt.Errorf("network policy refused: protected namespace %q", resource.Namespace)
		}
		return data, nil
	}
	if resource.Kind != "GlobalNetworkPolicy" || resource.APIVersion != "projectcalico.org/v3" {
		return nil, errors.New("unsupported cluster-wide policy protection")
	}
	// Calico namespaceSelector limits affected endpoints to selected namespaces.
	// Preserve the original selector while excluding host endpoints and protected
	// namespaces using Kubernetes' immutable namespace-name label.
	selector, _, err := unstructured.NestedString(obj.Object, "spec", "namespaceSelector")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(p.namespaces))
	for ns := range p.namespaces {
		names = append(names, strconv.Quote(ns))
	}
	sort.Strings(names)
	guard := "has(kubernetes.io/metadata.name) && kubernetes.io/metadata.name not in {" + strings.Join(names, ",") + "}"
	if strings.TrimSpace(selector) != "" {
		if err := validateSelectorGrouping(selector); err != nil {
			return nil, err
		}
		guard = "(" + selector + ") && (" + guard + ")"
	}
	if err := unstructured.SetNestedField(obj.Object, guard, "spec", "namespaceSelector"); err != nil {
		return nil, err
	}
	return json.Marshal(obj.Object)
}

// Prevent an invalid original expression from escaping the added conjunction.
// The API server still validates selector grammar; this checks grouping before
// composition. Backslash escapes are refused to avoid dialect ambiguity.
func validateSelectorGrouping(selector string) error {
	depth := 0
	var quote rune
	for _, r := range selector {
		if r == '\\' {
			return errors.New("unsupported escape in Calico namespace selector")
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return errors.New("unbalanced Calico namespace selector")
			}
		}
	}
	if quote != 0 || depth != 0 {
		return errors.New("unbalanced Calico namespace selector")
	}
	return nil
}
