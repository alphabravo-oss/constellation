package netpolicyapply

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Preserve required peers on the application side of a policy. Namespace names
// come from trusted installation configuration, addresses from live Kubernetes
// inventory; presentation labels never confer an exemption.
func (p *Protection) preserveCommunication(resource ManifestResource, data []byte, snapshot DependencySnapshot) ([]byte, error) {
	addresses := snapshot.Addresses
	if len(addresses) == 0 || len(snapshot.Services) == 0 {
		return nil, errors.New("network policy protection: dependency inventory is empty")
	}
	var obj unstructured.Unstructured
	if err := json.Unmarshal(data, &obj.Object); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(p.communicationNamespaces))
	for ns := range p.communicationNamespaces {
		names = append(names, ns)
	}
	sort.Strings(names)
	for _, ip := range addresses {
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("network policy protection: invalid dependency address")
		}
	}
	for _, peer := range snapshot.Services {
		if !peer.Address.IsValid() || peer.Port < 1 || peer.Port > 65535 || (peer.Protocol != "TCP" && peer.Protocol != "UDP" && peer.Protocol != "SCTP") {
			return nil, errors.New("network policy protection: invalid service endpoint")
		}
	}

	nsValues := make([]any, len(names))
	quoted := make([]string, len(names))
	for i, n := range names {
		nsValues[i] = n
		quoted[i] = strconv.Quote(n)
	}
	nsSelector := map[string]any{"matchExpressions": []any{map[string]any{"key": "kubernetes.io/metadata.name", "operator": "In", "values": nsValues}}}
	spec, ok := obj.Object["spec"].(map[string]any)
	if !ok && resource.Kind != "CiliumNetworkPolicy" {
		return nil, errors.New("network policy protection: missing policy spec")
	}
	switch resource.Kind {
	case "NetworkPolicy":
		directions, err := policyDirections(spec, "policyTypes", false)
		if err != nil {
			return nil, err
		}
		// Pin the original defaults before adding rules, so an ingress-only policy
		// never starts isolating egress as a side effect of self-protection.
		types := []any{}
		for _, direction := range []string{"ingress", "egress"} {
			if !directions[direction] {
				continue
			}
			types = append(types, strings.ToUpper(direction[:1])+direction[1:])
			peers := []any{map[string]any{"namespaceSelector": nsSelector}}
			key := "from"
			if direction == "egress" {
				key = "to"
			}
			rules := []any{map[string]any{key: peers}}
			if direction == "egress" {
				for _, peer := range snapshot.Services {
					cidr := netip.PrefixFrom(peer.Address, peer.Address.BitLen()).String()
					rules = append(rules, map[string]any{"to": []any{map[string]any{"ipBlock": map[string]any{"cidr": cidr}}}, "ports": []any{map[string]any{"port": int64(peer.Port), "protocol": peer.Protocol}}})
				}
			}
			if err := prependRules(spec, direction, rules); err != nil {
				return nil, err
			}
		}
		spec["policyTypes"] = types
	case "GlobalNetworkPolicy":
		directions, err := policyDirections(spec, "types", true)
		if err != nil {
			return nil, err
		}
		selector := "kubernetes.io/metadata.name in {" + strings.Join(quoted, ",") + "}"
		types := []any{}
		for _, direction := range []string{"ingress", "egress"} {
			if !directions[direction] {
				continue
			}
			types = append(types, strings.ToUpper(direction[:1])+direction[1:])
			key := "source"
			if direction == "egress" {
				key = "destination"
			}
			rules := []any{map[string]any{"action": "Allow", key: map[string]any{"namespaceSelector": selector, "selector": "all()"}}}
			if direction == "egress" {
				for _, peer := range snapshot.Services {
					cidr := netip.PrefixFrom(peer.Address, peer.Address.BitLen()).String()
					rules = append(rules, map[string]any{"action": "Allow", "protocol": peer.Protocol, key: map[string]any{"nets": []any{cidr}, "ports": []any{int64(peer.Port)}}})
				}
			}
			if err := prependRules(spec, direction, rules); err != nil {
				return nil, err
			}
		}
		spec["types"] = types
	case "CiliumNetworkPolicy":
		specs := []map[string]any{}
		if ok {
			specs = append(specs, spec)
		}
		if raw, exists := obj.Object["specs"]; exists {
			list, ok := raw.([]any)
			if !ok {
				return nil, errors.New("network policy protection: invalid Cilium specs")
			}
			for _, v := range list {
				s, ok := v.(map[string]any)
				if !ok {
					return nil, errors.New("network policy protection: invalid Cilium spec")
				}
				specs = append(specs, s)
			}
		}
		if len(specs) == 0 {
			return nil, errors.New("network policy protection: missing Cilium rules")
		}
		for _, s := range specs {
			if containsRequirement(s) {
				return nil, errors.New("network policy refused: Cilium requires constraints can override protected peers")
			}
			for _, direction := range []string{"ingress", "egress"} {
				prefix := "from"
				if direction == "egress" {
					prefix = "to"
				}
				if err := guardCiliumDeny(s, direction+"Deny", prefix+"CIDR", addresses); err != nil {
					return nil, err
				}
				// Cilium derives direction isolation from nonempty allow OR
				// deny rules. Empty/omitted directions must remain unaffected.
				allows, err := rulesList(s, direction)
				if err != nil {
					return nil, err
				}
				denies, err := rulesList(s, direction+"Deny")
				if err != nil {
					return nil, err
				}
				explicitlyIsolated := false
				if defaults, ok := s["enableDefaultDeny"].(map[string]any); ok {
					explicitlyIsolated, _ = defaults[direction].(bool)
				}
				if len(allows) == 0 && len(denies) == 0 && !explicitlyIsolated {
					continue
				}

				peer := map[string]any{"matchExpressions": []any{map[string]any{"key": "k8s:io.kubernetes.pod.namespace", "operator": "In", "values": nsValues}}}
				rules := []any{map[string]any{prefix + "Endpoints": []any{peer}}}
				if direction == "ingress" {
					// Match native Kubernetes' node-origin ingress trust boundary.
					rules = append(rules, map[string]any{"fromEntities": []any{"host", "remote-node", "kube-apiserver"}})
				} else {
					rules = append(rules, snapshot.CiliumPeers...)
					for _, endpoint := range snapshot.Services {
						cidr := netip.PrefixFrom(endpoint.Address, endpoint.Address.BitLen()).String()
						rule := map[string]any{"toCIDR": []any{cidr}, "toPorts": []any{map[string]any{"ports": []any{map[string]any{"port": strconv.Itoa(int(endpoint.Port)), "protocol": endpoint.Protocol}}}}}
						rules = append(rules, rule)
						if endpoint.Node {
							rules = append(rules, map[string]any{"toEntities": []any{"host", "remote-node", "kube-apiserver"}, "toPorts": rule["toPorts"]})
						}
					}
				}
				if err := prependRules(s, direction, rules); err != nil {
					return nil, err
				}
			}
		}
	default:
		return nil, errors.New("network policy protection: unsupported policy kind")
	}
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations["constellation.alphabravo.io/system-communication"] = "preserved"
	annotations["constellation.alphabravo.io/communication-namespaces"] = strings.Join(names, ",")
	protected := make([]string, 0, len(p.namespaces))
	for ns := range p.namespaces {
		protected = append(protected, ns)
	}
	sort.Strings(protected)
	annotations["constellation.alphabravo.io/protected-namespaces"] = strings.Join(protected, ",")
	obj.SetAnnotations(annotations)
	return json.Marshal(obj.Object)
}

func policyDirections(spec map[string]any, key string, calico bool) (map[string]bool, error) {
	result := map[string]bool{}
	if raw, ok := spec[key]; ok {
		values, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("invalid policy %s", key)
		}
		for _, v := range values {
			if v != "Ingress" && v != "Egress" {
				return nil, fmt.Errorf("invalid policy direction %v", v)
			}
			result[strings.ToLower(v.(string))] = true
		}
		if len(values) > 0 {
			return result, nil
		}
	}
	ingress, err := rulesList(spec, "ingress")
	if err != nil {
		return nil, err
	}
	egress, err := rulesList(spec, "egress")
	if err != nil {
		return nil, err
	}
	result["ingress"] = !calico || len(ingress) > 0 || len(egress) == 0
	result["egress"] = len(egress) > 0
	return result, nil
}
func rulesList(spec map[string]any, key string) ([]any, error) {
	raw, ok := spec[key]
	if !ok || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("invalid policy %s rules", key)
	}
	return list, nil
}
func prependRules(spec map[string]any, key string, rules []any) error {
	existing, err := rulesList(spec, key)
	if err != nil {
		return err
	}
	// Reprocessing the effective manifest must not accumulate identical rules.
	seen := map[string]bool{}
	out := []any{}
	for _, v := range append(rules, existing...) {
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if !seen[string(raw)] {
			out = append(out, v)
			seen[string(raw)] = true
		}
	}
	spec[key] = out
	return nil
}
func containsRequirement(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			if k == "fromRequires" || k == "toRequires" {
				return true
			}
			if containsRequirement(v) {
				return true
			}
		}
	case []any:
		for _, v := range x {
			if containsRequirement(v) {
				return true
			}
		}
	}
	return false
}
func guardCiliumDeny(spec map[string]any, key, cidrKey string, addresses []netip.Addr) error {
	rules, err := rulesList(spec, key)
	if err != nil {
		return err
	}
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			return errors.New("network policy refused: invalid Cilium deny rule")
		}
		// The supported block-IP action emits CIDR denies. Other deny selector
		// forms require an explicit proof they cannot match protected dependencies.
		for k := range rule {
			if k != cidrKey && k != "toPorts" && k != "icmps" {
				return fmt.Errorf("network policy refused: unsupported protected-peer analysis for Cilium deny field %s", k)
			}
		}
		cidrs, ok := rule[cidrKey].([]any)
		if !ok || len(cidrs) == 0 {
			return errors.New("network policy refused: unbounded Cilium deny")
		}
		for _, raw := range cidrs {
			s, ok := raw.(string)
			if !ok {
				return errors.New("network policy refused: invalid deny CIDR")
			}
			prefix, err := netip.ParsePrefix(s)
			if err != nil {
				return errors.New("network policy refused: invalid deny CIDR")
			}
			if prefix.Addr().Is4In6() {
				return errors.New("network policy refused: ambiguous IPv4-mapped deny CIDR")
			}
			for _, ip := range addresses {
				if prefix.Contains(ip) {
					return errors.New("network policy refused: deny overlaps a protected system endpoint")
				}
			}
		}
	}
	return nil
}
