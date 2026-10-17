package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

type runtimePolicyPodBinding struct {
	Namespace string `json:"namespace"`
	PodName   string `json:"pod_name"`
	PodUID    string `json:"pod_uid"`
}

type runtimePolicyScopePlan struct {
	identities       map[string]string
	endpoints        map[string]*dp.PolicyEndpoint
	pods             map[string]string
	wanted           map[string]*dp.WorkloadPolicy
	conflicts        map[string]string
	blockedWorkloads map[string]bool
}

func policyPodIdentity(namespace, pod, uid string) string {
	for _, field := range []string{namespace, pod, uid} {
		if field == "" || field != strings.TrimSpace(field) || strings.ContainsRune(field, '\x00') {
			return ""
		}
	}
	return namespace + "\x00" + pod + "\x00" + uid
}

func validateRuntimePolicyBundle(bundle *runtimePolicyBundle, cluster string) error {
	if bundle.ProtocolVersion != 2 || bundle.ClusterID != cluster || !bundle.SourceComplete || bundle.Policies == nil {
		return errors.New("runtime policy bundle scope or protocol is unavailable")
	}
	ids := map[string]bool{}
	wireIDs := map[int64]bool{}
	for index := range bundle.Policies {
		policy := &bundle.Policies[index]
		if err := validateScopedRuntimePolicy(policy); err != nil {
			return err
		}
		if ids[policy.ID] || policy.DPPolicyID > 0 && wireIDs[policy.DPPolicyID] {
			return errors.New("duplicate runtime policy identity")
		}
		ids[policy.ID] = true
		wireIDs[policy.DPPolicyID] = true
	}
	return nil
}

func validateScopedRuntimePolicy(policy *runtimePolicyWire) error {
	id, err := uuid.Parse(policy.ID)
	if err != nil || id == uuid.Nil || id.String() != policy.ID || policy.Version <= 0 {
		return errors.New("invalid runtime policy identity")
	}
	if _, err := networkPolicyWireID(policy.DPPolicyID); err != nil {
		return err
	}
	parts := strings.Split(policy.Workload, "/")
	if len(parts) != 2 && (len(parts) != 3 || parts[1] != "pod") {
		return errors.New("invalid runtime workload selector")
	}
	if policy.Namespace == "" || parts[0] != policy.Namespace || parts[len(parts)-1] == "" || policy.Workload != strings.TrimSpace(policy.Workload) {
		return errors.New("runtime policy namespace does not match workload")
	}
	if policy.Mode != "monitor" && policy.Mode != "enforce" || policy.DefAction > dp.PolicyActionDeny || policy.ApplyDir < 0 || policy.ApplyDir > dp.ApplyDirBoth || policy.Rules == nil {
		return errors.New("invalid runtime policy configuration")
	}
	if err := validatePolicyPodBindings(policy, parts); err != nil {
		return err
	}

	for i, rule := range policy.Rules {
		copy, err := normalizeRuntimePolicyRule(rule, policy.Mode == "monitor")
		if err != nil {
			return err
		}
		policy.Rules[i] = copy
	}
	return nil
}

func validatePolicyPodBindings(policy *runtimePolicyWire, parts []string) error {
	if policy.PodBindings == nil {
		return errors.New("runtime policy bindings missing")
	}
	switch policy.BindingStatus {
	case "resolved":
		if len(policy.PodBindings) == 0 {
			return errors.New("resolved runtime policy has no bindings")
		}
	case "unresolved", "ambiguous":
		if len(policy.PodBindings) != 0 {
			return errors.New("unresolved runtime policy has bindings")
		}
	default:
		return errors.New("invalid runtime policy binding status")
	}
	seen := map[string]bool{}
	for _, binding := range policy.PodBindings {
		identity := policyPodIdentity(binding.Namespace, binding.PodName, binding.PodUID)
		if identity == "" || binding.Namespace != policy.Namespace || seen[identity] || len(parts) == 3 && binding.PodName != parts[2] {
			return errors.New("invalid runtime policy pod identity")
		}
		seen[identity] = true
	}
	return nil
}

// The native control protocol requires IPv4 strings, including explicit zero
// for an omitted wildcard. Passing JSON null to inet_addr is not safe.
func normalizeRuntimePolicyRule(rule *dp.PolicyRule, monitor bool) (*dp.PolicyRule, error) {
	if rule == nil || rule.Action > dp.PolicyActionDeny || rule.PortR != 0 && rule.PortR < rule.Port || len(rule.Fqdn) > 255 || strings.ContainsRune(rule.Fqdn, '\x00') {
		return nil, errors.New("invalid native runtime policy rule")
	}
	out := *rule
	if err := normalizeRuntimeRuleIPs(&out); err != nil {
		return nil, err
	}
	if out.PortR == 0 {
		out.PortR = out.Port
		if out.Port == 0 && out.IPProto != dp.IPProtoICMP {
			out.PortR = 65535
		}
	}
	for _, pair := range [][2]net.IP{{out.SrcIP, out.SrcIPR}, {out.DstIP, out.DstIPR}} {
		if len(pair[1]) > 0 && bytes.Compare(pair[0], pair[1]) > 0 {
			return nil, errors.New("invalid native IP range")
		}
	}
	out.Apps = append([]dp.PolicyApp(nil), rule.Apps...)
	if monitor && out.Action == dp.PolicyActionDeny {
		out.Action = dp.PolicyActionViolate
	}
	if err := normalizeRuntimeRuleApps(out.Apps, monitor); err != nil {
		return nil, err
	}
	return &out, nil
}

func buildRuntimePolicyScopePlan(policies []runtimePolicyWire, endpoints []dp.PolicyEndpoint) runtimePolicyScopePlan {
	plan := runtimePolicyScopePlan{identities: map[string]string{}, endpoints: map[string]*dp.PolicyEndpoint{}, pods: map[string]string{}, wanted: map[string]*dp.WorkloadPolicy{}, conflicts: map[string]string{}, blockedWorkloads: map[string]bool{}}
	byPod := map[string][]runtimePolicyWire{}
	for _, policy := range policies {
		if policy.BindingStatus != "resolved" {
			plan.blockedWorkloads[policy.Workload] = true
			continue
		}
		for _, binding := range policy.PodBindings {
			identity := policyPodIdentity(binding.Namespace, binding.PodName, binding.PodUID)
			byPod[identity] = append(byPod[identity], policy)
		}
	}
	for _, endpoint := range endpoints {
		plan.addEndpoint(endpoint)
	}

	for mac, identity := range plan.identities {
		if identity == "" || plan.conflicts[mac] != "" {
			continue
		}
		matching := byPod[plan.pods[mac]]
		if len(matching) == 0 {
			continue
		}
		policy := buildMergedWorkloadPolicy(matching, []string{mac})
		if policy == nil {
			plan.conflicts[mac] = "runtime policies conflict on workload, default action, or direction"
			continue
		}
		specialized, err := specializeRuntimePolicy(policy, plan.endpoints[mac].IPs)
		if err != nil {
			plan.conflicts[mac] = err.Error()
			continue
		}
		plan.wanted[mac] = specialized
	}
	return plan
}

func (plan *runtimePolicyScopePlan) addEndpoint(endpoint dp.PolicyEndpoint) {
	mac, err := net.ParseMAC(endpoint.MAC)
	if err != nil || len(mac) != 6 {
		return
	}
	key := mac.String()
	pod := policyPodIdentity(endpoint.Namespace, endpoint.PodName, endpoint.PodUID)
	identity := ""
	if pod != "" {
		identity = fmt.Sprintf("%s\x00%d\x00%s", pod, endpoint.Registration, strings.Join(endpoint.IPs, "\x00"))
	}
	if previous, exists := plan.identities[key]; exists && previous != identity {
		plan.conflicts[key] = "MAC has ambiguous pod ownership"
		identity = ""
	}
	plan.identities[key] = identity
	plan.pods[key] = pod
	copy := endpoint
	plan.endpoints[key] = &copy
}

// Merge only an already-qualified single workload. No policy from another
// workload may contribute a rule, fallback action, or direction.
func buildMergedWorkloadPolicy(policies []runtimePolicyWire, macs []string) *dp.WorkloadPolicy {
	if len(policies) == 0 {
		return nil
	}
	out := &dp.WorkloadPolicy{WorkloadID: policies[0].Workload, Mode: "enforce", DefAction: policyDefaultAction(policies[0]), ApplyDir: policies[0].ApplyDir, MACs: append([]string(nil), macs...)}
	if out.ApplyDir == 0 {
		out.ApplyDir = dp.ApplyDirBoth
	}
	for _, policy := range policies {
		direction := policy.ApplyDir
		if direction == 0 {
			direction = dp.ApplyDirBoth
		}
		if policy.Workload != out.WorkloadID || policy.Mode == "disabled" || policyDefaultAction(policy) != out.DefAction || direction != out.ApplyDir {
			return nil
		}
		wireID, err := networkPolicyWireID(policy.DPPolicyID)
		if err != nil {
			return nil
		}
		for _, rule := range policy.Rules {
			copy, err := normalizeRuntimePolicyRule(rule, policy.Mode == "monitor")
			if err != nil {
				return nil
			}
			if wireID > 0 {
				stampRuntimePolicyRuleID(copy, wireID)
			}
			out.Rules = append(out.Rules, copy)
		}
	}
	return out
}

func scopedICMPPolicy(source *dp.WorkloadPolicy, globalICMP bool) *dp.WorkloadPolicy {
	out := *source
	out.MACs = append([]string(nil), source.MACs...)
	out.Rules = append([]*dp.PolicyRule(nil), source.Rules...)
	if !globalICMP || mergedHasICMP(source) {
		return &out
	}
	// Match native dpi_add_default_policy's full IPv4 range and both directions.
	// ProtoAny expands to TCP/UDP only for this scope; another workload's ICMP
	// opt-in must not make its wildcard rule cover ICMP as a side effect.
	out.Rules = nil
	for _, address := range source.LocalIPs {
		for _, ingress := range []bool{false, true} {
			rule := &dp.PolicyRule{SrcIP: net.IPv4zero.To4(), DstIP: net.IPv4zero.To4(), SrcIPR: net.IPv4bcast.To4(), DstIPR: net.IPv4bcast.To4(), IPProto: dp.IPProtoICMP, Action: dp.PolicyActionAllow, Ingress: ingress}
			if ingress {
				rule.DstIP, rule.DstIPR = address, address
			} else {
				rule.SrcIP, rule.SrcIPR = address, address
			}
			out.Rules = append(out.Rules, rule)
		}
	}
	for _, rule := range source.Rules {
		if rule.IPProto != dp.IPProtoAny {
			out.Rules = append(out.Rules, rule)
			continue
		}
		for _, protocol := range []uint8{dp.IPProtoTCP, dp.IPProtoUDP} {
			copy := *rule
			copy.IPProto = protocol
			out.Rules = append(out.Rules, &copy)
		}
	}
	return &out
}

func sortedPolicyMACs[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func validatePolicyFingerprints(plan runtimePolicyScopePlan) error {
	for mac, policy := range plan.wanted {
		if fingerprintWorkloadPolicy(policy) == "" {
			return fmt.Errorf("invalid policy fingerprint for %s", mac)
		}
	}
	return nil
}

// The native range table hashes the local IP; it does not expand wildcard
// local ranges. Bind each matching local selector to an actual interface IP.
func specializeRuntimePolicy(source *dp.WorkloadPolicy, addresses []string) (*dp.WorkloadPolicy, error) {
	out := *source
	out.Rules = nil
	out.LocalIPs = runtimeEndpointIPs(addresses)
	if len(out.LocalIPs) == 0 {
		return nil, errors.New("current endpoint IPv4 addresses unavailable")
	}
	for _, rule := range source.Rules {
		out.Rules = append(out.Rules, bindRuntimeRuleLocalIPs(rule, out.LocalIPs)...)
	}
	return &out, nil
}

func nativeRemoteUpper(lower, upper net.IP) net.IP {
	if len(upper) > 0 {
		return upper
	}
	if lower.IsUnspecified() {
		return net.IPv4bcast.To4()
	}
	return lower
}

func normalizeRuntimeRuleIPs(out *dp.PolicyRule) error {
	ips := []*net.IP{&out.SrcIP, &out.DstIP, &out.SrcIPR, &out.DstIPR}
	for index, ip := range ips {
		if len(*ip) == 0 {
			if index < 2 {
				*ip = net.IPv4(0, 0, 0, 0).To4()
			}
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			return errors.New("native runtime policy supports IPv4 selectors only")
		}
		*ip = append(net.IP(nil), v4...)
	}
	return nil
}

func normalizeRuntimeRuleApps(apps []dp.PolicyApp, monitor bool) error {

	for index := range apps {
		if apps[index].Action > dp.PolicyActionDeny {
			return errors.New("invalid native runtime policy app action")
		}
		if monitor && apps[index].Action == dp.PolicyActionDeny {
			apps[index].Action = dp.PolicyActionViolate
		}
	}
	return nil
}

func runtimeEndpointIPs(addresses []string) []net.IP {
	var out []net.IP
	seen := map[string]bool{}
	for _, address := range addresses {
		ip := net.ParseIP(address).To4()
		if ip == nil || ip.IsUnspecified() || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}
	return out
}

func bindRuntimeRuleLocalIPs(rule *dp.PolicyRule, addresses []net.IP) []*dp.PolicyRule {
	var out []*dp.PolicyRule

	local, upper := rule.SrcIP, rule.SrcIPR
	if rule.Ingress {
		local, upper = rule.DstIP, rule.DstIPR
	}
	if len(upper) == 0 {
		upper = local
		if local.IsUnspecified() {
			upper = net.IPv4bcast.To4()
		}
	}
	for _, address := range addresses {
		if bytes.Compare(address, local) < 0 || bytes.Compare(address, upper) > 0 {
			continue
		}
		copy := *rule
		if rule.Ingress {
			copy.DstIP, copy.DstIPR = address, address
			copy.SrcIPR = nativeRemoteUpper(copy.SrcIP, copy.SrcIPR)
		} else {
			copy.SrcIP, copy.SrcIPR = address, address
			copy.DstIPR = nativeRemoteUpper(copy.DstIP, copy.DstIPR)
		}
		out = append(out, &copy)
	}
	return out
}

func stampRuntimePolicyRuleID(rule *dp.PolicyRule, id uint32) {
	rule.ID = id
	for index := range rule.Apps {
		rule.Apps[index].RuleID = id
	}
}
