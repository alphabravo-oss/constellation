// Package netpolicy emits NetworkPolicy YAML in three flavors — native K8s
// NetworkPolicy, Cilium CiliumNetworkPolicy, and Calico GlobalNetworkPolicy — from
// observed network flows.
//
// The generator takes a learn-window of NetworkFlow records and synthesizes:
//
//	for each (target_workload, namespace):
//	  ingress:  one rule per distinct (src_workload, port, protocol)
//	  egress:   one rule per distinct (dst_workload, port, protocol)
//
// External egress (workloads with no podSelector match) becomes an ipBlock egress rule
// against the observed peer CIDR. DNS (UDP/53) is allow-listed by default.
package netpolicy

import (
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Flow is one observed edge between two workloads, derived from runtime agent emissions.
type Flow struct {
	SrcWorkload  string // "default/api-service" or "" for external
	SrcNamespace string
	SrcLabels    map[string]string
	DstWorkload  string
	DstNamespace string
	DstLabels    map[string]string
	DstIP        string // populated when DstWorkload is "" (external)
	// Fqdn, when set on an egress flow, anchors the egress allow rule to a
	// DNS name instead of an IP/CIDR. Cilium enforces these via its DNS
	// proxy: an exact name (eg. "api.github.com") becomes a toFQDNs
	// matchName; a wildcard (eg. "*.github.com") becomes a matchPattern.
	// Only the Cilium generator consumes this; native/Calico ignore it
	// (they have no FQDN primitive and fall back to the resolved DstIP).
	Fqdn       string
	Protocol   string // TCP | UDP | SCTP
	Port       int
	Count      int    // number of observations
	LastSeen   string // RFC3339 timestamp
	L7Protocol string // optional observed app protocol, preserved as manifest metadata
}

// GenerateNative renders one native K8s NetworkPolicy per target workload from `flows`.
func GenerateNative(targetWorkload, targetNamespace string, targetLabels map[string]string, flows []Flow) string {
	ingress, egress := bucketFlows(flows, targetWorkload, targetNamespace)
	policy := map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata":   metadataWithAnnotations(shortName(targetWorkload)+"-policy", targetNamespace, targetPolicyFlows(ingress, egress)),
		"spec": map[string]any{
			"podSelector": map[string]any{
				"matchLabels": labelOrApp(targetWorkload, targetLabels),
			},
			"policyTypes": []string{"Ingress", "Egress"},
			"ingress":     renderNativeIngress(ingress),
			"egress":      renderNativeEgress(egress),
		},
	}
	return marshalYAML(policy)
}

// CiliumOptions tunes the Cilium generator's cluster-specific knobs — chiefly
// the DNS-visibility egress rule that toFQDNs enforcement depends on. The
// zero value is NOT usable; callers should start from DefaultCiliumOptions and
// override individual fields.
type CiliumOptions struct {
	// KubeDNSSelector is the endpointSelector matchLabels used to target the
	// cluster's DNS pods on the DNS-visibility rule. Cilium-style label keys
	// (prefixed with "k8s:") are expected. Default selects the standard
	// kube-system / kube-dns CoreDNS deployment.
	KubeDNSSelector map[string]string
	// DNSPort is the port the DNS-visibility rule opens to the DNS pods.
	// Default 53.
	DNSPort int
	// DNSProtocols are the L4 protocols opened to the DNS pods on DNSPort.
	// Cilium's DNS proxy needs both UDP and TCP so large responses (TCP
	// fallback) are still parsed. Default {"UDP", "TCP"}.
	DNSProtocols []string
}

// DefaultCiliumOptions returns the defaults that work on a stock cluster
// running CoreDNS as kube-dns in kube-system.
func DefaultCiliumOptions() CiliumOptions {
	return CiliumOptions{
		KubeDNSSelector: map[string]string{
			"k8s:io.kubernetes.pod.namespace": "kube-system",
			"k8s:k8s-app":                     "kube-dns",
		},
		DNSPort:      53,
		DNSProtocols: []string{"UDP", "TCP"},
	}
}

// normalize fills any unset field with its default so a partially-populated
// CiliumOptions (or the zero value) still produces a valid policy.
func (o CiliumOptions) normalize() CiliumOptions {
	def := DefaultCiliumOptions()
	if len(o.KubeDNSSelector) == 0 {
		o.KubeDNSSelector = def.KubeDNSSelector
	}
	if o.DNSPort == 0 {
		o.DNSPort = def.DNSPort
	}
	if len(o.DNSProtocols) == 0 {
		o.DNSProtocols = def.DNSProtocols
	}
	return o
}

// GenerateCilium renders a CiliumNetworkPolicy for the same target using the
// default DNS-visibility settings. Cilium supports L7 rules natively (HTTP
// method/path) and FQDN egress via its DNS proxy; egress flows carrying a
// Flow.Fqdn become real toFQDNs rules (see GenerateCiliumWithOptions).
func GenerateCilium(targetWorkload, targetNamespace string, targetLabels map[string]string, flows []Flow) string {
	return GenerateCiliumWithOptions(targetWorkload, targetNamespace, targetLabels, flows, DefaultCiliumOptions())
}

// GenerateCiliumWithOptions is GenerateCilium with a caller-supplied
// CiliumOptions, so the kube-dns selector / DNS port / DNS protocols of the
// mandatory DNS-visibility rule can be adapted per cluster.
func GenerateCiliumWithOptions(targetWorkload, targetNamespace string, targetLabels map[string]string, flows []Flow, opts CiliumOptions) string {
	opts = opts.normalize()
	ingress, egress := bucketFlows(flows, targetWorkload, targetNamespace)
	policy := map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata":   metadataWithAnnotations(shortName(targetWorkload)+"-cilium", targetNamespace, targetPolicyFlows(ingress, egress)),
		"spec": map[string]any{
			"endpointSelector": map[string]any{
				"matchLabels": labelOrApp(targetWorkload, targetLabels),
			},
			"ingress": renderCiliumIngress(ingress),
			"egress":  renderCiliumEgress(egress, opts),
		},
	}
	return marshalYAML(policy)
}

// GenerateCalico renders a Calico GlobalNetworkPolicy. Calico's selector syntax differs
// from Kubernetes label-selectors (it uses Felix expression syntax); we render the simpler
// "app == 'X' && namespace == 'Y'" form which Felix accepts.
func GenerateCalico(targetWorkload, targetNamespace string, targetLabels map[string]string, flows []Flow) string {
	ingress, egress := bucketFlows(flows, targetWorkload, targetNamespace)
	policy := map[string]any{
		"apiVersion": "projectcalico.org/v3",
		"kind":       "GlobalNetworkPolicy",
		"metadata":   metadataWithAnnotations(shortName(targetWorkload)+"-calico", "", targetPolicyFlows(ingress, egress)),
		"spec": map[string]any{
			"selector": calicoSelector(targetWorkload, targetNamespace, targetLabels),
			"types":    []string{"Ingress", "Egress"},
			"ingress":  renderCalicoIngress(ingress),
			"egress":   renderCalicoEgress(egress),
		},
	}
	return marshalYAML(policy)
}

func targetPolicyFlows(ingress, egress []Flow) []Flow {
	out := make([]Flow, 0, len(ingress)+len(egress))
	out = append(out, ingress...)
	out = append(out, egress...)
	return out
}

func metadataWithAnnotations(name, namespace string, flows []Flow) map[string]any {
	metadata := map[string]any{"name": name}
	if namespace != "" {
		metadata["namespace"] = namespace
	}
	if protocols := observedL7Protocols(flows); len(protocols) > 0 {
		metadata["annotations"] = map[string]string{
			"constellation.alphabravo.io/l7-protocols": strings.Join(protocols, ","),
			"constellation.alphabravo.io/l7-intent":    "preserved-as-metadata",
		}
	}
	return metadata
}

func observedL7Protocols(flows []Flow) []string {
	seen := map[string]bool{}
	for _, flow := range flows {
		for _, value := range strings.Split(flow.L7Protocol, ",") {
			protocol := strings.ToLower(strings.TrimSpace(value))
			if protocol == "" {
				continue
			}
			seen[protocol] = true
		}
	}
	out := make([]string, 0, len(seen))
	for protocol := range seen {
		out = append(out, protocol)
	}
	sort.Strings(out)
	return out
}

// bucketFlows splits a flow set into ingress (dst=target) + egress (src=target) groups.
func bucketFlows(flows []Flow, targetWorkload, targetNamespace string) (ingress, egress []Flow) {
	for _, f := range flows {
		if f.DstWorkload == targetWorkload && f.DstNamespace == targetNamespace {
			ingress = append(ingress, f)
		}
		if f.SrcWorkload == targetWorkload && f.SrcNamespace == targetNamespace {
			egress = append(egress, f)
		}
	}
	return
}

// renderNativeIngress emits []ingress rules in native NetworkPolicy shape.
func renderNativeIngress(flows []Flow) []map[string]any {
	out := []map[string]any{}
	for _, f := range dedupeFlows(flows) {
		if f.SrcWorkload == "" {
			// No peer identity: a native ingress rule with `ports` but no `from`
			// matches ALL sources on the port (K8s allow-all). Fail closed.
			continue
		}
		rule := map[string]any{}
		rule["from"] = []map[string]any{{
			"podSelector": map[string]any{
				"matchLabels": labelOrApp(f.SrcWorkload, f.SrcLabels),
			},
			"namespaceSelector": map[string]any{
				"matchLabels": map[string]string{"kubernetes.io/metadata.name": f.SrcNamespace},
			},
		}}
		rule["ports"] = []map[string]any{{
			"protocol": f.Protocol,
			"port":     f.Port,
		}}
		out = append(out, rule)
	}
	return out
}

// renderNativeEgress emits []egress rules in native NetworkPolicy shape.
func renderNativeEgress(flows []Flow) []map[string]any {
	out := []map[string]any{
		// DNS pinhole — always allow DNS to kube-dns. Without it most apps break.
		// Open both UDP and TCP/53 so DNS-over-TCP (truncated/large responses)
		// still works.
		{
			"to": []map[string]any{{
				"namespaceSelector": map[string]any{
					"matchLabels": map[string]string{"kubernetes.io/metadata.name": "kube-system"},
				},
				"podSelector": map[string]any{
					"matchLabels": map[string]string{"k8s-app": "kube-dns"},
				},
			}},
			"ports": []map[string]any{
				{"protocol": "UDP", "port": 53},
				{"protocol": "TCP", "port": 53},
			},
		},
	}
	for _, f := range dedupeFlows(flows) {
		rule := map[string]any{}
		if f.DstWorkload != "" {
			rule["to"] = []map[string]any{{
				"podSelector": map[string]any{"matchLabels": labelOrApp(f.DstWorkload, f.DstLabels)},
				"namespaceSelector": map[string]any{
					"matchLabels": map[string]string{"kubernetes.io/metadata.name": f.DstNamespace},
				},
			}}
		} else if f.DstIP != "" {
			rule["to"] = []map[string]any{{
				"ipBlock": map[string]any{"cidr": f.DstIP + "/32"},
			}}
		} else {
			// No peer identity: a native egress rule with `ports` but no `to`
			// matches ALL destinations on the port (K8s allow-all). Fail closed.
			continue
		}
		rule["ports"] = []map[string]any{{"protocol": f.Protocol, "port": f.Port}}
		out = append(out, rule)
	}
	return out
}

func renderCiliumIngress(flows []Flow) []map[string]any {
	out := []map[string]any{}
	for _, f := range dedupeFlows(flows) {
		if f.SrcWorkload == "" {
			// No L3 peer identity: a toPorts-only ingress rule in Cilium permits
			// ALL sources on this port — allow-any-ingress. Fail closed.
			continue
		}
		rule := map[string]any{
			"toPorts": []map[string]any{{
				"ports": []map[string]any{{"port": stringInt(f.Port), "protocol": f.Protocol}},
			}},
		}
		rule["fromEndpoints"] = []map[string]any{{
			"matchLabels": ciliumLabels(f.SrcWorkload, f.SrcNamespace, f.SrcLabels),
		}}
		out = append(out, rule)
	}
	return out
}

func renderCiliumEgress(flows []Flow, opts CiliumOptions) []map[string]any {
	// The DNS-visibility rule MUST come first and MUST always be present:
	// without it Cilium's DNS proxy never observes the lookups that resolve
	// toFQDNs names to IPs, so every toFQDNs rule below silently fails to
	// match. This is the #1 correctness requirement for FQDN egress.
	out := []map[string]any{dnsVisibilityRule(opts)}
	for _, f := range dedupeFlows(flows) {
		rule := map[string]any{
			"toPorts": []map[string]any{{
				"ports": []map[string]any{{"port": stringInt(f.Port), "protocol": f.Protocol}},
			}},
		}
		fqdn, fqdnOK := cleanFqdn(f.Fqdn)
		switch {
		case fqdnOK:
			// FQDN-anchored egress: matchName for an exact name, matchPattern
			// for a wildcard. Takes precedence over any resolved DstIP so the
			// rule survives the peer's IPs rotating.
			rule["toFQDNs"] = []map[string]any{fqdnSelector(fqdn)}
		case f.DstWorkload != "":
			rule["toEndpoints"] = []map[string]any{{
				"matchLabels": ciliumLabels(f.DstWorkload, f.DstNamespace, f.DstLabels),
			}}
		case f.DstIP != "":
			rule["toCIDR"] = []string{f.DstIP + "/32"}
		default:
			// No L3 peer identity (no FQDN, no workload, no IP). A toPorts-only
			// egress rule in Cilium permits ALL destinations on this port —
			// allow-any-egress. Fail closed: drop the unidentifiable flow rather
			// than emit a rule that is broader than intended.
			continue
		}
		out = append(out, rule)
	}
	return out
}

// dnsVisibilityRule builds the egress rule that lets Cilium's DNS proxy
// observe lookups to the cluster DNS pods. The rules.dns matchPattern "*"
// tells Cilium to snoop every answer so it can populate the toFQDNs IP cache.
func dnsVisibilityRule(opts CiliumOptions) map[string]any {
	ports := make([]map[string]any, 0, len(opts.DNSProtocols))
	for _, proto := range opts.DNSProtocols {
		ports = append(ports, map[string]any{"port": stringInt(opts.DNSPort), "protocol": proto})
	}
	return map[string]any{
		"toEndpoints": []map[string]any{{"matchLabels": opts.KubeDNSSelector}},
		"toPorts": []map[string]any{{
			"ports": ports,
			"rules": map[string]any{"dns": []map[string]any{{"matchPattern": "*"}}},
		}},
	}
}

// fqdnSelector picks matchName vs matchPattern. Cilium's toFQDNs treats a
// name containing a wildcard ("*") as a pattern; anything else is an exact
// match. A leading "*." or an embedded "*" both route to matchPattern. The
// input must already be cleaned (see cleanFqdn).
func fqdnSelector(fqdn string) map[string]any {
	if strings.Contains(fqdn, "*") {
		return map[string]any{"matchPattern": fqdn}
	}
	return map[string]any{"matchName": fqdn}
}

// cleanFqdn normalizes and validates a Flow.Fqdn before it becomes a toFQDNs
// selector. It lower-cases, trims whitespace, and strips a trailing dot so
// equivalent names dedupe and compare correctly. It returns ok=false for an
// empty name or for a wildcard pattern with no literal label characters (eg.
// "*", "*.*", "*."), which would compile to a matchPattern that matches EVERY
// DNS name — an allow-egress-to-any-FQDN widening. Such a flow is rejected so
// the caller can fail closed instead of opening the port to the world.
func cleanFqdn(fqdn string) (string, bool) {
	f := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	if f == "" {
		return "", false
	}
	if strings.Contains(f, "*") {
		// Require at least one literal (non-wildcard, non-dot) character so a
		// bare/over-broad wildcard cannot match all labels.
		if strings.Trim(f, "*.") == "" {
			return "", false
		}
	}
	return f, true
}

func renderCalicoIngress(flows []Flow) []map[string]any {
	out := []map[string]any{}
	for _, f := range dedupeFlows(flows) {
		if f.SrcWorkload == "" {
			// No peer identity: a source with only ports matches every host on
			// the port. Fail closed rather than allow-all ingress.
			continue
		}
		rule := map[string]any{
			"action":   "Allow",
			"protocol": strings.ToUpper(f.Protocol),
			"source": map[string]any{
				"selector": calicoSelector(f.SrcWorkload, f.SrcNamespace, f.SrcLabels),
			},
			"destination": map[string]any{
				"ports": []int{f.Port},
			},
		}
		out = append(out, rule)
	}
	return out
}

func renderCalicoEgress(flows []Flow) []map[string]any {
	out := []map[string]any{
		// Default Calico DNS allow — UDP and TCP/53 so DNS-over-TCP also works.
		{
			"action":   "Allow",
			"protocol": "UDP",
			"destination": map[string]any{
				"selector": "k8s-app == 'kube-dns'",
				"ports":    []int{53},
			},
		},
		{
			"action":   "Allow",
			"protocol": "TCP",
			"destination": map[string]any{
				"selector": "k8s-app == 'kube-dns'",
				"ports":    []int{53},
			},
		},
	}
	for _, f := range dedupeFlows(flows) {
		dest := map[string]any{"ports": []int{f.Port}}
		if f.DstWorkload != "" {
			dest["selector"] = calicoSelector(f.DstWorkload, f.DstNamespace, f.DstLabels)
		} else if f.DstIP != "" {
			dest["nets"] = []string{f.DstIP + "/32"}
		} else {
			// No peer identity: a destination with only ports matches every
			// host on the port. Fail closed rather than allow-all egress.
			continue
		}
		out = append(out, map[string]any{
			"action":      "Allow",
			"protocol":    strings.ToUpper(f.Protocol),
			"destination": dest,
		})
	}
	return out
}

// dedupeFlows collapses identical (peer, proto, port) entries so we don't emit redundant
// rules. The Count field is summed but otherwise dropped on the rule.
func dedupeFlows(flows []Flow) []Flow {
	type key struct {
		srcNS, src, dstNS, dst, dstIP, fqdn, proto string
		port                                       int
	}
	bag := map[key]Flow{}
	for _, f := range flows {
		fqdnKey, _ := cleanFqdn(f.Fqdn) // normalize so equivalent names dedupe
		k := key{f.SrcNamespace, f.SrcWorkload, f.DstNamespace, f.DstWorkload, f.DstIP, fqdnKey, f.Protocol, f.Port}
		cur, ok := bag[k]
		if !ok {
			bag[k] = f
			continue
		}
		cur.Count += f.Count
		bag[k] = cur
	}
	out := make([]Flow, 0, len(bag))
	for _, f := range bag {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DstWorkload != out[j].DstWorkload {
			return out[i].DstWorkload < out[j].DstWorkload
		}
		if out[i].Fqdn != out[j].Fqdn {
			return out[i].Fqdn < out[j].Fqdn
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// labelOrApp returns a labels map. If the workload has labels, use them; otherwise fall
// back to a synthesized `app: <workload-name>` label.
func labelOrApp(workload string, labels map[string]string) map[string]string {
	if len(labels) > 0 {
		out := map[string]string{}
		for k, v := range labels {
			out[k] = v
		}
		return out
	}
	return map[string]string{"app": shortName(workload)}
}

func ciliumLabels(workload, namespace string, labels map[string]string) map[string]string {
	out := map[string]string{"k8s:io.kubernetes.pod.namespace": namespace}
	for k, v := range labelOrApp(workload, labels) {
		out["k8s:"+k] = v
	}
	return out
}

func calicoSelector(workload, namespace string, labels map[string]string) string {
	if workload == "" {
		return ""
	}
	parts := []string{}
	for k, v := range labelOrApp(workload, labels) {
		parts = append(parts, k+" == '"+v+"'")
	}
	sort.Strings(parts)
	expr := strings.Join(parts, " && ")
	if namespace != "" {
		expr += " && projectcalico.org/namespace == '" + namespace + "'"
	}
	return expr
}

// shortName returns the trailing path segment of a "namespace/name" identifier.
func shortName(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func stringInt(n int) string { return strconv.Itoa(n) }

func marshalYAML(v any) string {
	b, err := yaml.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
