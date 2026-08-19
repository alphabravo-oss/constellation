package quarantine

import (
	"context"
	"fmt"
)

// RenderCordonYAML produces the deny-all NetworkPolicy YAML for `t`. We use the
// native K8s NetworkPolicy form so the cordon works on any CNI. Egress to kube-dns
// is preserved so DNS-based health checks don't make the pod look CrashLoopBackOff.
func RenderCordonYAML(t Target) string {
	app := t.Pod
	if t.WorkloadID != "" {
		app = lastSegment(t.WorkloadID)
	}
	return fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: constellation-quarantine-%s
  namespace: %s
  labels:
    constellation.io/quarantine: "true"
    constellation.io/pod: %q
spec:
  podSelector:
    matchLabels:
      app: %s
  policyTypes:
    - Ingress
    - Egress
  ingress: []
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
`, sanitize(app), t.Namespace, t.Pod, app)
}

// RenderDenyAllYAML produces a pure default-deny NetworkPolicy for `t`: both
// policy types selected, with no ingress/egress allow rules at all. Unlike
// RenderCordonYAML it does NOT preserve DNS egress — RT-3 uses this for live
// quarantine of a running workload, where the intent is to sever the workload
// completely rather than keep it limping along for health checks. The native
// (networking.k8s.io/v1) form is used so the netpolicy-applier can reconcile it
// on any CNI via the FlavorNative path.
//
// ponytail: scoped by `app: <name>` matchLabels (cordon.go's existing
// convention) rather than the workload's real selector — upgrade path is to
// thread the live pod's labels through when attribution improves.
func RenderDenyAllYAML(t Target) string {
	app := t.Pod
	if t.WorkloadID != "" {
		app = lastSegment(t.WorkloadID)
	}
	return fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: constellation-quarantine-%s
  namespace: %s
  labels:
    constellation.io/quarantine: "true"
    constellation.io/pod: %q
spec:
  podSelector:
    matchLabels:
      app: %s
  policyTypes:
    - Ingress
    - Egress
  ingress: []
  egress: []
`, sanitize(app), t.Namespace, t.Pod, app)
}

// LocalCordonCollector returns a Cordon collector that renders the YAML without
// applying it (the caller is expected to push it through their K8s client). For
// monitor / dry-run / tests this is the right behaviour; the production agent
// composes this with a kubectl apply via its in-cluster client.
func LocalCordonCollector() func(ctx context.Context, t Target) (string, error) {
	return func(_ context.Context, t Target) (string, error) {
		return RenderCordonYAML(t), nil
	}
}

func lastSegment(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return s[i+1:]
		}
	}
	return s
}
