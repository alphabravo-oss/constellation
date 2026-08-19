package network

import "testing"

func TestEndpointKind(t *testing.T) {
	cases := map[string]string{
		"default/api":             "workload",
		"cert-manager/webhook":    "workload",
		"cluster/10.42.0.1":       "host",      // CNI pod-network gateway (.1) — infra, not a workload
		"cluster/8.8.8.8":         "external",  // public IP under cluster scope
		"host/node-1":             "host",
		"node/ip-10-0-0-5":        "host",
		"external/api.github.com": "external",
		"10.0.0.5":                "unmanaged", // bare private IP
		"1.1.1.1":                 "external",  // bare public IP
		"default/192.168.1.5":     "unmanaged", // ns-scoped but a private IP
	}
	for id, want := range cases {
		if got := endpointKind(id); got != want {
			t.Errorf("endpointKind(%q)=%q want %q", id, got, want)
		}
	}
}
