package network

import (
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/netpolicyapply"
)

// The generated manifests are only useful if the applier can parse them. Round-trip
// each through ParseManifest and assert the flavor/GVR/name the applier will act on.
func TestEnforcementManifestsParse(t *testing.T) {
	isoManifest, isoRef := isolateManifest("prod", "api", map[string]string{"app": "api"})
	res, _, err := netpolicyapply.ParseManifest(netpolicyapply.FlavorNative, isoManifest)
	if err != nil {
		t.Fatalf("isolate manifest failed to parse: %v", err)
	}
	if res.Kind != "NetworkPolicy" || res.Namespace != "prod" {
		t.Fatalf("isolate parsed wrong: kind=%s ns=%s", res.Kind, res.Namespace)
	}
	if !strings.HasSuffix(isoRef, res.Namespace+"/"+res.Name) {
		t.Fatalf("isolate ref %q disagrees with parsed name %q", isoRef, res.Name)
	}
	// default-deny = both policy types, no allow rules
	if !strings.Contains(isoManifest, "\"policyTypes\":[\"Ingress\",\"Egress\"]") {
		t.Fatalf("isolate manifest is not default-deny: %s", isoManifest)
	}

	blkManifest, blkRef := blockIPManifest("prod", "api", "8.8.8.8", "egress", map[string]string{"app": "api"})
	bres, _, err := netpolicyapply.ParseManifest(netpolicyapply.FlavorCilium, blkManifest)
	if err != nil {
		t.Fatalf("block manifest failed to parse: %v", err)
	}
	if bres.Kind != "CiliumNetworkPolicy" || bres.Namespace != "prod" {
		t.Fatalf("block parsed wrong: kind=%s ns=%s", bres.Kind, bres.Namespace)
	}
	if !strings.HasSuffix(blkRef, bres.Namespace+"/"+bres.Name) {
		t.Fatalf("block ref %q disagrees with parsed name %q", blkRef, bres.Name)
	}
	if !strings.Contains(blkManifest, "egressDeny") || !strings.Contains(blkManifest, "8.8.8.8/32") {
		t.Fatalf("block manifest missing egressDeny toCIDR: %s", blkManifest)
	}
	// egress-only must not emit an ingressDeny
	if strings.Contains(blkManifest, "ingressDeny") {
		t.Fatalf("egress-only block leaked an ingressDeny: %s", blkManifest)
	}
}

func TestK8sNameSanitize(t *testing.T) {
	if got := k8sName("Constellation-Isolate-My_App.v2"); got != "constellation-isolate-my-app-v2" {
		t.Fatalf("k8sName sanitize: got %q", got)
	}
	if got := k8sName("///"); got != "constellation-enforce" {
		t.Fatalf("k8sName empty fallback: got %q", got)
	}
	if got := ipSlug("10.0.0.5"); got != "10-0-0-5" {
		t.Fatalf("ipSlug: got %q", got)
	}
}
