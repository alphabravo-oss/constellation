package compliance

import (
	"strings"
	"testing"
)

func TestBenchmarkRequestProfilesAndIdentifiers(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ raw, want string }{{"", "kube-bench"}, {" KubeBench ", "kube-bench"}, {"kube-bench", "kube-bench"}, {"docker", "docker-bench"}, {"docker-bench", "docker-bench"}} {
		if value, ok := NormalizeBenchProfile(test.raw); !ok || value != test.want {
			t.Fatalf("profile %q=%q/%v", test.raw, value, ok)
		}
	}
	if _, ok := NormalizeBenchProfile("upstream-shell"); ok {
		t.Fatal("unsupported executable profile accepted")
	}
	for _, pin := range []string{"", "cis-1.9", "eks-1.4.0", "gke-1.6.0", "aks-1.4.0", "k3s-cis-1.24", "rke2-cis-1.24", "custom_distro.v2", strings.Repeat("x", 128)} {
		if !ValidBenchmarkID(pin) {
			t.Fatalf("supported/custom pin refused: %q", pin)
		}
	}
	for _, pin := range []string{"--version", "../cis-1.9", "a/b", "cis 1.9", "a\x00b", "a;b", strings.Repeat("x", 129)} {
		if ValidBenchmarkID(pin) {
			t.Fatalf("unsafe pin accepted: %q", pin)
		}
	}
}
