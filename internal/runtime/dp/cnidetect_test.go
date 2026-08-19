package dp

import (
	"os"
	"path/filepath"
	"testing"
)

// helper to build a tempdir with N named files containing the given JSON.
func cniFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDetectCNI_Empty(t *testing.T) {
	dir := t.TempDir()
	if got := DetectCNI(dir).Name; got != CNIUnknown {
		t.Errorf("empty dir → %q, want %q", got, CNIUnknown)
	}
}

func TestDetectCNI_MissingDir(t *testing.T) {
	if got := DetectCNI("/nope/no/no").Name; got != CNIUnknown {
		t.Errorf("missing dir → %q, want %q", got, CNIUnknown)
	}
}

func TestDetectCNI_FilenameMatches(t *testing.T) {
	cases := map[string]string{
		"10-flannel.conflist": CNIFlannel,
		"10-calico.conflist":  CNICalico,
		"05-cilium.conf":      CNICilium,
		"10-weave.conf":       CNIWeave,
	}
	for filename, expect := range cases {
		t.Run(filename, func(t *testing.T) {
			dir := cniFixture(t, map[string]string{filename: `{}`})
			if got := DetectCNI(dir).Name; got != expect {
				t.Errorf("file %q → %q, want %q", filename, got, expect)
			}
		})
	}
}

func TestDetectCNI_ContentMatch(t *testing.T) {
	// Filename doesn't reveal CNI; content does.
	body := `{"plugins":[{"type":"calico"},{"type":"portmap"}]}`
	dir := cniFixture(t, map[string]string{"01-cluster.conflist": body})
	if got := DetectCNI(dir).Name; got != CNICalico {
		t.Errorf("content match → %q, want %q", got, CNICalico)
	}
}

func TestDetectCNI_CiliumWinsOverChained(t *testing.T) {
	// Cilium chained on top of Calico is a real-world setup; our
	// enforcement decision wants Cilium-detect because NFQUEUE is moot.
	dir := cniFixture(t, map[string]string{
		"05-cilium.conflist":  `{}`,
		"10-calico.conflist":  `{}`,
	})
	if got := DetectCNI(dir).Name; got != CNICilium {
		t.Errorf("Cilium chained over Calico → %q, want %q", got, CNICilium)
	}
}

func TestDetectCNI_GarbageJSONFallsThroughToUnknown(t *testing.T) {
	dir := cniFixture(t, map[string]string{
		"99-mystery.conf": `{not even json`,
	})
	if got := DetectCNI(dir).Name; got != CNIUnknown {
		t.Errorf("bad json → %q, want %q", got, CNIUnknown)
	}
}

func TestSafeForNFQUEUE(t *testing.T) {
	cases := map[string]bool{
		CNIFlannel: true,
		CNICalico:  true,
		CNIWeave:   true,
		CNIAWSVPC:  true,
		CNIUnknown: true,
		CNICilium:  false, // the only one that's NOT safe
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			got := CNIInfo{Name: name}.SafeForNFQUEUE()
			if got != want {
				t.Errorf("%q safe=%v want %v", name, got, want)
			}
		})
	}
}

// Wave A4: when called with empty dir, DetectCNI walks
// CandidateCNIDirs in order. We can't safely test this with the real
// filesystem (would interfere with the host) so we just assert that
// CandidateCNIDirs lists every distro we claim to support.
func TestCandidateCNIDirs_CoversKnownDistros(t *testing.T) {
	want := []string{
		"/etc/cni/net.d",
		"/var/lib/rancher/k3s/agent/etc/cni/net.d",
		"/var/lib/rancher/rke2/agent/etc/cni/net.d",
		"/etc/cni/multus/net.d",
		"/var/snap/microk8s/current/args/cni-network",
	}
	for _, w := range want {
		found := false
		for _, c := range CandidateCNIDirs {
			if c == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("CandidateCNIDirs missing %q (the chart's hostPath mount and the in-pod detector path must agree)", w)
		}
	}
	// Also assert /etc/cni/net.d is FIRST so the standard kubeadm/EKS/GKE
	// path wins over weirder distro-specific paths in the common case.
	if CandidateCNIDirs[0] != "/etc/cni/net.d" {
		t.Errorf("/etc/cni/net.d should be the first candidate (standard kubeadm/EKS/GKE path); got %q", CandidateCNIDirs[0])
	}
}

// hasCNIConfig returns false on missing/empty/non-CNI directories. Direct
// behaviour test because the auto-discovery loop relies on this.
func TestHasCNIConfig(t *testing.T) {
	if hasCNIConfig("/this/path/does/not/exist") {
		t.Error("hasCNIConfig must return false for a missing path")
	}
	empty := t.TempDir()
	if hasCNIConfig(empty) {
		t.Error("hasCNIConfig must return false for an empty dir")
	}
	noConfigs := t.TempDir()
	_ = os.WriteFile(filepath.Join(noConfigs, "README.md"), []byte("not a cni config"), 0o644)
	if hasCNIConfig(noConfigs) {
		t.Error("hasCNIConfig must return false when dir has only non-CNI files")
	}
	withConfig := t.TempDir()
	_ = os.WriteFile(filepath.Join(withConfig, "10-flannel.conflist"), []byte("{}"), 0o644)
	if !hasCNIConfig(withConfig) {
		t.Error("hasCNIConfig must return true when dir contains a *.conflist")
	}
}
