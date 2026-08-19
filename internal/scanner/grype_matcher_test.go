package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCycloneDXFromPackages(t *testing.T) {
	pkgs := []Package{
		// OS package, no PURL → synthesize with distro qualifier.
		{Ecosystem: "deb", Name: "openssl", Version: "1.1.1f-1ubuntu2", NamespaceName: "ubuntu", NamespaceVersion: "20.04"},
		// Language package with a PURL → pass through unchanged.
		{Ecosystem: "maven", Name: "log4j-core", Version: "2.14.1", Purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		// OS package with a PURL that lacks distro → append it.
		{Ecosystem: "deb", Name: "libc6", Version: "2.31", Purl: "pkg:deb/ubuntu/libc6@2.31", NamespaceName: "ubuntu", NamespaceVersion: "20.04"},
		// Alpine, no PURL.
		{Ecosystem: "apk", Name: "musl", Version: "1.2.3-r0", NamespaceName: "alpine", NamespaceVersion: "3.18"},
		// Missing version → skipped.
		{Ecosystem: "npm", Name: "left-pad"},
	}
	b, err := cycloneDXFromPackages(pkgs)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		"pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2?distro=ubuntu-20.04",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		"pkg:deb/ubuntu/libc6@2.31?distro=ubuntu-20.04",
		"pkg:apk/alpine/musl@1.2.3-r0?distro=alpine-3.18",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing purl %q in %s", want, s)
		}
	}
	if strings.Contains(s, "left-pad") {
		t.Errorf("package without version should be skipped")
	}
	var bom cdxBOM
	if err := json.Unmarshal(b, &bom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.5" {
		t.Errorf("bad header: %+v", bom)
	}
	if len(bom.Components) != 4 {
		t.Errorf("want 4 components, got %d", len(bom.Components))
	}
}
