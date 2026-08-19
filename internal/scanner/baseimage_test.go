package scanner

import "testing"

func attr(b *bool) string {
	if b == nil {
		return "nil"
	}
	if *b {
		return "true"
	}
	return "false"
}

func TestAttributeBaseImageByOSEcosystem(t *testing.T) {
	pkgs := []Package{
		{Ecosystem: "deb", Name: "openssl", Version: "3.0.13"},
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
		{Ecosystem: "apk", Name: "musl", Version: "1.2.5", NamespaceKind: "os"},
	}
	attributeBaseImage(pkgs)

	if pkgs[0].InBaseImage == nil || !*pkgs[0].InBaseImage {
		t.Fatalf("deb openssl InBaseImage = %s, want true", attr(pkgs[0].InBaseImage))
	}
	if pkgs[2].InBaseImage == nil || !*pkgs[2].InBaseImage {
		t.Fatalf("apk musl InBaseImage = %s, want true", attr(pkgs[2].InBaseImage))
	}
	// npm package with no layer evidence and not OS: attribution must stay nil.
	if pkgs[1].InBaseImage != nil {
		t.Fatalf("npm left-pad InBaseImage = %s, want nil (no layer evidence)", attr(pkgs[1].InBaseImage))
	}
}

func TestAttributeBaseImageByLayerCoResidence(t *testing.T) {
	// Layer "base" holds an OS package; layer "app" holds only language packages.
	pkgs := []Package{
		{
			Ecosystem: "deb", Name: "libc6", Version: "2.39",
			Locations: []PackageLocation{{LayerDigest: "sha256:base"}},
		},
		{
			// Language package that physically lives in the base OS layer:
			// treated as base-image.
			Ecosystem: "python", Name: "pip", Version: "24.0",
			Locations: []PackageLocation{{LayerDigest: "sha256:base"}},
		},
		{
			// Language package added by an application layer: app-introduced.
			Ecosystem: "npm", Name: "express", Version: "4.18.0",
			Locations: []PackageLocation{{LayerDigest: "sha256:app"}},
		},
		{
			// Spans both a base layer and an app layer: not fully base.
			Ecosystem: "go", Name: "example.com/x", Version: "1.0.0",
			Locations: []PackageLocation{{LayerDigest: "sha256:base"}, {LayerDigest: "sha256:app"}},
		},
	}
	attributeBaseImage(pkgs)

	cases := []struct {
		name string
		idx  int
		want string
	}{
		{"libc6 os", 0, "true"},
		{"pip in base layer", 1, "true"},
		{"express in app layer", 2, "false"},
		{"go spanning base+app", 3, "false"},
	}
	for _, c := range cases {
		if got := attr(pkgs[c.idx].InBaseImage); got != c.want {
			t.Fatalf("%s InBaseImage = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestApplyBaseImageToFindings(t *testing.T) {
	pkgs := []Package{
		{Ecosystem: "deb", Name: "openssl", Version: "3.0.13"},
		{
			Ecosystem: "npm", Name: "express", Version: "4.18.0",
			Locations: []PackageLocation{{LayerDigest: "sha256:app"}},
		},
	}
	attributeBaseImage(pkgs)
	idx := baseImageIndex(pkgs)

	findings := []Finding{
		{VulnerabilityID: "CVE-1", Package: Package{Ecosystem: "deb", Name: "openssl", Version: "3.0.13"}},
		{VulnerabilityID: "CVE-2", Package: Package{Ecosystem: "npm", Name: "express", Version: "4.18.0"}},
		{VulnerabilityID: "CVE-3", Package: Package{Ecosystem: "npm", Name: "unknown", Version: "9.9.9"}},
	}
	applyBaseImageToFindings(findings, idx)

	if findings[0].InBaseImage == nil || !*findings[0].InBaseImage {
		t.Fatalf("CVE-1 InBaseImage = %s, want true", attr(findings[0].InBaseImage))
	}
	if findings[1].InBaseImage == nil || *findings[1].InBaseImage {
		t.Fatalf("CVE-2 InBaseImage = %s, want false", attr(findings[1].InBaseImage))
	}
	if findings[2].InBaseImage != nil {
		t.Fatalf("CVE-3 InBaseImage = %s, want nil (package not in SBOM)", attr(findings[2].InBaseImage))
	}
	if findings[0].Package.InBaseImage == nil || !*findings[0].Package.InBaseImage {
		t.Fatalf("CVE-1 finding package attribution not stamped")
	}
}

func TestBaseImageIndexLooseConflictDropsToNil(t *testing.T) {
	tru, fls := true, false
	pkgs := []Package{
		{Ecosystem: "deb", Name: "shared", Version: "1.0", InBaseImage: &tru},
		{Ecosystem: "npm", Name: "shared", Version: "1.0", InBaseImage: &fls},
	}
	idx := baseImageIndex(pkgs)
	if got := idx[baseImageKey("", "shared", "1.0")]; got != nil {
		t.Fatalf("loose key with conflicting attribution = %s, want nil", attr(got))
	}
	if got := idx[baseImageKey("deb", "shared", "1.0")]; got == nil || !*got {
		t.Fatalf("full deb key = %s, want true", attr(got))
	}
}
