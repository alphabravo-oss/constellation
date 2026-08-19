package scanner

import (
	"strings"
	"testing"
)

func TestBaseImageUpgradeSuggestion(t *testing.T) {
	tru, fls := true, false
	cases := []struct {
		name         string
		f            Finding
		wantEmpty    bool
		wantContains []string
	}{
		{
			name: "base image with fix -> rebase guidance names fixed version",
			f: Finding{
				InBaseImage:  &tru,
				FixedVersion: "3.0.14",
				Package:      Package{Name: "openssl", Version: "3.0.13", BaseImage: "debian:12"},
			},
			wantContains: []string{"openssl", "3.0.14", "debian:12", "rebase"},
		},
		{
			name: "base image without fix -> track base tag guidance",
			f: Finding{
				InBaseImage: &tru,
				Package:     Package{Name: "zlib1g", Version: "1.3", BaseImage: "ubuntu:22.04"},
			},
			wantContains: []string{"zlib1g", "no upstream fix", "ubuntu:22.04"},
		},
		{
			name: "base image with fix but unknown base image name still speaks generically",
			f: Finding{
				InBaseImage:  &tru,
				FixedVersion: "1.2.3",
				Package:      Package{Name: "libc6"},
			},
			wantContains: []string{"libc6", "1.2.3", "the base image"},
		},
		{
			name:      "app-introduced finding -> no suggestion",
			f:         Finding{InBaseImage: &fls, FixedVersion: "9.9", Package: Package{Name: "express"}},
			wantEmpty: true,
		},
		{
			name:      "unattributed finding -> no suggestion",
			f:         Finding{Package: Package{Name: "leftpad"}},
			wantEmpty: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := baseImageUpgradeSuggestion(&c.f)
			if c.wantEmpty {
				if got != "" {
					t.Fatalf("suggestion = %q, want empty", got)
				}
				return
			}
			for _, sub := range c.wantContains {
				if !strings.Contains(got, sub) {
					t.Fatalf("suggestion %q missing %q", got, sub)
				}
			}
		})
	}
}

// TestApplyBaseImageStampsSuggestion proves applyBaseImageToFindings surfaces the
// suggestion end-to-end on base-image findings and leaves app-introduced ones bare.
func TestApplyBaseImageStampsSuggestion(t *testing.T) {
	pkgs := []Package{
		{Ecosystem: "deb", Name: "openssl", Version: "3.0.13", BaseImage: "debian:12"},
		{
			Ecosystem: "npm", Name: "express", Version: "4.18.0",
			Locations: []PackageLocation{{LayerDigest: "sha256:app"}},
		},
	}
	attributeBaseImage(pkgs)
	idx := baseImageIndex(pkgs)

	findings := []Finding{
		{VulnerabilityID: "CVE-1", FixedVersion: "3.0.14", Package: Package{Ecosystem: "deb", Name: "openssl", Version: "3.0.13", BaseImage: "debian:12"}},
		{VulnerabilityID: "CVE-2", FixedVersion: "4.19.0", Package: Package{Ecosystem: "npm", Name: "express", Version: "4.18.0"}},
	}
	applyBaseImageToFindings(findings, idx)

	if findings[0].BaseImageUpgrade == "" || !strings.Contains(findings[0].BaseImageUpgrade, "debian:12") {
		t.Fatalf("base finding suggestion = %q", findings[0].BaseImageUpgrade)
	}
	if findings[1].BaseImageUpgrade != "" {
		t.Fatalf("app finding should have no suggestion, got %q", findings[1].BaseImageUpgrade)
	}
}
