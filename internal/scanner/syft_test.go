package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPackageFromSyftArtifactCarriesOSNamespaceMetadata(t *testing.T) {
	tests := []struct {
		name          string
		artifact      syftArtifact
		distro        syftDistro
		imageRef      string
		wantNamespace string
		wantVersion   string
		wantArch      string
		wantCPEs      []string
		wantImageRepo string
		wantImageTag  string
	}{
		{
			name: "ubuntu deb",
			artifact: syftArtifact{
				Name:    "openssl",
				Version: "3.0.2-0ubuntu1.17",
				Type:    "deb",
				Purl:    "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.17?arch=amd64",
				CPEs:    []string{" cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:* ", "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"},
			},
			distro:        syftDistro{ID: "ubuntu", VersionID: "24.04"},
			imageRef:      "ubuntu:24.04",
			wantNamespace: "ubuntu",
			wantVersion:   "24.04",
			wantArch:      "amd64",
			wantCPEs:      []string{"cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"},
			wantImageRepo: "ubuntu",
			wantImageTag:  "24.04",
		},
		{
			name: "alpine apk",
			artifact: syftArtifact{
				Name:    "busybox",
				Version: "1.36.1-r2",
				Type:    "apk",
				Purl:    "pkg:apk/alpine/busybox@1.36.1-r2?arch=x86_64",
			},
			distro:        syftDistro{ID: "alpine", VersionID: "3.20"},
			imageRef:      "alpine:3.20",
			wantNamespace: "alpine",
			wantVersion:   "3.20",
			wantArch:      "x86_64",
			wantImageRepo: "alpine",
			wantImageTag:  "3.20",
		},
		{
			name: "rhel rpm",
			artifact: syftArtifact{
				Name:    "openssl-libs",
				Version: "1:3.0.7-18.el9",
				Type:    "rpm",
				Purl:    "pkg:rpm/redhat/openssl-libs@1:3.0.7-18.el9?arch=x86_64",
			},
			distro:        syftDistro{ID: "redhat", VersionID: "9.4"},
			imageRef:      "registry.access.redhat.com/ubi9/ubi:9.4",
			wantNamespace: "rhel",
			wantVersion:   "9.4",
			wantArch:      "x86_64",
			wantImageRepo: "registry.access.redhat.com/ubi9/ubi",
			wantImageTag:  "9.4",
		},
		{
			name: "amazon rpm",
			artifact: syftArtifact{
				Name:    "openssl-libs",
				Version: "1:3.0.8-1.amzn2023",
				Type:    "rpm",
				Purl:    "pkg:rpm/amazon/openssl-libs@1:3.0.8-1.amzn2023?arch=x86_64",
			},
			distro:        syftDistro{ID: "amzn", VersionID: "2023"},
			imageRef:      "public.ecr.aws/amazonlinux/amazonlinux:2023",
			wantNamespace: "amazon",
			wantVersion:   "2023",
			wantArch:      "x86_64",
			wantImageRepo: "public.ecr.aws/amazonlinux/amazonlinux",
			wantImageTag:  "2023",
		},
		{
			name: "sles rpm",
			artifact: syftArtifact{
				Name:    "openssl",
				Version: "3.1.4-150500.5.27.1",
				Type:    "rpm",
				Purl:    "pkg:rpm/sles/openssl@3.1.4-150500.5.27.1?arch=x86_64",
			},
			distro:        syftDistro{ID: "sles", VersionID: "15.5"},
			imageRef:      "registry.suse.com/suse/sle15:15.5",
			wantNamespace: "suse",
			wantVersion:   "15.5",
			wantArch:      "x86_64",
			wantImageRepo: "registry.suse.com/suse/sle15",
			wantImageTag:  "15.5",
		},
		{
			name: "wolfi apk",
			artifact: syftArtifact{
				Name:    "wolfi-baselayout",
				Version: "20230201-r18",
				Type:    "apk",
				Purl:    "pkg:apk/wolfi/wolfi-baselayout@20230201-r18?arch=aarch64",
			},
			distro:        syftDistro{ID: "wolfi", VersionID: "rolling"},
			imageRef:      "cgr.dev/chainguard/wolfi-base:latest",
			wantNamespace: "wolfi",
			wantVersion:   "rolling",
			wantArch:      "aarch64",
			wantImageRepo: "cgr.dev/chainguard/wolfi-base",
			wantImageTag:  "latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := packageFromSyftArtifact(tt.artifact, tt.distro, tt.imageRef)
			if pkg.NamespaceKind != "os" || pkg.NamespaceName != tt.wantNamespace || pkg.NamespaceVersion != tt.wantVersion {
				t.Fatalf("namespace metadata = kind:%q name:%q version:%q", pkg.NamespaceKind, pkg.NamespaceName, pkg.NamespaceVersion)
			}
			if pkg.Arch != tt.wantArch {
				t.Fatalf("arch = %q, want %q", pkg.Arch, tt.wantArch)
			}
			if pkg.BaseImage != tt.imageRef {
				t.Fatalf("base image = %q, want %q", pkg.BaseImage, tt.imageRef)
			}
			if pkg.ImageRepository != tt.wantImageRepo || pkg.ImageTag != tt.wantImageTag {
				t.Fatalf("image hints = repo:%q tag:%q, want repo:%q tag:%q", pkg.ImageRepository, pkg.ImageTag, tt.wantImageRepo, tt.wantImageTag)
			}
			if len(pkg.CPEs) != len(tt.wantCPEs) {
				t.Fatalf("cpes = %#v, want %#v", pkg.CPEs, tt.wantCPEs)
			}
			for i := range tt.wantCPEs {
				if pkg.CPEs[i] != tt.wantCPEs[i] {
					t.Fatalf("cpes = %#v, want %#v", pkg.CPEs, tt.wantCPEs)
				}
			}
		})
	}
}

func TestPackageFromSyftArtifactDoesNotApplyDistroToLanguagePackage(t *testing.T) {
	pkg := packageFromSyftArtifact(syftArtifact{
		Name:    "compat-lib",
		Version: "2.0.5",
		Type:    "npm",
		Purl:    "pkg:npm/compat-lib@2.0.5",
	}, syftDistro{
		ID:        "ubuntu",
		VersionID: "24.04",
	}, "example.test/app:latest")

	if pkg.NamespaceKind != "" || pkg.NamespaceName != "" || pkg.NamespaceVersion != "" {
		t.Fatalf("unexpected namespace metadata on language package: %+v", pkg)
	}
}

func TestPackageFromSyftArtifactCarriesLocationsAndLayerDigest(t *testing.T) {
	pkg := packageFromSyftArtifact(syftArtifact{
		Name:    "openssl",
		Version: "3.0.13-0ubuntu3",
		Type:    "deb",
		Purl:    "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3?arch=amd64",
		Locations: []syftLocation{
			{
				Path:        "/var/lib/dpkg/status",
				AccessPath:  "/var/lib/dpkg/status",
				LayerID:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Coordinates: syftCoordinates{RealPath: "/var/lib/dpkg/status"},
			},
			{
				Path:        "/var/lib/dpkg/status",
				AccessPath:  "/var/lib/dpkg/status",
				LayerID:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Coordinates: syftCoordinates{RealPath: "/var/lib/dpkg/status"},
			},
			{
				Path:        "/usr/share/doc/openssl/copyright",
				LayerDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
	}, syftDistro{ID: "ubuntu", VersionID: "24.04"}, "ubuntu:24.04")

	if len(pkg.Locations) != 2 {
		t.Fatalf("locations = %+v, want two deduped locations", pkg.Locations)
	}
	if pkg.Locations[0].Path != "/var/lib/dpkg/status" ||
		pkg.Locations[0].RealPath != "/var/lib/dpkg/status" ||
		pkg.Locations[0].LayerDigest != "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("first location = %+v", pkg.Locations[0])
	}
	if pkg.Locations[1].LayerDigest != "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("second location = %+v", pkg.Locations[1])
	}
}

func TestSyftCPEsDecodeStringAndObjectForms(t *testing.T) {
	var got struct {
		CPEs syftCPEs `json:"cpes"`
	}
	raw := []byte(`{
		"cpes": [
			" cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:* ",
			{"cpe": "cpe:2.3:a:alpine:alpine:3.16:*:*:*:*:*:*:*", "source": "syft-generated"},
			{"source": "empty"}
		]
	}`)
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode cpes: %v", err)
	}
	want := []string{
		" cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:* ",
		"cpe:2.3:a:alpine:alpine:3.16:*:*:*:*:*:*:*",
	}
	if len(got.CPEs) != len(want) {
		t.Fatalf("cpes = %#v, want %#v", []string(got.CPEs), want)
	}
	for i := range want {
		if got.CPEs[i] != want[i] {
			t.Fatalf("cpes = %#v, want %#v", []string(got.CPEs), want)
		}
	}
}

func TestPackagesFromSyftDocumentFixtures(t *testing.T) {
	tests := []struct {
		name          string
		file          string
		imageRef      string
		packageName   string
		wantNamespace string
		wantVersion   string
		wantArch      string
		wantRepo      string
		wantImageRepo string
		wantImageTag  string
		wantModule    string
		wantCPE       string
		wantLicense   string
	}{
		{
			name:          "ubuntu full syft document",
			file:          "ubuntu-24.04.json",
			imageRef:      "ubuntu:24.04",
			packageName:   "openssl",
			wantNamespace: "ubuntu",
			wantVersion:   "24.04",
			wantArch:      "amd64",
			wantImageRepo: "ubuntu",
			wantImageTag:  "24.04",
			wantCPE:       "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
			wantLicense:   "Apache-2.0",
		},
		{
			name:          "alpine legacy string licenses",
			file:          "alpine-3.20.json",
			imageRef:      "alpine:3.20",
			packageName:   "busybox",
			wantNamespace: "alpine",
			wantVersion:   "3.20",
			wantArch:      "x86_64",
			wantImageRepo: "alpine",
			wantImageTag:  "3.20",
			wantLicense:   "GPL-2.0-only",
		},
		{
			name:          "ubi rpm metadata",
			file:          "ubi-9.4.json",
			imageRef:      "registry.access.redhat.com/ubi9/ubi:9.4",
			packageName:   "openssl-libs",
			wantNamespace: "rhel",
			wantVersion:   "9.4",
			wantArch:      "x86_64",
			wantRepo:      "ubi-9-baseos-rpms",
			wantImageRepo: "registry.access.redhat.com/ubi9/ubi",
			wantImageTag:  "9.4",
			wantModule:    "nodejs:18",
			wantLicense:   "OpenSSL",
		},
		{
			name:          "amazon linux document",
			file:          "amazonlinux-2023.json",
			imageRef:      "public.ecr.aws/amazonlinux/amazonlinux:2023",
			packageName:   "openssl-libs",
			wantNamespace: "amazon",
			wantVersion:   "2023",
			wantArch:      "x86_64",
			wantImageRepo: "public.ecr.aws/amazonlinux/amazonlinux",
			wantImageTag:  "2023",
		},
		{
			name:          "sles document",
			file:          "sles-15.5.json",
			imageRef:      "registry.suse.com/suse/sle15:15.5",
			packageName:   "openssl",
			wantNamespace: "suse",
			wantVersion:   "15.5",
			wantArch:      "x86_64",
			wantImageRepo: "registry.suse.com/suse/sle15",
			wantImageTag:  "15.5",
		},
		{
			name:          "wolfi document",
			file:          "wolfi-rolling.json",
			imageRef:      "cgr.dev/chainguard/wolfi-base:latest",
			packageName:   "wolfi-baselayout",
			wantNamespace: "wolfi",
			wantVersion:   "rolling",
			wantArch:      "aarch64",
			wantImageRepo: "cgr.dev/chainguard/wolfi-base",
			wantImageTag:  "latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "syft", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			var doc syftDocument
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			packages := packagesFromSyftDocument(doc, tt.imageRef)
			var got *Package
			for i := range packages {
				if packages[i].Name == tt.packageName {
					got = &packages[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("package %q not found: %+v", tt.packageName, packages)
			}
			if got.NamespaceKind != "os" || got.NamespaceName != tt.wantNamespace || got.NamespaceVersion != tt.wantVersion {
				t.Fatalf("namespace metadata = kind:%q name:%q version:%q", got.NamespaceKind, got.NamespaceName, got.NamespaceVersion)
			}
			if got.Arch != tt.wantArch {
				t.Fatalf("arch = %q, want %q", got.Arch, tt.wantArch)
			}
			if got.Repository != tt.wantRepo {
				t.Fatalf("repository = %q, want %q", got.Repository, tt.wantRepo)
			}
			if got.ImageRepository != tt.wantImageRepo || got.ImageTag != tt.wantImageTag {
				t.Fatalf("image hints = repo:%q tag:%q, want repo:%q tag:%q", got.ImageRepository, got.ImageTag, tt.wantImageRepo, tt.wantImageTag)
			}
			if got.ModuleStream != tt.wantModule {
				t.Fatalf("module stream = %q, want %q", got.ModuleStream, tt.wantModule)
			}
			if tt.wantCPE != "" && !containsString(got.CPEs, tt.wantCPE) {
				t.Fatalf("cpes = %#v, want %q", got.CPEs, tt.wantCPE)
			}
			if tt.wantLicense != "" && !containsString(got.Licenses, tt.wantLicense) {
				t.Fatalf("licenses = %#v, want %q", got.Licenses, tt.wantLicense)
			}
		})
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
