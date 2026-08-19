package scanner

import (
	"encoding/json"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestDockerfileInstruction(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/bin/sh -c #(nop) ADD file:abc123 in / ", "ADD file:abc123 in /"},
		{"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]", "CMD [\"/bin/sh\"]"},
		{"/bin/sh -c apk add --no-cache curl", "RUN apk add --no-cache curl"},
		{"COPY dir:xyz in /app", "COPY dir:xyz in /app"},
		{"", ""},
	}
	for _, c := range cases {
		if got := dockerfileInstruction(c.in); got != c.want {
			t.Fatalf("dockerfileInstruction(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestEnrichLayerHistoryFromSyntheticConfig builds a synthetic manifest+config
// (3 real layers, plus empty-layer ENV/CMD metadata entries) and asserts the
// instruction text + diff_id lands on the right manifest layer, skipping the
// empty-layer history rows that consume no diff_id.
func TestEnrichLayerHistoryFromSyntheticConfig(t *testing.T) {
	meta := &ImageLayerMetadata{
		Layers: []ImageLayer{
			{Digest: "sha256:comp0"},
			{Digest: "sha256:comp1"},
			{Digest: "sha256:comp2"},
		},
	}
	// Build order: base ADD (layer), ENV (empty), RUN apk (layer), LABEL (empty),
	// COPY app (layer), CMD (empty).
	history := []LayerHistoryEntry{
		{CreatedBy: "/bin/sh -c #(nop) ADD file:base in /"},
		{CreatedBy: "/bin/sh -c #(nop)  ENV PATH=/usr/bin", EmptyLayer: true},
		{CreatedBy: "/bin/sh -c apk add --no-cache curl"},
		{CreatedBy: "/bin/sh -c #(nop)  LABEL org=acme", EmptyLayer: true},
		{CreatedBy: "/bin/sh -c #(nop) COPY dir:app in /app"},
		{CreatedBy: "/bin/sh -c #(nop)  CMD [\"/app/run\"]", EmptyLayer: true},
	}
	diffIDs := []string{"sha256:diff0", "sha256:diff1", "sha256:diff2"}

	EnrichLayerHistory(meta, history, diffIDs)

	want := []struct {
		index   int
		diffID  string
		command string
	}{
		{0, "sha256:diff0", "ADD file:base in /"},
		{1, "sha256:diff1", "RUN apk add --no-cache curl"},
		{2, "sha256:diff2", "COPY dir:app in /app"},
	}
	for i, w := range want {
		got := meta.Layers[i]
		if got.Index != w.index {
			t.Errorf("layer %d Index = %d, want %d", i, got.Index, w.index)
		}
		if got.DiffID != w.diffID {
			t.Errorf("layer %d DiffID = %q, want %q", i, got.DiffID, w.diffID)
		}
		if got.Command != w.command {
			t.Errorf("layer %d Command = %q, want %q", i, got.Command, w.command)
		}
		if got.CreatedBy == "" {
			t.Errorf("layer %d CreatedBy unexpectedly empty", i)
		}
	}
}

// TestAttributeLayersBaseVsAppAndVulnRollup builds a 3-layer image: base OS
// layer (deb), a base-side language layer, then an application layer. It joins
// packages by diff_id and asserts (a) base-vs-app propagation along ancestry,
// (b) per-layer vuln rollups with severity counts and distinct IDs, and
// (c) per-layer package counts.
func TestAttributeLayersBaseVsAppAndVulnRollup(t *testing.T) {
	meta := &ImageLayerMetadata{
		Layers: []ImageLayer{
			{Index: 0, DiffID: "sha256:diff0"}, // base OS
			{Index: 1, DiffID: "sha256:diff1"}, // still base (no app content yet)
			{Index: 2, DiffID: "sha256:diff2"}, // application
		},
	}
	packages := []Package{
		{
			Ecosystem: "deb", Name: "openssl", Version: "3.0.13", NamespaceKind: "os",
			Locations: []PackageLocation{{LayerDigest: "sha256:diff0"}},
		},
		{
			Ecosystem: "deb", Name: "libc6", Version: "2.39", NamespaceKind: "os",
			Locations: []PackageLocation{{LayerDigest: "sha256:diff1"}},
		},
		{
			Ecosystem: "npm", Name: "express", Version: "4.18.0",
			Locations: []PackageLocation{{LayerDigest: "sha256:diff2"}},
		},
	}
	findings := []Finding{
		{VulnerabilityID: "CVE-OPENSSL", Severity: "critical", Package: Package{Ecosystem: "deb", Name: "openssl", Version: "3.0.13"}},
		{VulnerabilityID: "CVE-OPENSSL-2", Severity: "high", Package: Package{Ecosystem: "deb", Name: "openssl", Version: "3.0.13"}},
		{VulnerabilityID: "CVE-EXPRESS", Severity: "medium", Package: Package{Ecosystem: "npm", Name: "express", Version: "4.18.0"}},
	}

	AttributeLayers(meta, packages, findings)

	// Base-vs-app: layers 0 and 1 base, layer 2 application.
	for i, want := range []bool{true, true, false} {
		got := meta.Layers[i].InBaseImage
		if got == nil || *got != want {
			t.Fatalf("layer %d InBaseImage = %s, want %v", i, attr(got), want)
		}
	}

	// Layer 0 rollup: two openssl CVEs (critical + high).
	r0 := meta.Layers[0].Vulnerabilities
	if r0 == nil || r0.Total != 2 || r0.Critical != 1 || r0.High != 1 {
		t.Fatalf("layer 0 rollup = %+v, want total=2 critical=1 high=1", r0)
	}
	if len(r0.IDs) != 2 || r0.IDs[0] != "CVE-OPENSSL" || r0.IDs[1] != "CVE-OPENSSL-2" {
		t.Fatalf("layer 0 IDs = %v, want sorted [CVE-OPENSSL CVE-OPENSSL-2]", r0.IDs)
	}
	if meta.Layers[0].PackageCount != 1 {
		t.Fatalf("layer 0 PackageCount = %d, want 1", meta.Layers[0].PackageCount)
	}

	// Layer 1 has a package but no vulns.
	if meta.Layers[1].Vulnerabilities != nil {
		t.Fatalf("layer 1 rollup = %+v, want nil", meta.Layers[1].Vulnerabilities)
	}
	if meta.Layers[1].PackageCount != 1 {
		t.Fatalf("layer 1 PackageCount = %d, want 1", meta.Layers[1].PackageCount)
	}

	// Layer 2 (app) rollup: the express CVE (medium).
	r2 := meta.Layers[2].Vulnerabilities
	if r2 == nil || r2.Total != 1 || r2.Medium != 1 {
		t.Fatalf("layer 2 rollup = %+v, want total=1 medium=1", r2)
	}
}

// TestAttributeLayersOSPackageInAppLayerDoesNotRelabel guards the G2-high
// regression: an OS package added in a DERIVED application stage (e.g.
// `RUN apt-get install` in a layer above COPY'd app content) must NOT drag the
// base boundary up to that high layer and retroactively re-label the intervening
// application layers as base. The boundary is the FIRST application layer.
func TestAttributeLayersOSPackageInAppLayerDoesNotRelabel(t *testing.T) {
	meta := &ImageLayerMetadata{
		Layers: []ImageLayer{
			{Index: 0, DiffID: "sha256:d0"}, // base OS
			{Index: 1, DiffID: "sha256:d1"}, // app: COPY app + npm install
			{Index: 2, DiffID: "sha256:d2"}, // app: RUN apt-get install some-oslib
		},
	}
	packages := []Package{
		{Ecosystem: "deb", Name: "libc6", Version: "2.39", NamespaceKind: "os",
			Locations: []PackageLocation{{LayerDigest: "sha256:d0"}}},
		{Ecosystem: "npm", Name: "express", Version: "4.18.0",
			Locations: []PackageLocation{{LayerDigest: "sha256:d1"}}},
		// OS package added in the TOP application layer.
		{Ecosystem: "deb", Name: "curl", Version: "8.5.0", NamespaceKind: "os",
			Locations: []PackageLocation{{LayerDigest: "sha256:d2"}}},
	}
	findings := []Finding{
		{VulnerabilityID: "CVE-EXPRESS", Severity: "high", Package: Package{Ecosystem: "npm", Name: "express", Version: "4.18.0"}},
		{VulnerabilityID: "CVE-CURL", Severity: "high", Package: Package{Ecosystem: "deb", Name: "curl", Version: "8.5.0"}},
	}
	AttributeLayers(meta, packages, findings)

	// Layer 0 base; layers 1 and 2 application (first app layer is 1).
	for i, want := range []bool{true, false, false} {
		got := meta.Layers[i].InBaseImage
		if got == nil || *got != want {
			t.Fatalf("layer %d InBaseImage = %s, want %v", i, attr(got), want)
		}
	}

	// Per-package/finding attribution must agree with the layer flags: express
	// (layer 1) is app; curl (layer 2, an OS package physically in an app layer)
	// is also app — no contradiction with its layer flag.
	for _, f := range findings {
		if f.InBaseImage == nil || *f.InBaseImage {
			t.Fatalf("finding %s InBaseImage = %s, want false (app layer)", f.VulnerabilityID, attr(f.InBaseImage))
		}
	}
}

// TestAttributeLayersNoOSPackageLeavesAttributionNil ensures we never invent a
// base/app boundary when no OS package maps to a layer.
func TestAttributeLayersNoOSPackageLeavesAttributionNil(t *testing.T) {
	meta := &ImageLayerMetadata{
		Layers: []ImageLayer{{Index: 0, DiffID: "sha256:d0"}},
	}
	packages := []Package{
		{Ecosystem: "npm", Name: "express", Version: "4", Locations: []PackageLocation{{LayerDigest: "sha256:d0"}}},
	}
	AttributeLayers(meta, packages, nil)
	if meta.Layers[0].InBaseImage != nil {
		t.Fatalf("InBaseImage = %s, want nil (no OS layer)", attr(meta.Layers[0].InBaseImage))
	}
}

// TestHistoryAndDiffIDsFromConfig validates the go-containerregistry config
// projection used by FetchLayerHistory, driven by synthetic config JSON.
func TestHistoryAndDiffIDsFromConfig(t *testing.T) {
	const diffA = "sha256:" + "aa" + "00000000000000000000000000000000000000000000000000000000000000"
	const diffB = "sha256:" + "bb" + "00000000000000000000000000000000000000000000000000000000000000"
	raw := `{
		"architecture": "amd64",
		"os": "linux",
		"rootfs": {"type": "layers", "diff_ids": ["` + diffA + `", "` + diffB + `"]},
		"history": [
			{"created_by": "/bin/sh -c #(nop) ADD file:x in /"},
			{"created_by": "/bin/sh -c #(nop) ENV A=1", "empty_layer": true},
			{"created_by": "/bin/sh -c apk add curl"}
		]
	}`
	var cfg v1.ConfigFile
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	hist := historyFromConfig(&cfg)
	if len(hist) != 3 || !hist[1].EmptyLayer || hist[0].CreatedBy == "" {
		t.Fatalf("historyFromConfig = %+v", hist)
	}
	diffIDs := diffIDsFromConfig(&cfg)
	if len(diffIDs) != 2 || diffIDs[0] != diffA || diffIDs[1] != diffB {
		t.Fatalf("diffIDsFromConfig = %v", diffIDs)
	}

	// End-to-end: feed the projection through enrichment and confirm the join.
	meta := &ImageLayerMetadata{Layers: []ImageLayer{{Digest: "c0"}, {Digest: "c1"}}}
	EnrichLayerHistory(meta, hist, diffIDs)
	if meta.Layers[0].Command != "ADD file:x in /" || meta.Layers[0].DiffID != diffA {
		t.Fatalf("layer0 = %+v", meta.Layers[0])
	}
	if meta.Layers[1].Command != "RUN apk add curl" || meta.Layers[1].DiffID != diffB {
		t.Fatalf("layer1 = %+v", meta.Layers[1])
	}
}
