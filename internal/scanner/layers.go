package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Per-layer vulnerability attribution and Dockerfile-history reconstruction.
//
// NeuVector's image report surfaces, per layer, the build instruction that
// created it (the Dockerfile line) and the vulnerabilities introduced at that
// layer, and tags layers base-vs-application. Constellation derives the same
// from data it already pulls without extracting layer blobs:
//
//   - The OCI image config (config.history[] + rootfs.diff_ids) gives, in build
//     order, the instruction text and the uncompressed layer digest (diff_id)
//     for every non-empty-layer history entry. config.history records ENV/CMD/
//     LABEL/etc. as empty_layer=true entries that do NOT consume a diff_id, so
//     diff_ids are assigned only to the non-empty-layer history rows, in order.
//   - Syft records each package's residing layer as the uncompressed diff_id in
//     PackageLocation.LayerDigest, so joining package locations to layer diff_ids
//     attributes packages — and the findings that matched them — to a layer.
//   - Base-vs-app uses the same base-boundary as the per-package co-residence
//     rule in baseimage.go: the base region is the contiguous prefix of layers
//     carrying ONLY OS/distro packages, ending at the FIRST layer that introduces
//     non-OS (language/application) content. That boundary layer and everything
//     above it are application; everything below is base. Base-ness is NOT
//     propagated up to the highest layer that merely happens to carry an OS
//     package, so an `apk/apt install` in a derived stage cannot retroactively
//     re-label intervening application layers as base.
//
// This file performs no blob extraction: it consumes the small config JSON
// (history + diff_ids) and the SBOM that earlier stages already produced.

// enrichLayerHistory folds OCI config history and rootfs diff_ids onto the
// manifest layers in meta, in place. history is the full config.history[] list
// (including empty-layer entries) in build order; diffIDs is rootfs.diff_ids in
// build order (one per non-empty-layer history entry, and one per manifest
// layer). It assigns each manifest layer its Index, DiffID, and the build
// instruction (CreatedBy/Command/Comment/Author/CreatedAt) of the history entry
// that produced it.
func EnrichLayerHistory(meta *ImageLayerMetadata, history []LayerHistoryEntry, diffIDs []string) {
	if meta == nil {
		return
	}
	for i := range meta.Layers {
		meta.Layers[i].Index = i
		if i < len(diffIDs) {
			meta.Layers[i].DiffID = strings.TrimSpace(diffIDs[i])
		}
	}

	// Walk history in order; every non-empty-layer entry consumes the next
	// manifest layer slot. Empty-layer entries (ENV/CMD/LABEL/WORKDIR/...) carry
	// no layer and are skipped for the layer join.
	layerIdx := 0
	for _, h := range history {
		if h.EmptyLayer {
			continue
		}
		if layerIdx >= len(meta.Layers) {
			break
		}
		applyHistoryToLayer(&meta.Layers[layerIdx], h)
		layerIdx++
	}
}

func applyHistoryToLayer(layer *ImageLayer, h LayerHistoryEntry) {
	layer.CreatedBy = strings.TrimSpace(h.CreatedBy)
	layer.Command = dockerfileInstruction(h.CreatedBy)
	layer.Comment = strings.TrimSpace(h.Comment)
	layer.Author = strings.TrimSpace(h.Author)
	layer.CreatedAt = strings.TrimSpace(h.Created)
}

// dockerfileInstruction normalizes a raw OCI created_by string to the
// Dockerfile-style instruction. BuildKit/Docker prefix metadata instructions
// with "/bin/sh -c #(nop) " and shell-form RUN steps with "/bin/sh -c ".
func dockerfileInstruction(createdBy string) string {
	s := strings.TrimSpace(createdBy)
	if s == "" {
		return ""
	}
	if idx := strings.Index(s, "#(nop)"); idx >= 0 {
		return strings.TrimSpace(s[idx+len("#(nop)"):])
	}
	for _, prefix := range []string{"/bin/sh -c ", "|"} {
		if strings.HasPrefix(s, prefix) {
			rest := strings.TrimSpace(strings.TrimPrefix(s, prefix))
			// buildkit RUN lines are shell-form; present them as RUN.
			if prefix == "/bin/sh -c " {
				return "RUN " + rest
			}
			return rest
		}
	}
	return s
}

// attributeLayers fills per-layer base-vs-app attribution and per-layer
// vulnerability rollups on meta, in place, using the SBOM packages and the
// canonical findings. It is safe to call with a nil meta or empty layers.
func AttributeLayers(meta *ImageLayerMetadata, packages []Package, findings []Finding) {
	if meta == nil || len(meta.Layers) == 0 {
		return
	}

	// diffID -> layer index, for joining package locations to layers.
	layerByDiffID := map[string]int{}
	for i := range meta.Layers {
		if d := strings.TrimSpace(meta.Layers[i].DiffID); d != "" {
			layerByDiffID[d] = i
		}
		// Fall back to the compressed digest if no diff_id is known, so images
		// whose config we could not read still get a (best-effort) join.
		if d := strings.TrimSpace(meta.Layers[i].Digest); d != "" {
			if _, ok := layerByDiffID[d]; !ok {
				layerByDiffID[d] = i
			}
		}
	}

	attributeLayerBaseImage(meta, packages, layerByDiffID)
	reconcilePackageBaseImage(meta, packages, findings, layerByDiffID)
	rollupLayerVulns(meta, packages, findings, layerByDiffID)
}

// reconcilePackageBaseImage re-derives each package's (and each finding's)
// InBaseImage from the authoritative per-LAYER base flags computed by
// attributeLayerBaseImage, so the layer-granularity flag and the
// package/finding-granularity flag can never contradict. The aggregator's
// earlier co-residence pass (baseimage.go) runs WITHOUT manifest layer ordering;
// once ordering is known here we treat the layer boundary as canonical. A
// package is base iff every layer it physically resides in is a base layer; a
// package with no layer mapping keeps whatever the co-residence pass decided.
func reconcilePackageBaseImage(meta *ImageLayerMetadata, packages []Package, findings []Finding, layerByDiffID map[string]int) {
	// Any layer carrying a base flag means the boundary was established; if none
	// were flagged (no OS layer) leave the co-residence attribution untouched.
	established := false
	for i := range meta.Layers {
		if meta.Layers[i].InBaseImage != nil {
			established = true
			break
		}
	}
	if !established {
		return
	}
	for i := range packages {
		keys := packageLayerKeys(&packages[i])
		mapped := false
		allBase := true
		for _, key := range keys {
			idx, ok := layerByDiffID[strings.TrimSpace(key)]
			if !ok {
				continue
			}
			mapped = true
			if flag := meta.Layers[idx].InBaseImage; flag == nil || !*flag {
				allBase = false
			}
		}
		if !mapped {
			continue
		}
		packages[i].InBaseImage = boolPtr(allBase)
	}
	applyBaseImageToFindings(findings, baseImageIndex(packages))
}

// attributeLayerBaseImage marks each layer base or application using the SAME
// base-boundary as the per-package co-residence rule in baseimage.go: the base
// region is the contiguous prefix of layers that carry ONLY OS/distro packages.
// The boundary is the FIRST layer that introduces non-OS (language/application)
// content; that layer and everything above it are application layers, and every
// layer below it is base. This deliberately does NOT propagate base-ness up to
// the highest layer that happens to carry an OS package: an `apk/apt/yum install`
// run in a derived application stage records its OS package in a high layer, and
// the old ancestry-max heuristic mislabeled all the intervening application
// layers (COPY app, RUN npm/pip install) below it as base, inverting the
// rebase-the-base vs fix-the-app triage signal this field exists for.
func attributeLayerBaseImage(meta *ImageLayerMetadata, packages []Package, layerByDiffID map[string]int) {
	// firstApp is the lowest layer index that carries a non-OS package; that is
	// where the application region begins. -1 means no application layer seen.
	firstApp := -1
	// haveOSLayer records whether any OS package mapped to a layer at all; without
	// one we cannot establish a base boundary (matches the per-package rule, which
	// leaves attribution nil rather than guessing).
	haveOSLayer := false
	for i := range packages {
		isOS := packageIsOS(&packages[i])
		for _, key := range packageLayerKeys(&packages[i]) {
			idx, ok := layerByDiffID[strings.TrimSpace(key)]
			if !ok {
				continue
			}
			if isOS {
				haveOSLayer = true
				continue
			}
			if firstApp < 0 || idx < firstApp {
				firstApp = idx
			}
		}
	}
	if !haveOSLayer {
		// No OS package mapped to a layer: cannot establish a base boundary.
		return
	}
	for i := range meta.Layers {
		base := firstApp < 0 || i < firstApp
		meta.Layers[i].InBaseImage = boolPtr(base)
	}
}

// rollupLayerVulns attributes each finding to the layer(s) its vulnerable
// package resides in and aggregates severity counts plus distinct IDs per
// layer. PackageCount is filled from distinct packages per layer.
func rollupLayerVulns(meta *ImageLayerMetadata, packages []Package, findings []Finding, layerByDiffID map[string]int) {
	// Per-layer package set (for PackageCount).
	pkgPerLayer := make([]map[string]struct{}, len(meta.Layers))
	for i := range packages {
		for _, key := range packageLayerKeys(&packages[i]) {
			idx, ok := layerByDiffID[strings.TrimSpace(key)]
			if !ok {
				continue
			}
			if pkgPerLayer[idx] == nil {
				pkgPerLayer[idx] = map[string]struct{}{}
			}
			pkgPerLayer[idx][packageIdentity(&packages[i])] = struct{}{}
		}
	}

	// Map (ecosystem,name,version) -> layer indices, so a finding inherits the
	// layers of its matched package even though findings carry no locations.
	pkgLayers := map[string][]int{}
	for i := range packages {
		layers := []int{}
		for _, key := range packageLayerKeys(&packages[i]) {
			if idx, ok := layerByDiffID[strings.TrimSpace(key)]; ok {
				layers = append(layers, idx)
			}
		}
		if len(layers) == 0 {
			continue
		}
		full := baseImageKey(packages[i].Ecosystem, packages[i].Name, packages[i].Version)
		if full != "" {
			pkgLayers[full] = layers
		}
		loose := baseImageKey("", packages[i].Name, packages[i].Version)
		if loose != "" {
			if _, ok := pkgLayers[loose]; !ok {
				pkgLayers[loose] = layers
			}
		}
	}

	rollups := make([]*LayerVulnRollup, len(meta.Layers))
	seenPerLayer := make([]map[string]struct{}, len(meta.Layers))
	for fi := range findings {
		pkg := findings[fi].Package
		layers, ok := pkgLayers[baseImageKey(pkg.Ecosystem, pkg.Name, pkg.Version)]
		if !ok {
			layers, ok = pkgLayers[baseImageKey("", pkg.Name, pkg.Version)]
		}
		if !ok {
			continue
		}
		id := strings.TrimSpace(findings[fi].VulnerabilityID)
		for _, idx := range layers {
			if rollups[idx] == nil {
				rollups[idx] = &LayerVulnRollup{}
				seenPerLayer[idx] = map[string]struct{}{}
			}
			if id != "" {
				if _, dup := seenPerLayer[idx][id]; dup {
					continue
				}
				seenPerLayer[idx][id] = struct{}{}
				rollups[idx].IDs = append(rollups[idx].IDs, id)
			}
			rollups[idx].Total++
			bumpSeverity(rollups[idx], findings[fi].Severity)
		}
	}

	for i := range meta.Layers {
		meta.Layers[i].PackageCount = len(pkgPerLayer[i])
		if rollups[i] != nil {
			sort.Strings(rollups[i].IDs)
			meta.Layers[i].Vulnerabilities = rollups[i]
		}
	}
}

func bumpSeverity(r *LayerVulnRollup, severity string) {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		r.Critical++
	case "high":
		r.High++
	case "medium", "moderate":
		r.Medium++
	case "low":
		r.Low++
	case "negligible":
		r.Negligible++
	default:
		r.Unknown++
	}
}

func packageIdentity(pkg *Package) string {
	return baseImageKey(pkg.Ecosystem, pkg.Name, pkg.Version)
}

// fetchLayerHistory reads the image's OCI config (history + rootfs.diff_ids) via
// a registry metadata pull. It fetches only the small config object, never layer
// blobs, mirroring the go-containerregistry usage in file_risk.go.
func FetchLayerHistory(ctx context.Context, ref, platform string, insecure bool) ([]LayerHistoryEntry, []string, error) {
	parseOpts := []name.Option{}
	if insecure {
		parseOpts = append(parseOpts, name.Insecure)
	}
	parsed, err := name.ParseReference(ref, parseOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("layers: parse image ref: %w", err)
	}
	remoteOpts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithUserAgent("constellation-scanner"),
	}
	if strings.TrimSpace(platform) != "" {
		p, err := v1.ParsePlatform(platform)
		if err != nil {
			return nil, nil, fmt.Errorf("layers: parse platform: %w", err)
		}
		remoteOpts = append(remoteOpts, remote.WithPlatform(*p))
	}
	img, err := remote.Image(parsed, remoteOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("layers: pull image metadata: %w", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, nil, fmt.Errorf("layers: image config: %w", err)
	}
	return historyFromConfig(cfg), diffIDsFromConfig(cfg), nil
}

func historyFromConfig(cfg *v1.ConfigFile) []LayerHistoryEntry {
	if cfg == nil {
		return nil
	}
	out := make([]LayerHistoryEntry, 0, len(cfg.History))
	for _, h := range cfg.History {
		created := ""
		if !h.Created.Time.IsZero() {
			created = h.Created.Time.UTC().Format("2006-01-02T15:04:05Z")
		}
		out = append(out, LayerHistoryEntry{
			CreatedBy:  h.CreatedBy,
			Comment:    h.Comment,
			Author:     h.Author,
			Created:    created,
			EmptyLayer: h.EmptyLayer,
		})
	}
	return out
}

func diffIDsFromConfig(cfg *v1.ConfigFile) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.RootFS.DiffIDs))
	for _, d := range cfg.RootFS.DiffIDs {
		out = append(out, d.String())
	}
	return out
}
