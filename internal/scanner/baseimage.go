package scanner

import (
	"fmt"
	"strings"
)

// Base-image vs application-layer attribution.
//
// NeuVector tags every vulnerability with ScanVulnerability.InBase (share/scan):
// was the vulnerable package introduced by the image's base layers or by an
// application layer added on top. The exact mechanism NeuVector uses to compute
// InBase is not present in its open-source tree (the scanner that fills it is a
// closed-source component), so do not characterize it as a proven layer-FS diff.
// Constellation derives base-vs-app attribution in this path from the layer
// evidence Syft already records in each Package.Locations entry plus the
// package's ecosystem — without fetching or extracting layer blobs here. (Note:
// this is a property of this SBOM-attribution path specifically; Constellation's
// file-risk scanner, file_risk.go, *does* extract and walk layer blobs elsewhere,
// so "Constellation never extracts blobs" is not true product-wide.)
//
// Heuristic (deterministic over the SBOM, no network, no blob fetch):
//
//   - A layer is a "base layer" if it contains at least one OS / distro package
//     (apk / deb / rpm, or a package carrying an OS namespace). OS package
//     managers only populate the base of an image; application layers added on
//     top carry language packages (npm / pypi / go / ...).
//   - A package is InBaseImage=true when it is itself an OS package, or when
//     every layer it resides in is a base layer.
//   - A package is InBaseImage=false when it has layer evidence and at least one
//     of its layers is not a base layer (i.e. an application layer).
//   - When a package has no layer evidence and is not an OS package, attribution
//     is left nil rather than guessed.
//
// This is intentionally conservative: it never marks a language package as
// base-image unless it physically shares a layer with OS packages, and it never
// invents attribution it cannot support from the SBOM.

// attributeBaseImage fills Package.InBaseImage across the SBOM in place, using
// layer co-residence with OS packages. It returns a digest+name->*bool lookup so
// findings can inherit the same attribution as their matched package.
func attributeBaseImage(packages []Package) {
	if len(packages) == 0 {
		return
	}

	// First pass: identify which layers contain at least one OS package.
	baseLayers := map[string]struct{}{}
	for i := range packages {
		if !packageIsOS(&packages[i]) {
			continue
		}
		for _, layer := range packageLayerKeys(&packages[i]) {
			baseLayers[layer] = struct{}{}
		}
	}

	// Second pass: attribute each package.
	for i := range packages {
		packages[i].InBaseImage = attributePackage(&packages[i], baseLayers)
	}
}

func attributePackage(pkg *Package, baseLayers map[string]struct{}) *bool {
	if packageIsOS(pkg) {
		return boolPtr(true)
	}
	layers := packageLayerKeys(pkg)
	if len(layers) == 0 {
		// No layer evidence and not an OS package: cannot attribute.
		return nil
	}
	allBase := true
	for _, layer := range layers {
		if _, ok := baseLayers[layer]; !ok {
			allBase = false
			break
		}
	}
	return boolPtr(allBase)
}

func packageIsOS(pkg *Package) bool {
	parsed := parsePURL(pkg.Purl)
	return isOSPackage(pkg.Ecosystem, parsed.Type, pkg.NamespaceKind)
}

// packageLayerKeys returns the distinct, normalized layer identifiers a package
// resides in. It prefers the uncompressed layer digest and falls back to the
// layer ID Syft records.
func packageLayerKeys(pkg *Package) []string {
	if len(pkg.Locations) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(pkg.Locations))
	for _, loc := range pkg.Locations {
		key := strings.TrimSpace(loc.LayerDigest)
		if key == "" {
			key = strings.TrimSpace(loc.LayerID)
		}
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

// baseImageIndex builds a lookup from the SBOM's attributed packages so findings
// can inherit base-image attribution from their matched package without
// recomputing it. The key is (ecosystem, name, version); a looser
// (name, version) fallback covers engines that report a slightly different
// ecosystem string than Syft.
func baseImageIndex(packages []Package) map[string]*bool {
	idx := map[string]*bool{}
	for i := range packages {
		pkg := &packages[i]
		if pkg.InBaseImage == nil {
			continue
		}
		full := baseImageKey(pkg.Ecosystem, pkg.Name, pkg.Version)
		if full != "" {
			idx[full] = pkg.InBaseImage
		}
		loose := baseImageKey("", pkg.Name, pkg.Version)
		if loose != "" {
			// Only set the loose key when unambiguous; conflicting attributions
			// for the same (name, version) across ecosystems drop to nil.
			if existing, ok := idx[loose]; ok {
				if existing != nil && *existing != *pkg.InBaseImage {
					idx[loose] = nil
				}
			} else {
				idx[loose] = pkg.InBaseImage
			}
		}
	}
	return idx
}

func baseImageKey(ecosystem, name, version string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(ecosystem)) + "\x00" + name + "\x00" + strings.TrimSpace(version)
}

// applyBaseImageToFindings stamps each finding with the base-image attribution
// of its matched package, and — for base-image findings — an explicit
// rebase-the-base upgrade suggestion.
func applyBaseImageToFindings(findings []Finding, idx map[string]*bool) {
	if len(idx) == 0 {
		return
	}
	for i := range findings {
		pkg := findings[i].Package
		if attr, ok := idx[baseImageKey(pkg.Ecosystem, pkg.Name, pkg.Version)]; ok && attr != nil {
			findings[i].InBaseImage = boolPtr(*attr)
			findings[i].Package.InBaseImage = boolPtr(*attr)
			findings[i].BaseImageUpgrade = baseImageUpgradeSuggestion(&findings[i])
			continue
		}
		if attr, ok := idx[baseImageKey("", pkg.Name, pkg.Version)]; ok && attr != nil {
			findings[i].InBaseImage = boolPtr(*attr)
			findings[i].Package.InBaseImage = boolPtr(*attr)
			findings[i].BaseImageUpgrade = baseImageUpgradeSuggestion(&findings[i])
		}
	}
}

// baseImageUpgradeSuggestion builds human-readable rebase-the-base remediation
// guidance for a finding, modeled on NeuVector's per-item Remediation/Suggestion
// (share/scan/scan_report.go). It only speaks for findings attributed to the base
// image (InBaseImage == true): those are fixed by rebasing onto a newer base
// image rather than by bumping an application dependency. App-introduced findings
// (false) and unattributed ones (nil) return "" so the field stays absent.
//
// Two shapes:
//   - a fix exists upstream  -> tell the operator to rebase onto a base image that
//     ships the fixed package version;
//   - no fix exists yet      -> tell the operator to track the base image for a
//     newer tag that drops or patches the package.
func baseImageUpgradeSuggestion(f *Finding) string {
	if f.InBaseImage == nil || !*f.InBaseImage {
		return ""
	}
	pkgName := strings.TrimSpace(f.Package.Name)
	if pkgName == "" {
		return ""
	}
	base := strings.TrimSpace(f.Package.BaseImage)
	baseClause := "the base image"
	if base != "" {
		baseClause = "base image " + base
	}
	fixed := strings.TrimSpace(f.FixedVersion)
	if fixed != "" {
		return fmt.Sprintf(
			"Base-image package %q is fixed in %s: rebase onto a newer %s tag that ships %s >= %s.",
			pkgName, fixed, baseClause, pkgName, fixed,
		)
	}
	return fmt.Sprintf(
		"Base-image package %q has no upstream fix yet: track %s for a newer tag that drops or patches %s.",
		pkgName, baseClause, pkgName,
	)
}

func boolPtr(b bool) *bool { return &b }
