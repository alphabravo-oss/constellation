package sbom

// SBOM diff — compare two SBOMs (SPDX or CycloneDX) and produce a 3-set diff of packages:
// added, removed, version-changed. Surfaces in the UI as the "what changed between
// these two image releases?" view that supply-chain teams use during incident response.
//
// The diff is shape-agnostic: we extract packages from either SBOM via the canonical
// `(ecosystem, name, version)` tuple.

import (
	"encoding/json"
	"sort"
)

// PackageRef is the minimal package identity used for diffing.
type PackageRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// Diff is the result of comparing two SBOMs.
type Diff struct {
	Added   []PackageRef       `json:"added"`
	Removed []PackageRef       `json:"removed"`
	Changed []PackageVersionChange `json:"changed"`
}

// PackageVersionChange is one (ecosystem,name) pair that's present in both SBOMs with a
// different version.
type PackageVersionChange struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
}

// Compare returns a Diff of two SBOM documents (CycloneDX or SPDX). Both arguments must
// be raw JSON; the function inspects the shape to pick the right extractor.
func Compare(oldDoc, newDoc []byte) (Diff, error) {
	a, err := extractPackages(oldDoc)
	if err != nil {
		return Diff{}, err
	}
	b, err := extractPackages(newDoc)
	if err != nil {
		return Diff{}, err
	}

	type key struct{ eco, name string }
	aMap := map[key]string{}
	bMap := map[key]string{}
	for _, p := range a {
		aMap[key{p.Ecosystem, p.Name}] = p.Version
	}
	for _, p := range b {
		bMap[key{p.Ecosystem, p.Name}] = p.Version
	}

	diff := Diff{}
	for k, v := range bMap {
		if old, ok := aMap[k]; ok {
			if old != v {
				diff.Changed = append(diff.Changed, PackageVersionChange{
					Ecosystem: k.eco, Name: k.name, OldVersion: old, NewVersion: v,
				})
			}
		} else {
			diff.Added = append(diff.Added, PackageRef{Ecosystem: k.eco, Name: k.name, Version: v})
		}
	}
	for k, v := range aMap {
		if _, ok := bMap[k]; !ok {
			diff.Removed = append(diff.Removed, PackageRef{Ecosystem: k.eco, Name: k.name, Version: v})
		}
	}
	sort.Slice(diff.Added, func(i, j int) bool { return less(diff.Added[i], diff.Added[j]) })
	sort.Slice(diff.Removed, func(i, j int) bool { return less(diff.Removed[i], diff.Removed[j]) })
	sort.Slice(diff.Changed, func(i, j int) bool {
		if diff.Changed[i].Ecosystem != diff.Changed[j].Ecosystem {
			return diff.Changed[i].Ecosystem < diff.Changed[j].Ecosystem
		}
		return diff.Changed[i].Name < diff.Changed[j].Name
	})
	return diff, nil
}

func less(a, b PackageRef) bool {
	if a.Ecosystem != b.Ecosystem {
		return a.Ecosystem < b.Ecosystem
	}
	return a.Name < b.Name
}

func extractPackages(raw []byte) ([]PackageRef, error) {
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, err
	}
	if _, ok := probe["bomFormat"]; ok {
		return extractFromCycloneDX(raw)
	}
	return extractFromSPDX(raw)
}

func extractFromCycloneDX(raw []byte) ([]PackageRef, error) {
	var doc struct {
		Components []struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := make([]PackageRef, 0, len(doc.Components))
	for _, c := range doc.Components {
		out = append(out, PackageRef{Ecosystem: c.Type, Name: c.Name, Version: c.Version})
	}
	return out, nil
}

func extractFromSPDX(raw []byte) ([]PackageRef, error) {
	var doc struct {
		Packages []struct {
			Name        string `json:"name"`
			VersionInfo string `json:"versionInfo"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := make([]PackageRef, 0, len(doc.Packages))
	for _, p := range doc.Packages {
		out = append(out, PackageRef{Ecosystem: "spdx", Name: p.Name, Version: p.VersionInfo})
	}
	return out, nil
}
