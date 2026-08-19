// Package sbom emits SPDX 2.3 + CycloneDX 1.6 from a scanner.ScanResult.
//
// Both formats are required by FR-7 (SBOM endpoints) and the spec's "Supply chain security"
// pillar. We hand-roll the JSON shapes (rather than vendoring spdx-tools / cyclonedx-go)
// because the package surface we emit is narrow and stable, and we want zero non-stdlib
// dependencies in this hot-path code.
package sbom

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/scanner"
)

// SPDX2_3 builds an SPDX 2.3 JSON-LD document.
//
// Spec: https://spdx.github.io/spdx-spec/v2.3/
func SPDX2_3(version string, res *scanner.ScanResult) map[string]interface{} {
	docID := "SPDXRef-DOCUMENT"
	now := time.Now().UTC().Format(time.RFC3339)

	pkgs := make([]map[string]interface{}, 0, len(res.Packages)+1)

	// Root package: the container image itself.
	imgRef := spdxRef("Image-" + res.ImageRef)
	pkgs = append(pkgs, map[string]interface{}{
		"SPDXID":           imgRef,
		"name":             res.ImageRef,
		"downloadLocation": "NOASSERTION",
		"filesAnalyzed":    false,
		"versionInfo":      "",
	})

	relationships := []map[string]interface{}{{
		"spdxElementId":      docID,
		"relationshipType":   "DESCRIBES",
		"relatedSpdxElement": imgRef,
	}}

	for _, p := range res.Packages {
		id := spdxRef(fmt.Sprintf("Pkg-%s-%s-%s", p.Ecosystem, p.Name, p.Version))
		pkg := map[string]interface{}{
			"SPDXID":           id,
			"name":             p.Name,
			"versionInfo":      p.Version,
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed":    false,
		}
		if p.Purl != "" {
			pkg["externalRefs"] = []map[string]interface{}{{
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceLocator":  p.Purl,
				"referenceType":     "purl",
			}}
		}
		if len(p.Licenses) > 0 {
			pkg["licenseConcluded"] = joinLicenses(p.Licenses)
			pkg["licenseDeclared"] = joinLicenses(p.Licenses)
		} else {
			pkg["licenseConcluded"] = "NOASSERTION"
			pkg["licenseDeclared"] = "NOASSERTION"
		}
		if comment := packageLocationAnnotation(p); comment != "" {
			pkg["annotations"] = []map[string]interface{}{{
				"annotationType": "OTHER",
				"annotator":      "Tool: Constellation-" + version,
				"annotationDate": now,
				"comment":        comment,
			}}
		}
		pkgs = append(pkgs, pkg)
		relationships = append(relationships, map[string]interface{}{
			"spdxElementId":      imgRef,
			"relationshipType":   "CONTAINS",
			"relatedSpdxElement": id,
		})
	}

	return map[string]interface{}{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            docID,
		"documentNamespace": fmt.Sprintf("https://constellation.alphabravo.io/sbom/%s", res.ImageRef),
		"name":              "Constellation SBOM for " + res.ImageRef,
		"creationInfo": map[string]interface{}{
			"created":  now,
			"creators": []string{"Tool: Constellation-" + version},
		},
		"packages":      pkgs,
		"relationships": relationships,
	}
}

// CycloneDX1_6 builds a CycloneDX 1.6 JSON document.
//
// Spec: https://cyclonedx.org/docs/1.6/json/
func CycloneDX1_6(version string, res *scanner.ScanResult) map[string]interface{} {
	now := time.Now().UTC().Format(time.RFC3339)
	components := make([]map[string]interface{}, 0, len(res.Packages))
	for _, p := range res.Packages {
		c := map[string]interface{}{
			"type":    typeForEcosystem(p.Ecosystem),
			"name":    p.Name,
			"version": p.Version,
		}
		if p.Purl != "" {
			c["purl"] = p.Purl
		}
		if len(p.Licenses) > 0 {
			licenses := make([]map[string]interface{}, 0, len(p.Licenses))
			for _, l := range p.Licenses {
				licenses = append(licenses, map[string]interface{}{
					"license": map[string]string{"name": l},
				})
			}
			c["licenses"] = licenses
		}
		if properties := packageLocationProperties(p); len(properties) > 0 {
			c["properties"] = properties
		}
		components = append(components, c)
	}

	vulns := make([]map[string]interface{}, 0, len(res.Findings))
	for _, f := range res.Findings {
		v := map[string]interface{}{
			"id": f.VulnerabilityID,
			"source": map[string]string{
				"name": "Constellation Aggregator",
			},
			"ratings": []map[string]interface{}{{
				"source":   map[string]string{"name": "NVD"},
				"score":    f.CVSSBase,
				"severity": f.Severity,
				"method":   "CVSSv3",
				"vector":   f.CVSSVector,
			}},
			"affects": []map[string]interface{}{{
				"ref": fmt.Sprintf("pkg:%s/%s@%s", f.Package.Ecosystem, f.Package.Name, f.Package.Version),
			}},
		}
		if f.Description != "" {
			v["description"] = f.Description
		}
		vulns = append(vulns, v)
	}

	return map[string]interface{}{
		"$schema":      "http://cyclonedx.org/schema/bom-1.6.schema.json",
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"version":      1,
		"serialNumber": "urn:uuid:" + uuidV4(),
		"metadata": map[string]interface{}{
			"timestamp": now,
			"tools": []map[string]interface{}{{
				"vendor":  "AlphaBravo",
				"name":    "Constellation",
				"version": version,
			}},
			"component": map[string]interface{}{
				"type":    "container",
				"name":    res.ImageRef,
				"bom-ref": "image-" + sha1Hex(res.ImageRef),
			},
		},
		"components":      components,
		"vulnerabilities": vulns,
	}
}

func packageLocationAnnotation(pkg scanner.Package) string {
	if len(pkg.Locations) == 0 {
		return ""
	}
	raw, err := json.Marshal(pkg.Locations)
	if err != nil {
		return ""
	}
	return "constellation.package.locations=" + string(raw)
}

func packageLocationProperties(pkg scanner.Package) []map[string]string {
	if len(pkg.Locations) == 0 {
		return nil
	}
	props := []map[string]string{}
	for i, loc := range pkg.Locations {
		prefix := fmt.Sprintf("constellation:package:location:%d", i)
		for _, item := range []struct {
			name  string
			value string
		}{
			{"path", loc.Path},
			{"access_path", loc.AccessPath},
			{"real_path", loc.RealPath},
			{"layer_id", loc.LayerID},
			{"layer_digest", loc.LayerDigest},
		} {
			if strings.TrimSpace(item.value) == "" {
				continue
			}
			props = append(props, map[string]string{
				"name":  prefix + ":" + item.name,
				"value": strings.TrimSpace(item.value),
			})
		}
	}
	return props
}

func typeForEcosystem(eco string) string {
	switch strings.ToLower(eco) {
	case "alpine", "debian", "deb", "rpm", "apk":
		return "operating-system"
	case "go", "npm", "pypi", "maven", "gem", "cargo":
		return "library"
	}
	return "library"
}

func joinLicenses(licenses []string) string {
	if len(licenses) == 1 {
		return licenses[0]
	}
	return strings.Join(licenses, " AND ")
}

func spdxRef(s string) string {
	// SPDXIDs must match `[A-Za-z0-9.-]+`.
	var b strings.Builder
	b.WriteString("SPDXRef-")
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

func sha1Hex(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// uuidV4 returns a UUID-shaped string. We use a stable construction (sha1 of input + time)
// because pulling google/uuid into this hot-path is unnecessary; the only consumer is
// CycloneDX's serialNumber field which only needs uniqueness, not crypto guarantees.
func uuidV4() string {
	h := sha1.Sum([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Nanosecond())))
	hex := hex.EncodeToString(h[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex[0:8], hex[8:12], "4"+hex[13:16], "8"+hex[17:20], hex[20:32])
}
