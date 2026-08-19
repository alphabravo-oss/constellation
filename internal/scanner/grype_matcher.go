package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// GrypePackageMatcher matches an already-collected package inventory (host and
// platform scans, where there is no image to pull) against Grype's LIVE
// vulnerability DB. It synthesizes a CycloneDX SBOM from the packages and runs
// `grype sbom:<file>`, so those scans get the same fresh, upstream-fed data as
// image scans — no local vuln bundle required.
//
// This is the PackageMatcher used when the constellation-vulndb engine is
// disabled: it fills the same slot vulndb did (the ScanPackages path requires a
// matcher), sourcing from Grype's maintained feeds instead of a static bundle.
type GrypePackageMatcher struct {
	Binary string
}

func (m *GrypePackageMatcher) Name() string { return "grype" }

// scannerOfflineDB reports air-gapped mode (CONSTELLATION_SCANNER_OFFLINE_DB): in
// it, Trivy/Grype must not pull DBs from the internet — operators pre-load them.
func scannerOfflineDB() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CONSTELLATION_SCANNER_OFFLINE_DB"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// grypeEnv builds the env for a grype exec, disabling grype's implicit per-run DB
// auto-update in air-gapped mode so it uses only the pre-loaded local DB.
func grypeEnv(opts ScanOptions) []string {
	env := registryEnv(opts)
	if scannerOfflineDB() {
		env = append(env, "GRYPE_DB_AUTO_UPDATE=false")
	}
	return env
}

func (m *GrypePackageMatcher) MatchPackages(ctx context.Context, ref string, packages []Package, opts ScanOptions) (*EngineResult, error) {
	start := time.Now()
	bin := m.Binary
	if bin == "" {
		bin = "grype"
	}
	if len(packages) == 0 {
		return &EngineResult{Engine: m.Name(), ImageRef: ref, Confidence: 0.85, Duration: time.Since(start)}, nil
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("grype-matcher: binary not in PATH: %w", err)
	}

	sbom, err := cycloneDXFromPackages(packages)
	if err != nil {
		return nil, fmt.Errorf("grype-matcher: build sbom: %w", err)
	}
	f, err := os.CreateTemp("", "constellation-sbom-*.json")
	if err != nil {
		return nil, fmt.Errorf("grype-matcher: temp file: %w", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(sbom); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("grype-matcher: write sbom: %w", err)
	}
	_ = f.Close()

	ctx, cancel := withTimeout(ctx, opts.Timeout, 10*time.Minute)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "sbom:"+f.Name(), "-o", "json", "-q")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = grypeEnv(opts)
	if err := cmd.Run(); err != nil {
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("grype-matcher: %w (stderr=%s)", err, strings.TrimSpace(stderr.String()))
		}
	}

	var doc grypeReport
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		return nil, fmt.Errorf("grype-matcher: decode JSON: %w", err)
	}
	findings := findingsFromGrypeReport(doc, m.Name())
	return &EngineResult{
		Engine:     m.Name(),
		ImageRef:   ref,
		Findings:   findings,
		Confidence: 0.85,
		Raw:        stdout.Bytes(),
		Duration:   time.Since(start),
	}, nil
}

// --- CycloneDX SBOM synthesis --------------------------------------------------

type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl,omitempty"`
	CPE     string `json:"cpe,omitempty"`
}

type cdxBOM struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Components  []cdxComponent `json:"components"`
}

// cycloneDXFromPackages builds a minimal CycloneDX 1.5 SBOM Grype can match by
// PURL (and CPE). OS packages need a distro-qualified PURL to match distro
// advisories, so we ensure one is present.
func cycloneDXFromPackages(packages []Package) ([]byte, error) {
	comps := make([]cdxComponent, 0, len(packages))
	for _, p := range packages {
		if p.Name == "" || p.Version == "" {
			continue
		}
		purl := p.Purl
		if purl == "" {
			purl = synthPurl(p)
		} else {
			purl = ensureDistroQualifier(purl, p)
		}
		c := cdxComponent{Type: "library", Name: p.Name, Version: p.Version, Purl: purl}
		if len(p.CPEs) > 0 {
			c.CPE = p.CPEs[0]
		}
		comps = append(comps, c)
	}
	return json.Marshal(cdxBOM{BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1, Components: comps})
}

// distroQualifier derives Grype's expected `distro=<id>-<version>` string from a
// package's OS namespace metadata, e.g. "ubuntu-22.04", "alpine-3.18". Empty if
// the package isn't OS-scoped or lacks distro info.
func distroQualifier(p Package) string {
	name := strings.ToLower(p.NamespaceName)
	if name == "" {
		return ""
	}
	ver := p.NamespaceVersion
	if ver == "" {
		ver = p.OSReleaseVersion
	}
	if ver == "" {
		return name
	}
	return name + "-" + ver
}

func isOSType(t string) bool {
	switch t {
	case "apk", "deb", "rpm":
		return true
	}
	return false
}

// purlType maps a package Ecosystem to a purl type.
func purlType(eco string) string {
	switch strings.ToLower(eco) {
	case "apk", "alpine":
		return "apk"
	case "deb", "dpkg", "debian", "ubuntu":
		return "deb"
	case "rpm", "redhat", "rhel", "rpmdb", "amazon", "photon", "suse":
		return "rpm"
	case "npm", "node", "javascript":
		return "npm"
	case "pypi", "python":
		return "pypi"
	case "gem", "ruby", "rubygems":
		return "gem"
	case "go", "golang", "go-module":
		return "golang"
	case "maven", "java", "jar":
		return "maven"
	case "cargo", "rust", "rust-crate":
		return "cargo"
	case "composer", "php":
		return "composer"
	case "nuget", "dotnet":
		return "nuget"
	default:
		return "generic"
	}
}

// synthPurl builds a best-effort PURL for a package that arrived without one.
func synthPurl(p Package) string {
	t := purlType(p.Ecosystem)
	if isOSType(t) {
		ns := strings.ToLower(p.NamespaceName)
		base := "pkg:" + t + "/"
		if ns != "" {
			base += ns + "/"
		}
		out := base + p.Name + "@" + p.Version
		if d := distroQualifier(p); d != "" {
			out += "?distro=" + d
		}
		return out
	}
	return "pkg:" + t + "/" + p.Name + "@" + p.Version
}

// ensureDistroQualifier appends `?distro=` to an OS-package PURL that lacks it,
// so Grype can match distro advisories. Language PURLs are returned unchanged.
func ensureDistroQualifier(purl string, p Package) string {
	if !strings.HasPrefix(purl, "pkg:apk/") && !strings.HasPrefix(purl, "pkg:deb/") && !strings.HasPrefix(purl, "pkg:rpm/") {
		return purl
	}
	if strings.Contains(purl, "distro=") {
		return purl
	}
	d := distroQualifier(p)
	if d == "" {
		return purl
	}
	if strings.Contains(purl, "?") {
		return purl + "&distro=" + d
	}
	return purl + "?distro=" + d
}
