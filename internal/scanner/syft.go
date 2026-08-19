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

// SyftEngine wraps the syft CLI. We use syft for SBOM generation and as the package
// source for license findings. Vulnerability matching is delegated to the local VulnDB
// package matcher plus Trivy + Grype + (future) ClairCore — syft alone doesn't match CVEs.
type SyftEngine struct {
	Binary string // path to syft; defaults to "syft"
}

func (s *SyftEngine) Name() string { return "syft" }

func (s *SyftEngine) Scan(ctx context.Context, ref string, opts ScanOptions) (*EngineResult, error) {
	bin := s.Binary
	if bin == "" {
		bin = "syft"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("syft: binary not in PATH: %w", err)
	}

	start := time.Now()
	args := []string{"scan", ref, "-o", "json", "-q"}
	if opts.Platform != "" {
		args = append(args, "--platform", opts.Platform)
	}
	if opts.Insecure {
		args = append(args, "--registry-insecure-skip-tls-verify")
	}

	ctx, cancel := withTimeout(ctx, opts.Timeout, 5*time.Minute)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = registryEnv(opts)

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("syft: %w (stderr=%s)", err, strings.TrimSpace(stderr.String()))
	}

	var doc syftDocument
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		return nil, fmt.Errorf("syft: decode JSON: %w", err)
	}
	packages := packagesFromSyftDocument(doc, ref)

	return &EngineResult{
		Engine:     s.Name(),
		ImageRef:   ref,
		Packages:   packages,
		Confidence: 1.0, // syft is authoritative for SBOM
		Raw:        stdout.Bytes(),
		Duration:   time.Since(start),
	}, nil
}

// syftDocument captures the JSON shape syft emits. The schema is broad; we capture only
// the package-level fields the aggregator needs.
type syftDocument struct {
	Distro    syftDistro     `json:"distro,omitempty"`
	Artifacts []syftArtifact `json:"artifacts"`
}

type syftDistro struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	VersionID string `json:"versionID"`
}

type syftArtifact struct {
	Name      string         `json:"name"`
	Version   string         `json:"version"`
	Type      string         `json:"type"`
	Purl      string         `json:"purl"`
	CPEs      syftCPEs       `json:"cpes,omitempty"`
	Licenses  []syftLicense  `json:"licenses,omitempty"`
	Locations []syftLocation `json:"locations,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type syftLocation struct {
	Path        string          `json:"path,omitempty"`
	AccessPath  string          `json:"accessPath,omitempty"`
	RealPath    string          `json:"realPath,omitempty"`
	LayerID     string          `json:"layerID,omitempty"`
	LayerDigest string          `json:"layerDigest,omitempty"`
	Coordinates syftCoordinates `json:"coordinates,omitempty"`
	Annotations map[string]any  `json:"annotations,omitempty"`
}

type syftCoordinates struct {
	RealPath     string `json:"realPath,omitempty"`
	FileSystemID string `json:"fileSystemID,omitempty"`
}

type syftCPEs []string

func (c *syftCPEs) UnmarshalJSON(data []byte) error {
	var raws []json.RawMessage
	if err := json.Unmarshal(data, &raws); err != nil {
		return err
	}
	out := make([]string, 0, len(raws))
	for _, raw := range raws {
		var value string
		if err := json.Unmarshal(raw, &value); err == nil {
			if strings.TrimSpace(value) != "" {
				out = append(out, value)
			}
			continue
		}
		var obj struct {
			CPE string `json:"cpe,omitempty"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return err
		}
		if strings.TrimSpace(obj.CPE) != "" {
			out = append(out, obj.CPE)
		}
	}
	*c = out
	return nil
}

type syftLicense struct {
	Value          string
	SPDXExpression string
}

func (l *syftLicense) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		l.Value = strings.TrimSpace(s)
		return nil
	}
	var obj struct {
		Value          string `json:"value,omitempty"`
		SPDXExpression string `json:"spdxExpression,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	l.Value = strings.TrimSpace(obj.Value)
	l.SPDXExpression = strings.TrimSpace(obj.SPDXExpression)
	return nil
}

func packagesFromSyftDocument(doc syftDocument, imageRef string) []Package {
	packages := make([]Package, 0, len(doc.Artifacts))
	for _, art := range doc.Artifacts {
		pkg := packageFromSyftArtifact(art, doc.Distro, imageRef)
		for _, lic := range art.Licenses {
			if lic.Value != "" {
				pkg.Licenses = append(pkg.Licenses, lic.Value)
			} else if lic.SPDXExpression != "" {
				pkg.Licenses = append(pkg.Licenses, lic.SPDXExpression)
			}
		}
		packages = append(packages, pkg)
	}
	return packages
}

func packageFromSyftArtifact(art syftArtifact, distro syftDistro, imageRef string) Package {
	imageRepository, imageTag := imageReferenceHints(imageRef)
	pkg := Package{
		Ecosystem:       strings.TrimSpace(art.Type),
		Name:            strings.TrimSpace(art.Name),
		Version:         strings.TrimSpace(art.Version),
		Purl:            strings.TrimSpace(art.Purl),
		CPEs:            trimmedUniqueStrings([]string(art.CPEs)),
		ImageRepository: imageRepository,
		ImageTag:        imageTag,
		BaseImage:       strings.TrimSpace(imageRef),
	}
	parsed := parsePURL(pkg.Purl)
	if arch := strings.TrimSpace(parsed.Qualifiers["arch"]); arch != "" {
		pkg.Arch = arch
	}
	pkg.Repository = syftMetadataString(art.Metadata,
		"repository",
		"repositoryID",
		"repositoryId",
		"repository_id",
		"rpmRepository",
		"rpm_repository",
	)
	pkg.ModuleStream = syftMetadataString(art.Metadata,
		"modularityLabel",
		"moduleStream",
		"module_stream",
		"module",
	)
	pkg.Locations = packageLocationsFromSyft(art.Locations)
	// Record the upstream/source/origin package name so the matcher can also
	// query distro advisories keyed by the SOURCE package (Syft catalogues the
	// installed BINARY name, e.g. libssl3, but advisories are keyed by the
	// source, e.g. openssl). Syft exposes this as the purl "upstream=" qualifier
	// and in metadata (deb "source", apk "originPackage"). See
	// Package.SourcePackage and osPackageQueries.
	pkg.SourcePackage = firstTrimmed(
		parsed.Qualifiers["upstream"],
		syftMetadataString(art.Metadata, "source", "originPackage"),
	)
	if !isOSPackage(pkg.Ecosystem, parsed.Type, "") {
		return pkg
	}
	name, version := syftDistroNamespace(distro)
	// Record the os-release-derived release independently of the per-package
	// namespace so distroless/scratch OS packages (which Syft often emits without
	// a distro qualifier or NamespaceVersion) can still be matched against distro
	// advisories. See Package.OSReleaseVersion and osPackageQueries.
	pkg.OSReleaseVersion = version
	if name == "" || version == "" {
		return pkg
	}
	pkg.NamespaceKind = "os"
	pkg.NamespaceName = name
	pkg.NamespaceVersion = version
	return pkg
}

func packageLocationsFromSyft(locations []syftLocation) []PackageLocation {
	if len(locations) == 0 {
		return nil
	}
	out := make([]PackageLocation, 0, len(locations))
	seen := map[string]struct{}{}
	for _, loc := range locations {
		item := PackageLocation{
			Path:        firstTrimmed(loc.Path, syftAnnotationString(loc.Annotations, "path")),
			AccessPath:  strings.TrimSpace(loc.AccessPath),
			RealPath:    firstTrimmed(loc.RealPath, loc.Coordinates.RealPath),
			LayerID:     firstTrimmed(loc.LayerID, syftAnnotationString(loc.Annotations, "layerID"), syftAnnotationString(loc.Annotations, "layer_id")),
			LayerDigest: firstTrimmed(loc.LayerDigest, loc.Coordinates.FileSystemID, syftAnnotationString(loc.Annotations, "layerDigest"), syftAnnotationString(loc.Annotations, "layer_digest")),
		}
		if item.LayerDigest == "" && strings.HasPrefix(item.LayerID, "sha256:") {
			item.LayerDigest = item.LayerID
		}
		key := item.Path + "\x00" + item.AccessPath + "\x00" + item.RealPath + "\x00" + item.LayerID + "\x00" + item.LayerDigest
		if strings.Trim(key, "\x00") == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func syftAnnotationString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := values[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case fmt.Stringer:
			if strings.TrimSpace(typed.String()) != "" {
				return strings.TrimSpace(typed.String())
			}
		}
	}
	return ""
}

func syftMetadataString(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := metadata[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case fmt.Stringer:
			if strings.TrimSpace(typed.String()) != "" {
				return strings.TrimSpace(typed.String())
			}
		}
	}
	return ""
}

func syftDistroNamespace(d syftDistro) (name, version string) {
	name = canonicalDistroName(firstTrimmed(d.ID, d.Name))
	version = firstTrimmed(d.VersionID, d.Version)
	return name, version
}

func firstTrimmed(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func withTimeout(parent context.Context, requested, fallback time.Duration) (context.Context, context.CancelFunc) {
	d := requested
	if d <= 0 {
		d = fallback
	}
	return context.WithTimeout(parent, d)
}

func registryEnv(opts ScanOptions) []string {
	env := os.Environ()
	if opts.Username != "" || opts.Password != "" {
		env = append(env, "DOCKER_USER="+opts.Username, "DOCKER_PASSWORD="+opts.Password)
	}
	return env
}
