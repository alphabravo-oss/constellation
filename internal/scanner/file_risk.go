package scanner

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const defaultFileRiskMaxFindings = 500

type FileRiskOptions struct {
	Platform    string
	MaxFindings int
	Insecure    bool
}

// ScanImageFileRisks inspects the final layer-applied filesystem metadata for a
// registry image. It reads tar headers only; file contents are skipped.
func ScanImageFileRisks(ctx context.Context, ref string, opts FileRiskOptions) (*ImageFileRiskReport, error) {
	parseOpts := []name.Option{}
	if opts.Insecure {
		parseOpts = append(parseOpts, name.Insecure)
	}
	parsed, err := name.ParseReference(ref, parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("file-risk: parse image ref: %w", err)
	}
	remoteOpts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithUserAgent("constellation-scanner"),
	}
	if strings.TrimSpace(opts.Platform) != "" {
		platform, err := v1.ParsePlatform(opts.Platform)
		if err != nil {
			return nil, fmt.Errorf("file-risk: parse platform: %w", err)
		}
		remoteOpts = append(remoteOpts, remote.WithPlatform(*platform))
	}
	img, err := remote.Image(parsed, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("file-risk: pull image metadata: %w", err)
	}
	return fileRisksFromImage(ref, img, opts)
}

func fileRisksFromImage(imageRef string, img v1.Image, opts FileRiskOptions) (*ImageFileRiskReport, error) {
	maxFindings := opts.MaxFindings
	if maxFindings <= 0 {
		maxFindings = defaultFileRiskMaxFindings
	}
	report := &ImageFileRiskReport{
		ImageRef:     strings.TrimSpace(imageRef),
		Platform:     strings.TrimSpace(opts.Platform),
		Status:       "observed",
		MaxFindings:  maxFindings,
		FindingCount: 0,
	}
	if digest, err := img.Digest(); err == nil {
		report.ManifestDigest = digest.String()
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("file-risk: image layers: %w", err)
	}

	current := map[string]ImageFileRiskFinding{}
	for layerIndex, layer := range layers {
		layerDigest := ""
		if digest, err := layer.Digest(); err == nil {
			layerDigest = digest.String()
		}
		rc, err := layer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("file-risk: layer %d open: %w", layerIndex, err)
		}
		if err := scanFileRiskLayer(rc, layerIndex, layerDigest, maxFindings, current, report); err != nil {
			_ = rc.Close()
			return nil, err
		}
		if err := rc.Close(); err != nil {
			return nil, fmt.Errorf("file-risk: layer %d close: %w", layerIndex, err)
		}
	}

	report.Findings = make([]ImageFileRiskFinding, 0, len(current))
	for _, finding := range current {
		report.Findings = append(report.Findings, finding)
	}
	sort.Slice(report.Findings, func(i, j int) bool {
		leftRank := fileRiskSeverityRank(report.Findings[i].Severity)
		rightRank := fileRiskSeverityRank(report.Findings[j].Severity)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if report.Findings[i].Path != report.Findings[j].Path {
			return report.Findings[i].Path < report.Findings[j].Path
		}
		return strings.Join(report.Findings[i].RiskTypes, ",") < strings.Join(report.Findings[j].RiskTypes, ",")
	})
	report.FindingCount = len(report.Findings)
	return report, nil
}

func scanFileRiskLayer(rc io.Reader, layerIndex int, layerDigest string, maxFindings int, current map[string]ImageFileRiskFinding, report *ImageFileRiskReport) error {
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("file-risk: layer %d tar: %w", layerIndex, err)
		}
		cleanPath := normalizeTarPath(hdr.Name)
		if cleanPath == "" {
			continue
		}
		if applyWhiteout(cleanPath, current) {
			continue
		}
		report.EntryCount++
		finding, risky := fileRiskFindingFromHeader(hdr, cleanPath, layerIndex, layerDigest)
		if !risky {
			delete(current, cleanPath)
			continue
		}
		if _, exists := current[cleanPath]; !exists && len(current) >= maxFindings {
			report.Truncated = true
			continue
		}
		current[cleanPath] = finding
	}
}

func normalizeTarPath(name string) string {
	name = strings.TrimSpace(strings.TrimPrefix(name, "/"))
	if name == "" {
		return ""
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return ""
		}
	}
	cleaned := path.Clean("/" + name)
	if cleaned == "/" || strings.HasPrefix(cleaned, "/../") {
		return ""
	}
	return cleaned
}

func applyWhiteout(cleanPath string, current map[string]ImageFileRiskFinding) bool {
	base := path.Base(cleanPath)
	dir := path.Dir(cleanPath)
	if base == ".wh..wh..opq" {
		prefix := dir
		if prefix != "/" {
			prefix += "/"
		}
		for existing := range current {
			if existing == dir || strings.HasPrefix(existing, prefix) {
				delete(current, existing)
			}
		}
		return true
	}
	if strings.HasPrefix(base, ".wh.") {
		delete(current, path.Join(dir, strings.TrimPrefix(base, ".wh.")))
		return true
	}
	return false
}

func fileRiskFindingFromHeader(hdr *tar.Header, cleanPath string, layerIndex int, layerDigest string) (ImageFileRiskFinding, bool) {
	kind := tarHeaderKind(hdr)
	mode := hdr.Mode & 0o7777
	risks := []string{}
	switch kind {
	case "regular":
		if mode&0o4000 != 0 {
			risks = append(risks, "setuid")
		}
		if mode&0o2000 != 0 {
			risks = append(risks, "setgid")
		}
		if mode&0o0002 != 0 {
			risks = append(risks, "world-writable-file")
		}
	case "directory":
		if mode&0o2000 != 0 {
			risks = append(risks, "setgid-directory")
		}
		if mode&0o0002 != 0 {
			if mode&0o1000 != 0 {
				risks = append(risks, "world-writable-sticky-directory")
			} else {
				risks = append(risks, "world-writable-directory")
			}
		}
	case "char-device", "block-device":
		risks = append(risks, "device-node")
	case "fifo":
		risks = append(risks, "fifo")
	}
	if len(risks) == 0 {
		return ImageFileRiskFinding{}, false
	}
	severity := fileRiskSeverity(risks, hdr.Uid)
	return ImageFileRiskFinding{
		Path:        cleanPath,
		Type:        kind,
		Mode:        fmt.Sprintf("%04o", mode),
		UID:         hdr.Uid,
		GID:         hdr.Gid,
		SizeBytes:   hdr.Size,
		LayerIndex:  layerIndex,
		LayerDigest: layerDigest,
		LinkName:    strings.TrimSpace(hdr.Linkname),
		RiskTypes:   risks,
		Severity:    severity,
		Reason:      fileRiskReason(risks, severity),
	}, true
}

func tarHeaderKind(hdr *tar.Header) string {
	switch hdr.Typeflag {
	case tar.TypeReg, tar.TypeRegA:
		return "regular"
	case tar.TypeDir:
		return "directory"
	case tar.TypeSymlink:
		return "symlink"
	case tar.TypeLink:
		return "hardlink"
	case tar.TypeChar:
		return "char-device"
	case tar.TypeBlock:
		return "block-device"
	case tar.TypeFifo:
		return "fifo"
	default:
		return "other"
	}
}

func fileRiskSeverity(risks []string, uid int) string {
	for _, risk := range risks {
		if risk == "device-node" {
			return "high"
		}
		if risk == "setuid" && uid == 0 {
			return "high"
		}
	}
	for _, risk := range risks {
		switch risk {
		case "setuid", "setgid", "world-writable-file", "world-writable-directory":
			return "medium"
		}
	}
	for _, risk := range risks {
		if risk == "fifo" {
			return "low"
		}
	}
	return "info"
}

func fileRiskSeverityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func fileRiskReason(risks []string, severity string) string {
	if len(risks) == 0 {
		return ""
	}
	return fmt.Sprintf("%s filesystem risk: %s", severity, strings.Join(risks, ","))
}
