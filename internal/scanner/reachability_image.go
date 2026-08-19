package scanner

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Image-target binary extraction for Go reachability.
//
// govulncheck binary mode needs the actual executable on the scanner host. For an
// image scan, Syft records each Go binary's location as a path INSIDE the image
// (e.g. "/app/server"), which never exists on the host — so without extraction the
// reachability pass errors on every invocation and silently produces nothing.
//
// extractImageBinaries pulls the image once (config + layer blobs, like
// file_risk.go and layers.go already do) and writes the requested binary paths
// from the flattened root filesystem to a scratch directory, returning a resolver
// that maps each in-image path to its on-host copy. Extraction is best-effort:
// anything it cannot pull/extract simply resolves to (",", false), leaving that
// finding's reachability unknown rather than feeding govulncheck a bad path.

const (
	// reachabilityMaxBinaryBytes caps a single extracted binary (large Go binaries
	// exist, but a multi-hundred-MB executable is pathological for this opt-in pass).
	reachabilityMaxBinaryBytes int64 = 512 << 20 // 512 MiB
	// reachabilityMaxTotalBytes caps total bytes written across all extracted binaries.
	reachabilityMaxTotalBytes int64 = 1 << 30 // 1 GiB
)

// isImageScanTarget reports whether ref is an image reference (vs. a host-resolvable
// directory/file source). Serverless scans use a "dir:" ref; everything else the
// aggregator's Scan path handles is an image pulled from a registry.
func isImageScanTarget(ref string) bool {
	r := strings.TrimSpace(ref)
	for _, prefix := range []string{"dir:", "file:"} {
		if strings.HasPrefix(r, prefix) {
			return false
		}
	}
	return r != ""
}

// goBinaryInImagePaths collects the distinct in-image binary paths referenced by
// Go-ecosystem findings — the set extractImageBinaries needs to pull.
func goBinaryInImagePaths(findings []Finding) []string {
	seen := map[string]struct{}{}
	var out []string
	for i := range findings {
		if !isGoFinding(findings[i]) {
			continue
		}
		for _, p := range findingBinaryPaths(findings[i]) {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// extractImageBinaries pulls ref and extracts wantPaths from its flattened
// filesystem to a scratch dir. It returns a resolver (in-image path -> host path)
// and a cleanup func that removes the scratch dir. The resolver and cleanup are
// always non-nil; on any failure the resolver simply maps nothing.
func extractImageBinaries(ctx context.Context, ref string, opts ScanOptions, wantPaths []string) (func(string) (string, bool), func()) {
	deny := func(string) (string, bool) { return "", false }
	noopCleanup := func() {}
	if len(wantPaths) == 0 {
		return deny, noopCleanup
	}

	// Map normalized (clean) path -> original requested path so we can answer the
	// resolver in terms of whatever findingBinaryPaths handed us.
	wantByClean := map[string]string{}
	for _, p := range wantPaths {
		if c := normalizeTarPath(p); c != "" {
			wantByClean[c] = p
		}
	}
	if len(wantByClean) == 0 {
		return deny, noopCleanup
	}

	img, err := pullImageForExtraction(ctx, ref, opts)
	if err != nil {
		return deny, noopCleanup
	}
	layers, err := img.Layers()
	if err != nil {
		return deny, noopCleanup
	}

	dir, err := os.MkdirTemp("", "constellation-reach-*")
	if err != nil {
		return deny, noopCleanup
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	// resolvedByClean: clean in-image path -> host scratch path.
	resolvedByClean := extractBinaryTargets(layers, wantByClean, dir)
	if len(resolvedByClean) == 0 {
		cleanup()
		return deny, noopCleanup
	}

	resolve := func(p string) (string, bool) {
		if host, ok := resolvedByClean[p]; ok {
			return host, true
		}
		if host, ok := resolvedByClean[normalizeTarPath(p)]; ok {
			return host, true
		}
		return "", false
	}
	return resolve, cleanup
}

// extractBinaryTargets walks layers in build order and extracts each wanted clean
// path to dir, honoring whiteouts and later-layer overrides. It returns the set of
// clean paths it successfully wrote, mapped to their host location. Errors reading a
// layer are non-fatal: extraction continues with whatever was already pulled.
func extractBinaryTargets(layers []v1.Layer, wantByClean map[string]string, dir string) map[string]string {
	resolved := map[string]string{}
	var total int64
	fileSeq := 0
	for _, layer := range layers {
		rc, err := layer.Uncompressed()
		if err != nil {
			continue
		}
		extractLayerBinaryTargets(rc, wantByClean, dir, resolved, &total, &fileSeq)
		_ = rc.Close()
		if total >= reachabilityMaxTotalBytes {
			break
		}
	}
	return resolved
}

func extractLayerBinaryTargets(rc io.Reader, wantByClean map[string]string, dir string, resolved map[string]string, total *int64, fileSeq *int) {
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return // EOF or a corrupt tail: stop this layer, keep what we have.
		}
		clean := normalizeTarPath(hdr.Name)
		if clean == "" {
			continue
		}
		base := path.Base(clean)
		parent := path.Dir(clean)

		// Whiteouts: a later layer can delete a path extracted from a lower layer.
		if strings.HasPrefix(base, ".wh.") {
			if base == ".wh..wh..opq" {
				removeResolvedUnder(resolved, parent)
				continue
			}
			target := path.Join(parent, strings.TrimPrefix(base, ".wh."))
			if host, ok := resolved[target]; ok {
				_ = os.Remove(host)
				delete(resolved, target)
			}
			continue
		}

		if _, want := wantByClean[clean]; !want {
			continue
		}
		// Only real regular files are usable executables; skip symlinks/dirs/devices.
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		if hdr.Size > reachabilityMaxBinaryBytes || *total+hdr.Size > reachabilityMaxTotalBytes {
			continue
		}

		host := filepath.Join(dir, fmt.Sprintf("bin-%d", *fileSeq))
		*fileSeq++
		written, ok := writeExtractedFile(tr, host)
		if !ok {
			continue
		}
		*total += written
		// Later layer wins: drop the previous copy.
		if prev, exists := resolved[clean]; exists && prev != host {
			_ = os.Remove(prev)
		}
		resolved[clean] = host
	}
}

func writeExtractedFile(r io.Reader, host string) (int64, bool) {
	f, err := os.OpenFile(host, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, false
	}
	n, err := io.Copy(f, io.LimitReader(r, reachabilityMaxBinaryBytes+1))
	closeErr := f.Close()
	if err != nil || closeErr != nil || n > reachabilityMaxBinaryBytes {
		_ = os.Remove(host)
		return 0, false
	}
	return n, true
}

func removeResolvedUnder(resolved map[string]string, dirPath string) {
	prefix := dirPath
	if prefix != "/" {
		prefix += "/"
	}
	for clean, host := range resolved {
		if clean == dirPath || strings.HasPrefix(clean, prefix) {
			_ = os.Remove(host)
			delete(resolved, clean)
		}
	}
}

// pullImageForExtraction resolves ref to a v1.Image, mirroring the registry-pull
// setup used by file_risk.go / layers.go (keychain auth, platform, insecure).
func pullImageForExtraction(ctx context.Context, ref string, opts ScanOptions) (v1.Image, error) {
	parseOpts := []name.Option{}
	if opts.Insecure {
		parseOpts = append(parseOpts, name.Insecure)
	}
	parsed, err := name.ParseReference(ref, parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("reachability: parse image ref: %w", err)
	}
	remoteOpts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithUserAgent("constellation-scanner"),
	}
	if strings.TrimSpace(opts.Platform) != "" {
		platform, err := v1.ParsePlatform(opts.Platform)
		if err != nil {
			return nil, fmt.Errorf("reachability: parse platform: %w", err)
		}
		remoteOpts = append(remoteOpts, remote.WithPlatform(*platform))
	}
	img, err := remote.Image(parsed, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("reachability: pull image: %w", err)
	}
	return img, nil
}
