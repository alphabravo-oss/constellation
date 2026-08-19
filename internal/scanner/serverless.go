package scanner

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Serverless artifact scanning lets the scanner inspect a Lambda / function deployment
// package (a zip of the function code + bundled dependencies) WITHOUT a deployed
// runtime-agent. The flow is: fetch the artifact (https/http URL, file:// URL, or a
// local path), unzip it into a scratch directory, and hand the directory to Syft as a
// `dir:` reference. This mirrors how AWS distributes Lambda code (a flat zip) and how
// other serverless runtimes ship a function bundle.
//
// Only the standard library is used (archive/zip + net/http + os); no new dependency.

const (
	// defaultServerlessMaxArtifactBytes caps the compressed download size.
	defaultServerlessMaxArtifactBytes int64 = 512 << 20 // 512 MiB
	// defaultServerlessMaxUnpackedBytes caps the total uncompressed size to defuse
	// zip bombs (a small archive that expands to gigabytes).
	defaultServerlessMaxUnpackedBytes int64 = 2 << 30 // 2 GiB
	// defaultServerlessMaxFiles caps the number of entries extracted.
	defaultServerlessMaxFiles = 200000
)

// ServerlessArtifact describes where a serverless function bundle lives.
type ServerlessArtifact struct {
	// Source is the artifact location: an https/http URL, a file:// URL, or a local
	// filesystem path to a .zip.
	Source string

	// HTTPClient, when set, is used for https/http downloads. Defaults to a 5-minute
	// client. Tests inject a client pointed at an httptest server.
	HTTPClient *http.Client

	// MaxArtifactBytes / MaxUnpackedBytes / MaxFiles override the safety caps when > 0.
	MaxArtifactBytes int64
	MaxUnpackedBytes int64
	MaxFiles         int

	// AllowPrivateTargets bypasses the SSRF guard that otherwise rejects http(s)
	// sources resolving to loopback/link-local/private space. Only trusted callers
	// (tests, in-cluster mirrors) should set it.
	AllowPrivateTargets bool
}

// UnpackedArtifact is the result of fetching + extracting a serverless bundle.
type UnpackedArtifact struct {
	// Dir is the directory the artifact was extracted into. Pass `dir:`+Dir to the
	// aggregator/Syft.
	Dir string

	// Files is the number of regular files extracted.
	Files int

	// Bytes is the total uncompressed size extracted.
	Bytes int64

	cleanup func()
}

// Ref returns the Syft directory reference for the unpacked artifact.
func (u *UnpackedArtifact) Ref() string { return "dir:" + u.Dir }

// Close removes the scratch directory. Always call it (defer) once scanning is done.
func (u *UnpackedArtifact) Close() {
	if u != nil && u.cleanup != nil {
		u.cleanup()
	}
}

// FetchServerlessArtifact downloads (when remote) and unzips the artifact into a fresh
// temp directory. The caller MUST call UnpackedArtifact.Close() to remove it.
func FetchServerlessArtifact(ctx context.Context, art ServerlessArtifact) (*UnpackedArtifact, error) {
	source := strings.TrimSpace(art.Source)
	if source == "" {
		return nil, errors.New("serverless: empty artifact source")
	}

	localZip, isTemp, err := materializeArtifact(ctx, art, source)
	if err != nil {
		return nil, err
	}
	if isTemp {
		defer os.Remove(localZip)
	}

	dir, err := os.MkdirTemp("", "constellation-serverless-*")
	if err != nil {
		return nil, fmt.Errorf("serverless: scratch dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	files, total, err := unzipInto(localZip, dir, art.maxUnpackedBytes(), art.maxFiles())
	if err != nil {
		cleanup()
		return nil, err
	}
	return &UnpackedArtifact{Dir: dir, Files: files, Bytes: total, cleanup: cleanup}, nil
}

// materializeArtifact resolves the source to a local zip path. For local/file:// paths
// the original file is used in place (isTemp=false); for http(s) it is downloaded to a
// temp file (isTemp=true).
func materializeArtifact(ctx context.Context, art ServerlessArtifact, source string) (path string, isTemp bool, err error) {
	switch {
	case strings.HasPrefix(source, "http://"), strings.HasPrefix(source, "https://"):
		return downloadArtifact(ctx, art, source)
	case strings.HasPrefix(source, "file://"):
		p := strings.TrimPrefix(source, "file://")
		if p == "" {
			return "", false, errors.New("serverless: empty file:// path")
		}
		return p, false, nil
	case strings.Contains(source, "://"):
		// s3://, gs://, etc. are not fetched directly here — the control plane is
		// expected to presign them into an https URL before enqueueing the job.
		scheme, _, _ := strings.Cut(source, "://")
		return "", false, fmt.Errorf("serverless: unsupported artifact scheme %q (presign to https first)", scheme)
	default:
		// Treat as a local filesystem path.
		return source, false, nil
	}
}

func downloadArtifact(ctx context.Context, art ServerlessArtifact, source string) (string, bool, error) {
	client := art.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	if !art.AllowPrivateTargets {
		if err := guardServerlessTarget(source); err != nil {
			return "", false, err
		}
		// Copy the client so we can re-validate every redirect hop without mutating
		// a shared/injected client; otherwise a 3xx to 169.254.169.254 would bypass
		// the pre-flight IP check (SSRF).
		c := *client
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("serverless: too many redirects")
			}
			return guardServerlessTarget(req.URL.String())
		}
		client = &c
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return "", false, fmt.Errorf("serverless: request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("serverless: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("serverless: download status %d", resp.StatusCode)
	}

	f, err := os.CreateTemp("", "constellation-serverless-*.zip")
	if err != nil {
		return "", false, fmt.Errorf("serverless: temp file: %w", err)
	}
	limit := art.maxArtifactBytes()
	// limit+1 so we can detect an over-cap body rather than silently truncating.
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(f.Name())
		return "", false, fmt.Errorf("serverless: read body: %w", err)
	}
	if closeErr != nil {
		_ = os.Remove(f.Name())
		return "", false, fmt.Errorf("serverless: close temp: %w", closeErr)
	}
	if n > limit {
		_ = os.Remove(f.Name())
		return "", false, fmt.Errorf("serverless: artifact exceeds %d bytes", limit)
	}
	return f.Name(), true, nil
}

// guardServerlessTarget blocks server-side request forgery: it resolves the URL
// host and rejects any target landing on loopback, link-local (which includes the
// 169.254.169.254 cloud metadata endpoint), or private / unspecified address space.
// ponytail: coarse deny-by-range with a single AllowPrivateTargets escape hatch;
// upgrade path is an explicit CIDR allowlist on ServerlessArtifact plus a custom
// DialContext to also close the DNS-rebinding TOCTOU window.
func guardServerlessTarget(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("serverless: parse url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("serverless: empty artifact host")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("serverless: resolve %q: %w", host, err)
	}
	for _, ip := range ips {
		if isDisallowedTargetIP(ip) {
			return fmt.Errorf("serverless: refusing artifact host %q resolving to disallowed address %s", host, ip)
		}
	}
	return nil
}

// isDisallowedTargetIP reports whether ip is in a range the scanner must never
// reach when fetching an attacker-influenced artifact URL.
func isDisallowedTargetIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() ||
		ip.IsUnspecified()
}

// unzipInto extracts zipPath into dir with zip-slip, total-size, and file-count guards.
func unzipInto(zipPath, dir string, maxBytes int64, maxFiles int) (int, int64, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return 0, 0, fmt.Errorf("serverless: open zip: %w", err)
	}
	defer zr.Close()

	cleanDir := filepath.Clean(dir)
	var (
		files int
		total int64
	)
	for _, zf := range zr.File {
		// Zip-slip guard: reject entries that escape the extraction root.
		target := filepath.Join(cleanDir, zf.Name)
		if target != cleanDir && !strings.HasPrefix(target, cleanDir+string(os.PathSeparator)) {
			return files, total, fmt.Errorf("serverless: illegal path in zip: %q", zf.Name)
		}
		info := zf.FileInfo()
		if info.IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return files, total, fmt.Errorf("serverless: mkdir: %w", err)
			}
			continue
		}
		// Skip symlinks and other non-regular entries — they have no SBOM value and
		// could point outside the tree.
		if !info.Mode().IsRegular() {
			continue
		}
		if files >= maxFiles {
			return files, total, fmt.Errorf("serverless: archive exceeds %d files", maxFiles)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return files, total, fmt.Errorf("serverless: mkdir parent: %w", err)
		}
		written, err := extractZipFile(zf, target, maxBytes-total)
		total += written
		if err != nil {
			return files, total, err
		}
		files++
	}
	return files, total, nil
}

func extractZipFile(zf *zip.File, target string, remaining int64) (int64, error) {
	if remaining <= 0 {
		return 0, fmt.Errorf("serverless: unpacked size exceeds cap")
	}
	rc, err := zf.Open()
	if err != nil {
		return 0, fmt.Errorf("serverless: open entry %q: %w", zf.Name, err)
	}
	defer rc.Close()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, fmt.Errorf("serverless: create %q: %w", target, err)
	}
	// remaining+1 lets us detect a single entry that blows the remaining budget.
	n, err := io.Copy(out, io.LimitReader(rc, remaining+1))
	closeErr := out.Close()
	if err != nil {
		return n, fmt.Errorf("serverless: write %q: %w", target, err)
	}
	if closeErr != nil {
		return n, fmt.Errorf("serverless: close %q: %w", target, closeErr)
	}
	if n > remaining {
		return n, fmt.Errorf("serverless: unpacked size exceeds cap")
	}
	return n, nil
}

func (a ServerlessArtifact) maxArtifactBytes() int64 {
	if a.MaxArtifactBytes > 0 {
		return a.MaxArtifactBytes
	}
	return defaultServerlessMaxArtifactBytes
}

func (a ServerlessArtifact) maxUnpackedBytes() int64 {
	if a.MaxUnpackedBytes > 0 {
		return a.MaxUnpackedBytes
	}
	return defaultServerlessMaxUnpackedBytes
}

func (a ServerlessArtifact) maxFiles() int {
	if a.MaxFiles > 0 {
		return a.MaxFiles
	}
	return defaultServerlessMaxFiles
}
