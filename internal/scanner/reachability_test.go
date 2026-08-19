package scanner

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// sampleGovulncheckStream is a realistic govulncheck `-mode binary -format json`
// stream covering both reachability outcomes:
//   - GO-2021-0113 / CVE-2021-38561: a finding with a symbol-level trace frame
//     (Function set) => CALLED / reachable.
//   - GO-2022-1111 / CVE-2022-2222: only module/package-level findings (no
//     Function) => present but NOT called => unreachable.
const sampleGovulncheckStream = `
{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scan_mode":"binary"}}
{"osv":{"id":"GO-2021-0113","aliases":["CVE-2021-38561","GHSA-ffhg-7mh4-33c4"]}}
{"osv":{"id":"GO-2022-1111","aliases":["CVE-2022-2222"]}}
{"finding":{"osv":"GO-2021-0113","trace":[{"module":"golang.org/x/text"}]}}
{"finding":{"osv":"GO-2021-0113","trace":[{"module":"golang.org/x/text","package":"golang.org/x/text/language"}]}}
{"finding":{"osv":"GO-2021-0113","trace":[{"module":"golang.org/x/text","package":"golang.org/x/text/language","function":"Parse"}]}}
{"finding":{"osv":"GO-2022-1111","trace":[{"module":"example.com/vuln"}]}}
{"finding":{"osv":"GO-2022-1111","trace":[{"module":"example.com/vuln","package":"example.com/vuln/pkg"}]}}
`

func TestParseGovulncheckBinaryReachability(t *testing.T) {
	res := parseGovulncheckBinary([]byte(sampleGovulncheckStream))
	if res == nil {
		t.Fatal("nil result")
	}
	// Called by OSV id and by alias.
	if !res.called["GO-2021-0113"] {
		t.Error("GO-2021-0113 should be called")
	}
	if !res.called["CVE-2021-38561"] {
		t.Error("CVE alias of a called OSV should be marked called")
	}
	if !res.called["GHSA-FFHG-7MH4-33C4"] {
		t.Error("GHSA alias of a called OSV should be marked called")
	}
	// Present but not called.
	if res.called["GO-2022-1111"] {
		t.Error("GO-2022-1111 has no symbol frame; must not be called")
	}
	if !res.present["GO-2022-1111"] || !res.present["CVE-2022-2222"] {
		t.Error("GO-2022-1111 and its alias should be present")
	}
}

func goFindingFixture() []Finding {
	return []Finding{
		{
			VulnerabilityID: "CVE-2021-38561", // reachable Go finding (via OSV alias)
			Severity:        "high",
			Package: Package{
				Ecosystem: "go",
				Name:      "golang.org/x/text",
				Version:   "0.3.6",
				Locations: []PackageLocation{{RealPath: "/app/server"}},
			},
		},
		{
			VulnerabilityID: "CVE-2022-2222", // present-but-uncalled Go finding => unreachable
			Severity:        "critical",
			Package: Package{
				Ecosystem: "go",
				Name:      "example.com/vuln",
				Version:   "1.0.0",
				Locations: []PackageLocation{{RealPath: "/app/server"}},
			},
		},
		{
			VulnerabilityID: "CVE-2020-0001", // non-Go finding: must be left untouched
			Severity:        "critical",
			Package: Package{
				Ecosystem: "deb",
				Name:      "openssl",
				Version:   "1.1.1",
			},
		},
	}
}

func TestGoReachabilityAnalyzerSetsReachableAndDeprioritizes(t *testing.T) {
	findings := goFindingFixture()

	analyzer := goReachabilityAnalyzer{
		run: func(_ context.Context, binaryPath string) ([]byte, error) {
			if binaryPath != "/app/server" {
				t.Fatalf("unexpected binary path %q", binaryPath)
			}
			return []byte(sampleGovulncheckStream), nil
		},
	}

	out := analyzer.analyze(context.Background(), findings)

	byID := map[string]Finding{}
	for _, f := range out {
		byID[f.VulnerabilityID] = f
	}

	// Reachable set true on the called Go finding.
	reachable := byID["CVE-2021-38561"]
	if reachable.Reachable == nil || !*reachable.Reachable {
		t.Errorf("CVE-2021-38561 should be Reachable=true, got %v", reachable.Reachable)
	}

	// Reachable set false on the present-but-uncalled Go finding.
	unreachable := byID["CVE-2022-2222"]
	if unreachable.Reachable == nil || *unreachable.Reachable {
		t.Errorf("CVE-2022-2222 should be Reachable=false, got %v", unreachable.Reachable)
	}

	// Non-Go finding is never touched: Reachable stays nil.
	if byID["CVE-2020-0001"].Reachable != nil {
		t.Errorf("non-Go finding must keep Reachable=nil, got %v", byID["CVE-2020-0001"].Reachable)
	}

	// Deprioritization: the proven-unreachable Go finding must sort AFTER both the
	// reachable Go finding and the untouched non-Go finding, even though it is the
	// highest severity (critical). Reachability ordering overrides severity here.
	posUnreachable := indexOfFinding(out, "CVE-2022-2222")
	posReachable := indexOfFinding(out, "CVE-2021-38561")
	posOther := indexOfFinding(out, "CVE-2020-0001")
	if posUnreachable < posReachable {
		t.Errorf("unreachable finding (idx %d) must be deprioritized below reachable finding (idx %d)", posUnreachable, posReachable)
	}
	if posUnreachable < posOther {
		t.Errorf("unreachable finding (idx %d) must be deprioritized below untouched finding (idx %d)", posUnreachable, posOther)
	}
}

func TestGoReachabilityAnalyzerToleratesRunnerError(t *testing.T) {
	findings := goFindingFixture()
	analyzer := goReachabilityAnalyzer{
		run: func(_ context.Context, _ string) ([]byte, error) {
			return nil, errors.New("govulncheck: binary not in PATH")
		},
	}
	out := analyzer.analyze(context.Background(), findings)
	// A runner failure leaves reachability unknown (nil) on every finding and
	// must not drop or reorder findings destructively.
	for _, f := range out {
		if f.Reachable != nil {
			t.Errorf("finding %s should keep Reachable=nil when govulncheck fails, got %v", f.VulnerabilityID, f.Reachable)
		}
	}
	if len(out) != len(findings) {
		t.Fatalf("expected %d findings preserved, got %d", len(findings), len(out))
	}
}

func TestGoReachabilityAnalyzerNoGoFindingsIsNoop(t *testing.T) {
	findings := []Finding{
		{VulnerabilityID: "CVE-2020-0001", Package: Package{Ecosystem: "deb", Name: "openssl"}},
	}
	called := false
	analyzer := goReachabilityAnalyzer{
		run: func(_ context.Context, _ string) ([]byte, error) {
			called = true
			return nil, nil
		},
	}
	out := analyzer.analyze(context.Background(), findings)
	if called {
		t.Error("govulncheck must not run when there are no Go-binary findings")
	}
	if len(out) != 1 || out[0].Reachable != nil {
		t.Error("non-Go findings must be untouched")
	}
}

func TestGoReachabilityAnalyzerRespectsTimeoutConfig(t *testing.T) {
	// The configured per-binary timeout is applied to the runner's context.
	findings := goFindingFixture()
	analyzer := goReachabilityAnalyzer{
		timeout: 50 * time.Millisecond,
		run: func(ctx context.Context, _ string) ([]byte, error) {
			dl, ok := ctx.Deadline()
			if !ok {
				t.Error("runner context should carry a deadline")
				return []byte(sampleGovulncheckStream), nil
			}
			if remaining := time.Until(dl); remaining > time.Second {
				t.Errorf("deadline too far out: %v", remaining)
			}
			return []byte(sampleGovulncheckStream), nil
		},
	}
	_ = analyzer.analyze(context.Background(), findings)
}

// TestGoReachabilityAnalyzerUsesPathResolver verifies the image-target path mapping:
// the analyzer must run govulncheck against the resolved HOST path, not the in-image
// path Syft recorded.
func TestGoReachabilityAnalyzerUsesPathResolver(t *testing.T) {
	findings := goFindingFixture() // binaries live at in-image path /app/server
	analyzer := goReachabilityAnalyzer{
		resolvePath: func(p string) (string, bool) {
			if p != "/app/server" {
				t.Fatalf("resolver got unexpected in-image path %q", p)
			}
			return "/host/scratch/bin-0", true
		},
		run: func(_ context.Context, binaryPath string) ([]byte, error) {
			if binaryPath != "/host/scratch/bin-0" {
				t.Fatalf("govulncheck must run against the resolved host path, got %q", binaryPath)
			}
			return []byte(sampleGovulncheckStream), nil
		},
	}
	out := analyzer.analyze(context.Background(), findings)
	byID := map[string]Finding{}
	for _, f := range out {
		byID[f.VulnerabilityID] = f
	}
	if r := byID["CVE-2021-38561"].Reachable; r == nil || !*r {
		t.Errorf("reachable Go finding should be Reachable=true via resolved path, got %v", r)
	}
}

// TestGoReachabilityAnalyzerSkipsUnresolvablePaths verifies that when extraction
// fails (resolver returns ok=false), govulncheck is never invoked and reachability
// stays unknown — the feature is a no-op, not silently inert with bad paths.
func TestGoReachabilityAnalyzerSkipsUnresolvablePaths(t *testing.T) {
	findings := goFindingFixture()
	ran := false
	analyzer := goReachabilityAnalyzer{
		resolvePath: func(string) (string, bool) { return "", false },
		run: func(context.Context, string) ([]byte, error) {
			ran = true
			return []byte(sampleGovulncheckStream), nil
		},
	}
	out := analyzer.analyze(context.Background(), findings)
	if ran {
		t.Error("govulncheck must not run for binaries that cannot be resolved to a host path")
	}
	for _, f := range out {
		if f.Reachable != nil {
			t.Errorf("finding %s should keep Reachable=nil when its binary is unresolvable, got %v", f.VulnerabilityID, f.Reachable)
		}
	}
}

func TestIsImageScanTarget(t *testing.T) {
	cases := map[string]bool{
		"ghcr.io/acme/app:1.2.3":  true,
		"docker.io/library/nginx": true,
		"dir:/tmp/constellation":  false,
		"file:///tmp/x.zip":       false,
		"":                        false,
	}
	for ref, want := range cases {
		if got := isImageScanTarget(ref); got != want {
			t.Errorf("isImageScanTarget(%q) = %v, want %v", ref, got, want)
		}
	}
}

// TestExtractBinaryTargetsFromLayers verifies the layer-walking extraction logic:
// a wanted binary is written to host scratch, a later layer overrides an earlier
// one, an unrelated file is ignored, and a whiteout deletes a previously extracted
// file.
func TestExtractBinaryTargetsFromLayers(t *testing.T) {
	dir := t.TempDir()
	wantByClean := map[string]string{
		"/app/server": "/app/server",
		"/bin/tool":   "/bin/tool",
		"/app/gone":   "/app/gone",
	}
	layers := []v1.Layer{
		newTarLayer(t, map[string][]byte{
			"app/server": []byte("OLD-server-content"),
			"app/gone":   []byte("to-be-removed"),
			"etc/passwd": []byte("not-wanted"),
		}),
		newTarLayer(t, map[string][]byte{
			"app/server":   []byte("NEW-server-content"), // overrides layer 0
			"bin/tool":     []byte("tool-content"),
			"app/.wh.gone": nil, // whiteout deletes /app/gone
		}),
	}

	resolved := extractBinaryTargets(layers, wantByClean, dir)

	if host, ok := resolved["/app/server"]; !ok {
		t.Fatal("/app/server should be extracted")
	} else if b, _ := os.ReadFile(host); string(b) != "NEW-server-content" {
		t.Fatalf("/app/server content = %q, want the later-layer override", b)
	}
	if host, ok := resolved["/bin/tool"]; !ok {
		t.Fatal("/bin/tool should be extracted")
	} else if b, _ := os.ReadFile(host); string(b) != "tool-content" {
		t.Fatalf("/bin/tool content = %q", b)
	}
	if _, ok := resolved["/app/gone"]; ok {
		t.Fatal("/app/gone was whited out and must not resolve")
	}
	if _, ok := resolved["/etc/passwd"]; ok {
		t.Fatal("unrequested /etc/passwd must not be extracted")
	}
}

// newTarLayer builds an in-memory v1.Layer whose uncompressed tar contains the given
// files. A nil value writes a zero-length entry (used for whiteout markers).
func newTarLayer(t *testing.T, files map[string][]byte) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return layer
}

func indexOfFinding(findings []Finding, id string) int {
	for i, f := range findings {
		if f.VulnerabilityID == id {
			return i
		}
	}
	return -1
}
