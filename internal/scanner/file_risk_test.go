package scanner

import (
	"archive/tar"
	"bytes"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestFileRisksFromImageDetectsRiskyFilesystemMetadata(t *testing.T) {
	img := testImageWithLayers(t, []testTarEntry{
		{Name: "usr/bin/root-suid", Mode: 0o4755, Typeflag: tar.TypeReg},
		{Name: "usr/bin/group-sgid", Mode: 0o2755, Typeflag: tar.TypeReg},
		{Name: "var/lib/open", Mode: 0o777, Typeflag: tar.TypeDir},
		{Name: "dev/fuse", Mode: 0o600, Typeflag: tar.TypeChar},
		{Name: "tmp", Mode: 0o1777, Typeflag: tar.TypeDir},
	})

	report, err := fileRisksFromImage("example.test/app@sha256:deadbeef", img, FileRiskOptions{MaxFindings: 20})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "observed" || report.FindingCount != 5 || report.EntryCount != 5 {
		t.Fatalf("report = %+v", report)
	}
	byPath := fileRiskFindingsByPath(report.Findings)
	for _, path := range []string{"/usr/bin/root-suid", "/usr/bin/group-sgid", "/var/lib/open", "/dev/fuse", "/tmp"} {
		if _, ok := byPath[path]; !ok {
			t.Fatalf("missing %s in %+v", path, report.Findings)
		}
	}
	if byPath["/usr/bin/root-suid"].Severity != "high" || byPath["/dev/fuse"].RiskTypes[0] != "device-node" {
		t.Fatalf("unexpected risk classification: %+v", byPath)
	}
}

func TestFileRisksFromImageAppliesWhiteoutsAndOverwrites(t *testing.T) {
	img := testImageWithLayers(t,
		[]testTarEntry{
			{Name: "usr/bin/deleted", Mode: 0o4755, Typeflag: tar.TypeReg},
			{Name: "usr/bin/overwritten", Mode: 0o4755, Typeflag: tar.TypeReg},
			{Name: "opt/opaque/kept-out", Mode: 0o4755, Typeflag: tar.TypeReg},
		},
		[]testTarEntry{
			{Name: "usr/bin/.wh.deleted", Mode: 0o0000, Typeflag: tar.TypeReg},
			{Name: "usr/bin/overwritten", Mode: 0o755, Typeflag: tar.TypeReg},
			{Name: "opt/opaque/.wh..wh..opq", Mode: 0o0000, Typeflag: tar.TypeReg},
		},
	)

	report, err := fileRisksFromImage("example.test/app@sha256:deadbeef", img, FileRiskOptions{MaxFindings: 20})
	if err != nil {
		t.Fatal(err)
	}
	if report.FindingCount != 0 {
		t.Fatalf("findings survived whiteout/overwrite: %+v", report.Findings)
	}
}

func TestFileRisksFromImageCapsFindings(t *testing.T) {
	img := testImageWithLayers(t, []testTarEntry{
		{Name: "bin/a", Mode: 0o4755, Typeflag: tar.TypeReg},
		{Name: "bin/b", Mode: 0o4755, Typeflag: tar.TypeReg},
	})

	report, err := fileRisksFromImage("example.test/app@sha256:deadbeef", img, FileRiskOptions{MaxFindings: 1})
	if err != nil {
		t.Fatal(err)
	}
	if report.FindingCount != 1 || !report.Truncated {
		t.Fatalf("report = %+v", report)
	}
}

type testTarEntry struct {
	Name     string
	Mode     int64
	Typeflag byte
	UID      int
	GID      int
	Size     int64
}

func testImageWithLayers(t *testing.T, layerEntries ...[]testTarEntry) v1.Image {
	t.Helper()
	layers := make([]mutate.Addendum, 0, len(layerEntries))
	for _, entries := range layerEntries {
		layer := static.NewLayer(testTarBytes(t, entries), types.OCILayer)
		layers = append(layers, mutate.Addendum{Layer: layer})
	}
	img, err := mutate.Append(empty.Image, layers...)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func testTarBytes(t *testing.T, entries []testTarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range entries {
		if entry.Typeflag == 0 {
			entry.Typeflag = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     entry.Name,
			Mode:     entry.Mode,
			Uid:      entry.UID,
			Gid:      entry.GID,
			Size:     entry.Size,
			Typeflag: entry.Typeflag,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if entry.Size > 0 {
			if _, err := tw.Write(bytes.Repeat([]byte("x"), int(entry.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func fileRiskFindingsByPath(findings []ImageFileRiskFinding) map[string]ImageFileRiskFinding {
	out := map[string]ImageFileRiskFinding{}
	for _, finding := range findings {
		out[finding.Path] = finding
	}
	return out
}
