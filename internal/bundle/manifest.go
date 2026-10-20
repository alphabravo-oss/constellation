// Package bundle builds, verifies and loads air-gap deployment bundles (guide
// ch.09): every image the chart references in an OCI image layout, the chart
// itself, and a bill of materials signed with the vendor key. The loader
// verifies the BOM signature before it touches any payload (unsigned or
// tampered bundles are rejected), then pushes images into the cluster-local
// registry or imports them into containerd, logging the resolver layer used.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Manifest is the bill of materials (bom.json).
type Manifest struct {
	SchemaVersion int       `json:"schema_version"`
	Name          string    `json:"name"`
	Version       string    `json:"version"`
	CreatedAt     time.Time `json:"created_at"`
	Chart         *Chart    `json:"chart,omitempty"`
	Images        []Image   `json:"images"`
	Files         []File    `json:"files"`
}

// Chart records the packaged chart.
type Chart struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

// Image is one OCI image in the layout.
type Image struct {
	// Ref is the source reference the chart knows (registry/repo:tag).
	Ref string `json:"ref"`
	// Repository/Tag split out so loaders can retarget the registry.
	Repository string `json:"repository"`
	Tag        string `json:"tag,omitempty"`
	// Digest is the manifest digest (sha256:...) — the pin the chart values use.
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

// File is a payload file with its digest; everything under the bundle except
// bom.json and bom.sig is listed.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

const (
	ManifestFile  = "bom.json"
	SignatureFile = "bom.sig"
	ImagesDir     = "images"
	ChartDir      = "chart"
)

// hashFile returns hex sha256 and size.
func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// inventory walks dir and lists every regular file except the BOM pair.
func inventory(dir string) ([]File, error) {
	var files []File
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		rel = filepath.ToSlash(rel)
		if rel == ManifestFile || rel == SignatureFile {
			return nil
		}
		sum, size, err := hashFile(path)
		if err != nil {
			return err
		}
		files = append(files, File{Path: rel, SHA256: sum, Size: size})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func readManifest(dir string) (*Manifest, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: read %s: %w", ManifestFile, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, fmt.Errorf("bundle: parse %s: %w", ManifestFile, err)
	}
	return &m, raw, nil
}
