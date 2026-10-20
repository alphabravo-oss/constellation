package bundle

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"gopkg.in/yaml.v3"
)

// BuildOptions drive Build.
type BuildOptions struct {
	Out     string   // output directory (created)
	Name    string   // bundle name, e.g. constellation
	Version string   // bundle/chart version
	Images  []string // image references to include
	// FromDaemon pulls images from the local Docker daemon (a build box)
	// instead of the remote registry.
	FromDaemon bool
	// ChartDir, when set, is copied into the bundle under chart/.
	ChartDir string
	// SignKey signs the BOM; nil leaves the bundle unsigned (it will fail to
	// load) and is only useful for negative tests.
	SignKey *ecdsa.PrivateKey
	Logger  *slog.Logger
}

// Build writes the OCI layout, chart copy, bom.json and bom.sig.
func Build(ctx context.Context, opts BuildOptions) (*Manifest, error) {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	if opts.Out == "" || len(opts.Images) == 0 {
		return nil, fmt.Errorf("bundle: Out and at least one image are required")
	}
	if err := os.MkdirAll(opts.Out, 0o750); err != nil {
		return nil, err
	}
	m := &Manifest{SchemaVersion: 1, Name: opts.Name, Version: opts.Version, CreatedAt: time.Now().UTC()}
	if err := writeImages(ctx, opts, m, log); err != nil {
		return nil, err
	}
	if opts.ChartDir != "" {
		if err := copyChart(opts, m); err != nil {
			return nil, err
		}
	}
	files, err := inventory(opts.Out)
	if err != nil {
		return nil, err
	}
	m.Files = files
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(opts.Out, ManifestFile), append(raw, '\n'), 0o600); err != nil {
		return nil, err
	}
	if opts.SignKey != nil {
		if err := Sign(opts.Out, opts.SignKey); err != nil {
			return nil, err
		}
	}
	log.Info("bundle: built", slog.String("out", opts.Out), slog.Int("images", len(m.Images)), slog.Int("files", len(m.Files)), slog.Bool("signed", opts.SignKey != nil))
	return m, nil
}

// writeImages fetches every image into the OCI layout and records it in m.
func writeImages(ctx context.Context, opts BuildOptions, m *Manifest, log *slog.Logger) error {
	lp, err := layout.Write(filepath.Join(opts.Out, ImagesDir), empty())
	if err != nil {
		return fmt.Errorf("bundle: init layout: %w", err)
	}
	for _, ref := range opts.Images {
		parsed, err := name.ParseReference(ref)
		if err != nil {
			return fmt.Errorf("bundle: parse %q: %w", ref, err)
		}
		img, err := fetch(ctx, parsed, opts.FromDaemon)
		if err != nil {
			return fmt.Errorf("bundle: fetch %s: %w", ref, err)
		}
		digest, err := img.Digest()
		if err != nil {
			return err
		}
		size, _ := img.Size()
		if err := lp.AppendImage(img, layout.WithAnnotations(map[string]string{
			"org.opencontainers.image.ref.name": ref,
		})); err != nil {
			return fmt.Errorf("bundle: append %s: %w", ref, err)
		}
		m.Images = append(m.Images, Image{Ref: ref, Repository: parsed.Context().RepositoryStr(), Tag: tagOf(parsed), Digest: digest.String(), Size: size})
		log.Info("bundle: image added", slog.String("ref", ref), slog.String("digest", digest.String()))
	}
	return nil
}

func copyChart(opts BuildOptions, m *Manifest) error {
	dst := filepath.Join(opts.Out, ChartDir)
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := os.CopyFS(dst, os.DirFS(opts.ChartDir)); err != nil {
		return fmt.Errorf("bundle: copy chart: %w", err)
	}
	m.Chart = &Chart{Name: chartField(opts.ChartDir, "name"), Version: chartField(opts.ChartDir, "version"), Path: ChartDir}
	return nil
}

func fetch(ctx context.Context, ref name.Reference, fromDaemon bool) (v1.Image, error) {
	if fromDaemon {
		img, err := daemon.Image(ref, daemon.WithContext(ctx))
		if err != nil {
			return nil, err
		}
		// Docker's containerd image store reports a manifest config digest that
		// differs from the config bytes `docker save` returns, which would leave
		// the layout pointing at a blob that is never written. Re-serialising the
		// config makes the manifest, the config blob and its digest agree.
		cfg, err := img.ConfigFile()
		if err != nil {
			return nil, err
		}
		return mutate.ConfigFile(img, cfg)
	}
	return remote.Image(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
}

func tagOf(ref name.Reference) string {
	if t, ok := ref.(name.Tag); ok {
		return t.TagStr()
	}
	return ""
}

// empty is an empty image index for layout.Write.
func empty() v1.ImageIndex { return emptyIndex{} }

type emptyIndex struct{}

func (emptyIndex) MediaType() (types.MediaType, error) { return types.OCIImageIndex, nil }
func (emptyIndex) Digest() (v1.Hash, error)            { return v1.Hash{}, nil }
func (emptyIndex) Size() (int64, error)                { return 0, nil }
func (emptyIndex) IndexManifest() (*v1.IndexManifest, error) {
	return &v1.IndexManifest{SchemaVersion: 2}, nil
}
func (emptyIndex) RawManifest() ([]byte, error) {
	return []byte(`{"schemaVersion":2,"manifests":[]}`), nil
}
func (emptyIndex) Image(v1.Hash) (v1.Image, error)           { return nil, fs.ErrNotExist }
func (emptyIndex) ImageIndex(v1.Hash) (v1.ImageIndex, error) { return nil, fs.ErrNotExist }

func chartField(dir, key string) string {
	b, err := os.ReadFile(filepath.Join(dir, "Chart.yaml"))
	if err != nil {
		return ""
	}
	var c map[string]any
	if yaml.Unmarshal(b, &c) != nil {
		return ""
	}
	v, _ := c[key].(string)
	return v
}

// ImageTarball writes one image from the layout as a docker-load/ctr-import
// compatible tarball (used by the containerd loader).
func ImageTarball(lp layout.Path, digest v1.Hash, ref name.Reference, path string) error {
	img, err := lp.Image(digest)
	if err != nil {
		return err
	}
	tag, ok := ref.(name.Tag)
	if !ok {
		tag = ref.Context().Tag("bundle")
	}
	return tarball.WriteToFile(path, tag, img)
}
