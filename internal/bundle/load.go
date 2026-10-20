package bundle

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"gopkg.in/yaml.v3"
)

// LoadOptions drive Load.
type LoadOptions struct {
	Dir string
	// TrustKey overrides the embedded vendor key (tests, re-signed bundles).
	TrustKey *ecdsa.PublicKey
	// Registry is the cluster-local registry images are pushed to.
	Registry string
	Insecure bool
	// Fallback is consulted by the post-load resolver check (local first,
	// fallback second, fail closed).
	Fallback string
	// Containerd imports images straight into the node's containerd image
	// store (k3s: `k3s ctr -n k8s.io images import`) instead of a registry;
	// ContainerdCmd defaults to "k3s ctr".
	Containerd    bool
	ContainerdCmd []string
	// ValuesOut, when set, receives a Helm values file pinning every role
	// image to the loaded registry + digest.
	ValuesOut string
	DryRun    bool
	Logger    *slog.Logger
}

// LoadReport lists what happened per image.
type LoadReport struct {
	Manifest *Manifest
	Loaded   []LoadedImage
}

// LoadedImage is one image's destination and the resolver layer that serves it.
type LoadedImage struct {
	Source string
	Target string
	Digest string
	Layer  Layer
}

// Load verifies the bundle (signature, then digests) and only then pushes or
// imports every image, logging the destination and resolver layer per image.
func Load(ctx context.Context, opts LoadOptions) (*LoadReport, error) {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	m, err := Verify(opts.Dir, opts.TrustKey)
	if err != nil {
		log.Error("bundle: rejected", slog.String("dir", opts.Dir), slog.String("err", err.Error()))
		return nil, err
	}
	log.Info("bundle: verified", slog.String("name", m.Name), slog.String("version", m.Version), slog.Int("images", len(m.Images)))
	if !opts.Containerd && opts.Registry == "" {
		return nil, fmt.Errorf("bundle: a target registry (--registry) or --containerd is required")
	}
	lp, err := layout.FromPath(filepath.Join(opts.Dir, ImagesDir))
	if err != nil {
		return nil, fmt.Errorf("bundle: open layout: %w", err)
	}
	rep := &LoadReport{Manifest: m}
	for _, im := range m.Images {
		li, err := loadImage(ctx, lp, im, opts, log)
		if err != nil {
			return nil, err
		}
		rep.Loaded = append(rep.Loaded, li)
	}
	if opts.ValuesOut != "" {
		if err := writeValues(opts.ValuesOut, rep, opts.Registry, opts.Containerd); err != nil {
			return nil, err
		}
		log.Info("bundle: values written", slog.String("path", opts.ValuesOut))
	}
	return rep, nil
}

// loadImage pushes (or imports) one image and reports where it went.
func loadImage(ctx context.Context, lp layout.Path, im Image, opts LoadOptions, log *slog.Logger) (LoadedImage, error) {
	digest, err := v1.NewHash(im.Digest)
	if err != nil {
		return LoadedImage{}, err
	}
	img, err := lp.Image(digest)
	if err != nil {
		return LoadedImage{}, fmt.Errorf("bundle: image %s not in layout: %w", im.Ref, err)
	}
	src, err := name.ParseReference(im.Ref)
	if err != nil {
		return LoadedImage{}, err
	}
	target := src
	layer := LayerLocal
	switch {
	case opts.Containerd && !opts.DryRun:
		if err := importContainerd(ctx, lp, digest, src, opts.ContainerdCmd, log); err != nil {
			return LoadedImage{}, err
		}
	case !opts.Containerd:
		if target, err = Retarget(src, opts.Registry, opts.Insecure); err != nil {
			return LoadedImage{}, err
		}
		if !opts.DryRun {
			if err := remote.Write(target, img, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
				return LoadedImage{}, fmt.Errorf("bundle: push %s: %w", target, err)
			}
			r := &Resolver{Local: opts.Registry, Fallback: opts.Fallback, Insecure: opts.Insecure, Logger: log}
			if _, layer, err = r.Resolve(ctx, im.Ref); err != nil {
				return LoadedImage{}, err
			}
		}
	}
	log.Info("bundle: image loaded", slog.String("source", im.Ref), slog.String("target", target.String()),
		slog.String("digest", im.Digest), slog.String("layer", string(layer)), slog.Bool("dry_run", opts.DryRun))
	return LoadedImage{Source: im.Ref, Target: target.String(), Digest: im.Digest, Layer: layer}, nil
}

func importContainerd(ctx context.Context, lp layout.Path, digest v1.Hash, ref name.Reference, cmd []string, log *slog.Logger) error {
	tmp, err := os.CreateTemp("", "bundle-*.tar")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_ = tmp.Close()
	if err := ImageTarball(lp, digest, ref, tmp.Name()); err != nil {
		return fmt.Errorf("bundle: tarball %s: %w", ref, err)
	}
	if len(cmd) == 0 {
		cmd = []string{"k3s", "ctr"}
	}
	args := append(append([]string{}, cmd[1:]...), "-n", "k8s.io", "images", "import", tmp.Name())
	c := exec.CommandContext(ctx, cmd[0], args...) //nolint:gosec // G204: the command is the operator's --ctr setting; arguments are a temp path
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("bundle: %s import %s: %w: %s", strings.Join(cmd, " "), ref, err, out)
	}
	log.Debug("bundle: containerd import", slog.String("ref", ref.String()), slog.String("out", strings.TrimSpace(string(out))))
	return nil
}

// writeValues emits a Helm values fragment for the loaded bundle:
//   - registry mode: global.imageRegistry plus <role>.image {repository, tag,
//     digest} for every constellation role (digests survive remote.Write);
//   - containerd mode: image.registry/image.tag + pullPolicy Never; no digests,
//     because `ctr import` of a docker archive may re-derive manifest digests.
//
// Roles whose chart key is not an image map are mapped explicitly: postgres ->
// postgres.cloudnativepg.imageName, bootstrap -> image.tag only (bootstrap.image
// is the kubectl helper string).
func writeValues(path string, rep *LoadReport, registry string, containerd bool) error {
	values := map[string]any{}
	image := map[string]any{"pullPolicy": "IfNotPresent"}
	if containerd {
		image["pullPolicy"] = "Never"
	} else {
		values["global"] = map[string]any{"imageRegistry": registry}
	}
	var commonTag, commonRegistry string
	for _, li := range rep.Loaded {
		ri, ok := roleOf(li.Target)
		if !ok {
			continue // third-party image: referenced by digest in the chart already
		}
		if commonTag == "" {
			commonTag, commonRegistry = ri.tag, ri.prefix
		}
		if v := roleValues(ri, li.Digest, commonTag, containerd); v != nil {
			for k, val := range v {
				values[k] = val
			}
		}
	}
	if commonTag != "" {
		image["tag"] = commonTag
		if containerd {
			image["registry"] = commonRegistry
		}
	}
	values["image"] = image
	b, err := yaml.Marshal(values)
	if err != nil {
		return err
	}
	header := "# generated by constellationctl bundle load — every image resolved from the loaded bundle\n"
	return os.WriteFile(path, append([]byte(header), b...), 0o600)
}

type roleImage struct{ role, repo, tag, prefix string }

// roleOf recognises <registry>/<...>/constellation/<role>:<tag> image refs.
func roleOf(target string) (roleImage, bool) {
	ref, err := name.ParseReference(target)
	if err != nil {
		return roleImage{}, false
	}
	repo := ref.Context()
	path := repo.RepositoryStr()
	i := strings.LastIndex(path, "/")
	if i < 0 || !strings.HasSuffix(path[:i], "constellation") {
		return roleImage{}, false
	}
	ri := roleImage{role: kebabToRole(path[i+1:]), repo: repo.String(), prefix: repo.RegistryStr() + "/" + path[:i]}
	if t, ok := ref.(name.Tag); ok {
		ri.tag = t.TagStr()
	}
	return ri, true
}

// roleValues is the values fragment one role image contributes.
func roleValues(ri roleImage, digest, commonTag string, containerd bool) map[string]any {
	switch {
	case ri.role == "postgres":
		return map[string]any{"postgres": map[string]any{"cloudnativepg": map[string]any{"imageName": ri.repo + ":" + ri.tag}}}
	case ri.role == "bootstrap":
		return nil
	case containerd:
		if ri.tag == commonTag {
			return nil
		}
		return map[string]any{ri.role: map[string]any{"image": map[string]any{"repository": ri.repo, "tag": ri.tag}}}
	default:
		return map[string]any{ri.role: map[string]any{"image": map[string]any{"repository": ri.repo, "tag": ri.tag, "digest": digest}}}
	}
}

// kebabToRole maps image path names to chart value keys (runtime-agent -> runtimeAgent).
func kebabToRole(s string) string {
	parts := strings.Split(s, "-")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}
