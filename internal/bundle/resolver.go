package bundle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Resolver is the layered registry resolver (guide ch.09): the cluster-local
// registry first, then the configured fallback, then fail closed. An empty
// fallback means "fail closed after the local layer".
type Resolver struct {
	Local    string // host[:port] of the cluster-local registry
	Fallback string // host[:port] of the upstream mirror; empty = none
	Insecure bool   // plain HTTP registries (cluster-local)
	Logger   *slog.Logger
	// head overrides the manifest probe in tests.
	head func(ctx context.Context, ref name.Reference) error
}

// ErrFailClosed is returned when no layer serves the image.
var ErrFailClosed = errors.New("bundle: image not found in local or fallback registry (fail closed)")

// Layer names the resolver layer that answered.
type Layer string

const (
	LayerLocal    Layer = "local"
	LayerFallback Layer = "fallback"
)

// Resolve rewrites ref's registry to the first layer that serves it and logs
// the layer. The repository path and tag/digest are preserved.
func (r *Resolver) Resolve(ctx context.Context, ref string) (name.Reference, Layer, error) {
	src, err := name.ParseReference(ref)
	if err != nil {
		return nil, "", fmt.Errorf("bundle: parse %q: %w", ref, err)
	}
	log := r.Logger
	if log == nil {
		log = slog.Default()
	}
	probe := r.head
	if probe == nil {
		probe = r.remoteHead
	}
	for _, layer := range []struct {
		name Layer
		host string
	}{{LayerLocal, r.Local}, {LayerFallback, r.Fallback}} {
		if layer.host == "" {
			continue
		}
		target, err := Retarget(src, layer.host, r.Insecure)
		if err != nil {
			return nil, "", err
		}
		if err := probe(ctx, target); err != nil {
			log.Debug("resolver: layer miss", slog.String("layer", string(layer.name)), slog.String("ref", target.String()), slog.String("err", err.Error()))
			continue
		}
		log.Info("resolver: image resolved", slog.String("layer", string(layer.name)), slog.String("ref", target.String()), slog.String("source", ref))
		return target, layer.name, nil
	}
	log.Error("resolver: fail closed", slog.String("ref", ref), slog.String("local", r.Local), slog.String("fallback", r.Fallback))
	return nil, "", fmt.Errorf("%w: %s", ErrFailClosed, ref)
}

func (r *Resolver) remoteHead(ctx context.Context, ref name.Reference) error {
	_, err := remote.Head(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	return err
}

// Retarget moves ref to another registry host, keeping repository and
// tag/digest. Docker Hub's implicit library/ prefix is made explicit so the
// path round-trips.
func Retarget(ref name.Reference, host string, insecure bool) (name.Reference, error) {
	repoPath := ref.Context().RepositoryStr()
	opts := []name.Option{}
	if insecure {
		opts = append(opts, name.Insecure)
	}
	id := ref.Identifier()
	var full string
	if strings.HasPrefix(id, "sha256:") {
		full = fmt.Sprintf("%s/%s@%s", host, repoPath, id)
	} else {
		full = fmt.Sprintf("%s/%s:%s", host, repoPath, id)
	}
	return name.ParseReference(full, opts...)
}
