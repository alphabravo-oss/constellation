package registry

// Plain Docker Registry v2 connectors: GenericV2 (any registry that speaks the standard
// /v2/ API) and Nexus (Sonatype Nexus Repository's docker connector, which is itself a
// v2-compliant registry). Both enumerate via /v2/_catalog and delegate digest resolution
// to the shared v2 helpers, so they wire in with no bespoke auth dance — just optional HTTP
// Basic (Username/Password) or a pre-acquired bearer Token.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GenericV2 is a plain Docker Registry v2 connector for any registry that speaks the
// standard /v2/ API (the reference registry:2 image, or a private registry behind HTTP
// Basic auth). The shared v2 helpers negotiate any WWW-Authenticate challenge on
// ResolveDigest.
type GenericV2 struct {
	cfg    Config
	client *http.Client
}

func NewGenericV2(cfg Config) *GenericV2 {
	return &GenericV2{cfg: cfg, client: cfg.httpClient(30 * time.Second)}
}

func (g *GenericV2) Name() string { return "generic-v2" }

func (g *GenericV2) ListImages(ctx context.Context) ([]Image, error) {
	return listCatalogV2(ctx, g.client, "generic-v2", g.cfg)
}

func (g *GenericV2) ResolveDigest(ctx context.Context, ref string) (string, error) {
	return resolveDigestViaV2(ctx, g.client, ref, g.cfg.Token)
}

// Nexus is the Sonatype Nexus Repository docker (v2) connector. Nexus exposes each hosted
// docker repository on its own connector host:port that speaks the standard Registry v2
// API, so enumeration is the same /v2/_catalog walk as GenericV2; auth is typically HTTP
// Basic against a Nexus role with the nx-repository-view privilege.
type Nexus struct {
	cfg    Config
	client *http.Client
}

func NewNexus(cfg Config) *Nexus {
	return &Nexus{cfg: cfg, client: cfg.httpClient(30 * time.Second)}
}

func (n *Nexus) Name() string { return "nexus" }

func (n *Nexus) ListImages(ctx context.Context) ([]Image, error) {
	return listCatalogV2(ctx, n.client, "nexus", n.cfg)
}

func (n *Nexus) ResolveDigest(ctx context.Context, ref string) (string, error) {
	return resolveDigestViaV2(ctx, n.client, ref, n.cfg.Token)
}

// listCatalogV2 enumerates repositories from a Docker Registry v2 /v2/_catalog endpoint.
// It applies a bearer Token or HTTP Basic auth (Username/Password) when configured, then
// fills per-repo tags best-effort via the shared v2 tag walker. `kind` names the connector
// in error strings.
func listCatalogV2(ctx context.Context, client *http.Client, kind string, cfg Config) ([]Image, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("%s: Endpoint=<registry-host[:port]> required", kind)
	}
	host := stripSchemeReg(cfg.Endpoint)
	endpoint := "https://" + host + "/v2/_catalog?n=500"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	switch {
	case strings.TrimSpace(cfg.Token) != "":
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	case cfg.Username != "" && cfg.Password != "":
		req.SetBasicAuth(cfg.Username, cfg.Password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: catalog: %w", kind, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: catalog status %d: %s", kind, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var doc struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%s: decode catalog: %w", kind, err)
	}
	out := make([]Image, 0, len(doc.Repositories))
	for _, repo := range doc.Repositories {
		if repo == "" {
			continue
		}
		out = append(out, Image{Repository: host + "/" + repo})
	}
	populateTagsViaV2(ctx, client, out, cfg.Token)
	return out, nil
}
