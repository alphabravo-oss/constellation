package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GHCR is the ghcr.io connector. Public reads work without auth; private reads use a
// GitHub PAT with read:packages scope.
type GHCR struct {
	cfg    Config
	client *http.Client
}

func NewGHCR(cfg Config) *GHCR {
	return &GHCR{cfg: cfg, client: cfg.httpClient(30 * time.Second)}
}

func (g *GHCR) Name() string { return "ghcr" }

// ListImages uses the GitHub Packages REST API. The "container" package type covers GHCR.
func (g *GHCR) ListImages(ctx context.Context) ([]Image, error) {
	if g.cfg.Token == "" {
		return nil, errors.New("ghcr: GitHub PAT required (read:packages scope)")
	}
	owner := g.cfg.Username
	if owner == "" {
		return nil, errors.New("ghcr: Username (GitHub owner/org) required")
	}

	url := fmt.Sprintf("https://api.github.com/users/%s/packages?package_type=container&per_page=100", owner)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ghcr: list: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ghcr: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var pkgs []struct {
		Name      string    `json:"name"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	if err := json.Unmarshal(body, &pkgs); err != nil {
		return nil, fmt.Errorf("ghcr: decode: %w", err)
	}
	out := make([]Image, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, Image{
			Repository: fmt.Sprintf("ghcr.io/%s/%s", owner, p.Name),
			PushedAt:   p.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}
	populateTagsViaV2(ctx, g.client, out, g.cfg.Token)
	return out, nil
}

func (g *GHCR) ResolveDigest(ctx context.Context, ref string) (string, error) {
	return resolveDigestViaV2(ctx, g.client, ref, g.cfg.Token)
}
