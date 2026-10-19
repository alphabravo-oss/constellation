package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
		return nil, errors.New("registry: invalid request endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+g.cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, responseFailure("ghcr list", "request failed", 0, err)
	}
	body, readErr := readRegistryPage(resp, 4<<20)
	if readErr != nil {
		return nil, responseFailure("ghcr list", "response read or close failed", resp.StatusCode, readErr)
	}
	if resp.StatusCode != 200 {
		return nil, responseFailure("ghcr list", "response rejected", resp.StatusCode, nil)
	}
	var pkgs []struct {
		Name      string    `json:"name"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	if err := json.Unmarshal(body, &pkgs); err != nil {
		return nil, responseFailure("ghcr list", "invalid list response", resp.StatusCode, err)
	}
	out := make([]Image, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, Image{
			Repository: fmt.Sprintf("ghcr.io/%s/%s", owner, p.Name),
			PushedAt:   p.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}
	for i := range out {
		token, err := g.pullToken(ctx, out[i].Repository)
		if err != nil {
			return nil, err
		}
		tags, err := listTagsViaV2(ctx, g.client, out[i].Repository, token)
		if err != nil {
			return nil, fmt.Errorf("ghcr: enumerate tags: %w", err)
		}
		// An untagged package must not become an invented :latest scan target.
		out[i].Tags = tags
	}
	filtered := out[:0]
	for _, im := range out {
		if len(im.Tags) > 0 {
			filtered = append(filtered, im)
		}
	}
	return filtered, nil
}

func (g *GHCR) ResolveDigest(ctx context.Context, ref string) (string, error) {
	host, repo, _, err := parseRef(ref)
	if err != nil || host != "ghcr.io" {
		return "", errors.New("ghcr: expected a ghcr.io image reference")
	}
	token, err := g.pullToken(ctx, host+"/"+repo)
	if err != nil {
		return "", err
	}
	return resolveDigestViaV2(ctx, g.client, ref, token)
}

// GitHub API credentials are not registry bearer tokens. Exchange them at the
// fixed GHCR issuer, never at a realm supplied by an arbitrary registry.
func (g *GHCR) pullToken(ctx context.Context, repository string) (string, error) {
	if !strings.HasPrefix(repository, "ghcr.io/") {
		return "", errors.New("ghcr: invalid repository host")
	}
	query := url.Values{"service": {"ghcr.io"}, "scope": {"repository:" + strings.TrimPrefix(repository, "ghcr.io/") + ":pull"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ghcr.io/token?"+query.Encode(), nil)
	if err != nil {
		return "", errors.New("ghcr: invalid token request")
	}
	if g.cfg.Token != "" {
		req.SetBasicAuth(g.cfg.Username, g.cfg.Token)
	}
	client := *g.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return "", responseFailure("ghcr token", "request failed", 0, err)
	}
	body, err := readRegistryPage(resp, tokenResponseLimit)
	if err != nil {
		return "", responseFailure("ghcr token", "response read failed", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", responseFailure("ghcr token", "response rejected", resp.StatusCode, nil)
	}
	var result struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", responseFailure("ghcr token", "invalid response", resp.StatusCode, err)
	}
	if result.Token == "" {
		result.Token = result.AccessToken
	}
	if result.Token == "" {
		return "", errors.New("ghcr: empty registry token")
	}
	return result.Token, nil
}
