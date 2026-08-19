package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DockerHub is the docker.io connector. Public reads use the registry v2 API directly;
// private reads use the Docker Hub catalog endpoint (registry.hub.docker.com) with token
// auth.
type DockerHub struct {
	cfg    Config
	client *http.Client
}

func NewDockerHub(cfg Config) *DockerHub {
	return &DockerHub{cfg: cfg, client: cfg.httpClient(30 * time.Second)}
}

func (d *DockerHub) Name() string { return "docker-hub" }

func (d *DockerHub) ListImages(ctx context.Context) ([]Image, error) {
	if d.cfg.Username == "" {
		return nil, errors.New("docker-hub: Username required to list personal repositories")
	}

	u := fmt.Sprintf("https://hub.docker.com/v2/repositories/%s/?page_size=100",
		url.PathEscape(d.cfg.Username))
	out := []Image{}
	for u != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return out, err
		}
		if d.cfg.Token != "" {
			req.Header.Set("Authorization", "Bearer "+d.cfg.Token)
		} else if d.cfg.Password != "" {
			req.SetBasicAuth(d.cfg.Username, d.cfg.Password)
		}
		resp, err := d.client.Do(req)
		if err != nil {
			return out, fmt.Errorf("docker-hub: list: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			return out, fmt.Errorf("docker-hub: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var page struct {
			Next    string `json:"next"`
			Results []struct {
				Namespace   string    `json:"namespace"`
				Name        string    `json:"name"`
				LastUpdated time.Time `json:"last_updated"`
			} `json:"results"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return out, fmt.Errorf("docker-hub: decode: %w", err)
		}
		for _, r := range page.Results {
			out = append(out, Image{
				Repository: fmt.Sprintf("docker.io/%s/%s", r.Namespace, r.Name),
				PushedAt:   r.LastUpdated.UTC().Format(time.RFC3339),
			})
		}
		u = page.Next
	}
	// Docker Hub lists repos via hub.docker.com but tags live on the registry v2 API
	// (registry-1.docker.io); the anonymous pull token from the challenge dance covers
	// public repos, matching ResolveDigest which also passes an empty token.
	populateTagsViaV2(ctx, d.client, out, "")
	return out, nil
}

func (d *DockerHub) ResolveDigest(ctx context.Context, ref string) (string, error) {
	return resolveDigestViaV2(ctx, d.client, ref, "")
}
