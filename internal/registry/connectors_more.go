// Additional registry connectors (GCR/Artifact Registry, ACR, Quay, Harbor, GitLab, JFrog).
//
// All six are v2-compliant; the differences are auth shape. ListImages uses each
// registry's catalog API where they expose one; ResolveDigest delegates to the shared
// v2 helper which already handles the WWW-Authenticate challenge dance.
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

// =====================================================================================
// Google Artifact Registry / GCR
// =====================================================================================

// ArtifactRegistry hits the GCP Artifact Registry REST API. Auth: OAuth2 access token
// from a service-account key. Older GCR (us.gcr.io etc.) supports the same v2 endpoint.
type ArtifactRegistry struct {
	cfg    Config
	client *http.Client
}

func NewArtifactRegistry(cfg Config) *ArtifactRegistry {
	return &ArtifactRegistry{cfg: cfg, client: cfg.httpClient(30 * time.Second)}
}

func (a *ArtifactRegistry) Name() string { return "artifact-registry" }

func (a *ArtifactRegistry) ListImages(ctx context.Context) ([]Image, error) {
	if a.cfg.Token == "" {
		return nil, errors.New("artifact-registry: OAuth access token required")
	}
	// cfg.Endpoint = "projects/<id>/locations/<region>/repositories/<repo>"
	if a.cfg.Endpoint == "" {
		return nil, errors.New("artifact-registry: Endpoint=projects/.../locations/.../repositories/... required")
	}
	url := fmt.Sprintf("https://artifactregistry.googleapis.com/v1/%s/dockerImages?pageSize=200",
		strings.TrimPrefix(a.cfg.Endpoint, "/"))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("artifact-registry: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("artifact-registry: status %d: %s", resp.StatusCode, body)
	}
	var doc struct {
		DockerImages []struct {
			Name       string    `json:"name"`
			URI        string    `json:"uri"`
			UpdateTime time.Time `json:"updateTime"`
			Tags       []string  `json:"tags"`
		} `json:"dockerImages"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make([]Image, 0, len(doc.DockerImages))
	for _, d := range doc.DockerImages {
		out = append(out, Image{
			Repository: d.URI,
			Tags:       d.Tags,
			PushedAt:   d.UpdateTime.UTC().Format(time.RFC3339),
		})
	}
	return out, nil
}

func (a *ArtifactRegistry) ResolveDigest(ctx context.Context, ref string) (string, error) {
	return resolveDigestViaV2(ctx, a.client, ref, a.cfg.Token)
}

// =====================================================================================
// Azure Container Registry
// =====================================================================================

// ACR uses Azure AD bearer tokens (audience = registry hostname). At v1 the customer
// hands us a pre-acquired token (`az acr login --expose-token --output tsv`).
type ACR struct {
	cfg    Config
	client *http.Client
}

func NewACR(cfg Config) *ACR { return &ACR{cfg: cfg, client: cfg.httpClient(30 * time.Second)} }

func (a *ACR) Name() string { return "acr" }

func (a *ACR) ListImages(ctx context.Context) ([]Image, error) {
	if a.cfg.Endpoint == "" {
		return nil, errors.New("acr: Endpoint=<registry>.azurecr.io required")
	}
	if a.cfg.Token == "" {
		return nil, errors.New("acr: Token required (Azure AD)")
	}
	// v2 catalog endpoint — ACR supports it natively.
	url := fmt.Sprintf("https://%s/v2/_catalog?n=500", a.cfg.Endpoint)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("acr: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("acr: status %d", resp.StatusCode)
	}
	var doc struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make([]Image, 0, len(doc.Repositories))
	for _, r := range doc.Repositories {
		out = append(out, Image{Repository: a.cfg.Endpoint + "/" + r})
	}
	populateTagsViaV2(ctx, a.client, out, a.cfg.Token)
	return out, nil
}

func (a *ACR) ResolveDigest(ctx context.Context, ref string) (string, error) {
	return resolveDigestViaV2(ctx, a.client, ref, a.cfg.Token)
}

// =====================================================================================
// Quay
// =====================================================================================

type Quay struct {
	cfg    Config
	client *http.Client
}

func NewQuay(cfg Config) *Quay { return &Quay{cfg: cfg, client: cfg.httpClient(30 * time.Second)} }

func (q *Quay) Name() string { return "quay" }

func (q *Quay) ListImages(ctx context.Context) ([]Image, error) {
	if q.cfg.Token == "" {
		return nil, errors.New("quay: OAuth Bearer token required")
	}
	host := q.cfg.Endpoint
	if host == "" {
		host = "quay.io"
	}
	// Quay's /api/v1/repository scoped to the calling user/org.
	endpoint := fmt.Sprintf("https://%s/api/v1/repository?public=false&starred=false", host)
	if q.cfg.Username != "" {
		endpoint += "&namespace=" + url.QueryEscape(q.cfg.Username)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+q.cfg.Token)
	resp, err := q.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("quay: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("quay: status %d", resp.StatusCode)
	}
	var doc struct {
		Repositories []struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"repositories"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make([]Image, 0, len(doc.Repositories))
	for _, r := range doc.Repositories {
		out = append(out, Image{Repository: host + "/" + r.Namespace + "/" + r.Name})
	}
	populateTagsViaV2(ctx, q.client, out, q.cfg.Token)
	return out, nil
}

func (q *Quay) ResolveDigest(ctx context.Context, ref string) (string, error) {
	return resolveDigestViaV2(ctx, q.client, ref, q.cfg.Token)
}

// =====================================================================================
// Harbor
// =====================================================================================

type Harbor struct {
	cfg    Config
	client *http.Client
}

func NewHarbor(cfg Config) *Harbor {
	return &Harbor{cfg: cfg, client: cfg.httpClient(30 * time.Second)}
}

func (h *Harbor) Name() string { return "harbor" }

func (h *Harbor) ListImages(ctx context.Context) ([]Image, error) {
	if h.cfg.Endpoint == "" {
		return nil, errors.New("harbor: Endpoint=https://harbor.your-org required")
	}
	if h.cfg.Username == "" || h.cfg.Password == "" {
		return nil, errors.New("harbor: Username + Password required")
	}
	url := strings.TrimRight(h.cfg.Endpoint, "/") + "/api/v2.0/projects/_default/repositories?page_size=100"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.SetBasicAuth(h.cfg.Username, h.cfg.Password)
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("harbor: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("harbor: status %d", resp.StatusCode)
	}
	var repos []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &repos); err != nil {
		return nil, err
	}
	host := strings.TrimPrefix(strings.TrimPrefix(h.cfg.Endpoint, "https://"), "http://")
	out := make([]Image, 0, len(repos))
	for _, r := range repos {
		out = append(out, Image{Repository: host + "/" + r.Name})
	}
	populateTagsViaV2(ctx, h.client, out, "")
	return out, nil
}

func (h *Harbor) ResolveDigest(ctx context.Context, ref string) (string, error) {
	return resolveDigestViaV2(ctx, h.client, ref, "")
}

// =====================================================================================
// GitLab Container Registry
// =====================================================================================

type GitLab struct {
	cfg    Config
	client *http.Client
}

func NewGitLab(cfg Config) *GitLab {
	return &GitLab{cfg: cfg, client: cfg.httpClient(30 * time.Second)}
}

func (g *GitLab) Name() string { return "gitlab" }

func (g *GitLab) ListImages(ctx context.Context) ([]Image, error) {
	if g.cfg.Endpoint == "" {
		g.cfg.Endpoint = "https://gitlab.com"
	}
	if g.cfg.Token == "" {
		return nil, errors.New("gitlab: PAT (read_registry scope) required")
	}
	url := strings.TrimRight(g.cfg.Endpoint, "/") + "/api/v4/registry/repositories?per_page=100"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("PRIVATE-TOKEN", g.cfg.Token)
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gitlab: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("gitlab: status %d", resp.StatusCode)
	}
	var repos []struct {
		ID       int       `json:"id"`
		Path     string    `json:"path"`
		Location string    `json:"location"`
		Updated  time.Time `json:"updated_at"`
	}
	if err := json.Unmarshal(body, &repos); err != nil {
		return nil, err
	}
	base := strings.TrimRight(g.cfg.Endpoint, "/")
	out := make([]Image, 0, len(repos))
	for _, r := range repos {
		out = append(out, Image{
			Repository: r.Location,
			Tags:       g.repoTags(ctx, base, r.ID),
			PushedAt:   r.Updated.UTC().Format(time.RFC3339),
		})
	}
	return out, nil
}

// repoTags enumerates a GitLab container-registry repository's tags via
// /api/v4/registry/repositories/:id/tags. Best-effort: on error it returns no
// tags so the caller's tag policy falls back to its default selection.
func (g *GitLab) repoTags(ctx context.Context, base string, id int) []string {
	url := fmt.Sprintf("%s/api/v4/registry/repositories/%d/tags?per_page=100", base, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("PRIVATE-TOKEN", g.cfg.Token)
	resp, err := g.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil
	}
	var tags []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &tags); err != nil {
		return nil
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if t.Name != "" {
			out = append(out, t.Name)
		}
	}
	return out
}

func (g *GitLab) ResolveDigest(ctx context.Context, ref string) (string, error) {
	return resolveDigestViaV2(ctx, g.client, ref, g.cfg.Token)
}

// =====================================================================================
// JFrog Artifactory
// =====================================================================================

type JFrog struct {
	cfg    Config
	client *http.Client
}

func NewJFrog(cfg Config) *JFrog { return &JFrog{cfg: cfg, client: cfg.httpClient(30 * time.Second)} }

func (j *JFrog) Name() string { return "jfrog" }

func (j *JFrog) ListImages(ctx context.Context) ([]Image, error) {
	if j.cfg.Endpoint == "" {
		return nil, errors.New("jfrog: Endpoint=https://your.jfrog.io/artifactory required")
	}
	if j.cfg.Token == "" && j.cfg.Password == "" {
		return nil, errors.New("jfrog: Token or Password required")
	}
	// JFrog's /api/docker/<repo>/v2/_catalog endpoint
	url := strings.TrimRight(j.cfg.Endpoint, "/") + "/api/docker/" + strings.TrimPrefix(j.cfg.Username, "/") + "/v2/_catalog?n=500"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if j.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+j.cfg.Token)
	} else {
		req.SetBasicAuth("anonymous", j.cfg.Password)
	}
	resp, err := j.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jfrog: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("jfrog: status %d", resp.StatusCode)
	}
	var doc struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	host := strings.TrimPrefix(strings.TrimPrefix(j.cfg.Endpoint, "https://"), "http://")
	out := make([]Image, 0, len(doc.Repositories))
	for _, r := range doc.Repositories {
		out = append(out, Image{Repository: host + "/" + r})
	}
	populateTagsViaV2(ctx, j.client, out, j.cfg.Token)
	return out, nil
}

func (j *JFrog) ResolveDigest(ctx context.Context, ref string) (string, error) {
	return resolveDigestViaV2(ctx, j.client, ref, j.cfg.Token)
}
