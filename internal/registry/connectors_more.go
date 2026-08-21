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
	// cfg.Endpoint = "projects/<id>/locations/<region>/repositories/<repo>"
	if a.cfg.Endpoint == "" {
		return nil, errors.New("artifact-registry: Endpoint=projects/.../locations/.../repositories/... required")
	}
	token, err := a.cfg.gcpAccessToken(ctx, a.client)
	if err != nil {
		return nil, fmt.Errorf("artifact-registry: %w", err)
	}
	url := fmt.Sprintf("https://artifactregistry.googleapis.com/v1/%s/dockerImages?pageSize=200",
		strings.TrimPrefix(a.cfg.Endpoint, "/"))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
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
	token, err := a.cfg.gcpAccessToken(ctx, a.client)
	if err != nil {
		// Fall back to an anonymous v2 lookup (public images) rather than hard-failing.
		return resolveDigestViaV2(ctx, a.client, ref, "")
	}
	return resolveDigestViaV2(ctx, a.client, ref, token)
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
	token, err := a.cfg.acrAccessToken(ctx, a.client, a.cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("acr: %w", err)
	}
	// v2 catalog endpoint — ACR supports it natively.
	url := fmt.Sprintf("https://%s/v2/_catalog?n=500", a.cfg.Endpoint)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
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
	populateTagsViaV2(ctx, a.client, out, token)
	return out, nil
}

func (a *ACR) ResolveDigest(ctx context.Context, ref string) (string, error) {
	token, err := a.cfg.acrAccessToken(ctx, a.client, a.cfg.Endpoint)
	if err != nil {
		return resolveDigestViaV2(ctx, a.client, ref, "")
	}
	return resolveDigestViaV2(ctx, a.client, ref, token)
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
	base := strings.TrimRight(h.cfg.Endpoint, "/")
	host := stripSchemeReg(h.cfg.Endpoint)

	// 1. Enumerate projects (paginated).
	projects, err := h.harborGetPaged(ctx, base+"/api/v2.0/projects")
	if err != nil {
		return nil, err
	}

	// 2. Per project, enumerate repositories (paginated). Harbor returns the repo
	// "name" already qualified as "<project>/<repo>".
	out := []Image{}
	for _, p := range projects {
		if p.Name == "" {
			continue
		}
		reposURL := base + "/api/v2.0/projects/" + url.PathEscape(p.Name) + "/repositories"
		repos, err := h.harborGetPaged(ctx, reposURL)
		if err != nil {
			return nil, err
		}
		for _, r := range repos {
			if r.Name == "" {
				continue
			}
			out = append(out, Image{Repository: host + "/" + r.Name})
		}
	}
	populateTagsViaV2(ctx, h.client, out, "")
	return out, nil
}

// namedEntity captures the only field Harbor's project + repository list responses
// have in common that we need: the object name.
type namedEntity struct {
	Name string `json:"name"`
}

// harborGetPaged accumulates a Harbor list endpoint across pages. Harbor uses
// page/page_size query params and advertises more pages via a Link: rel="next"
// header (and X-Total-Count); we page until a short page with no next link.
func (h *Harbor) harborGetPaged(ctx context.Context, endpoint string) ([]namedEntity, error) {
	const pageSize = 100
	var acc []namedEntity
	for page := 1; ; page++ {
		u := fmt.Sprintf("%s?page=%d&page_size=%d", endpoint, page, pageSize)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.SetBasicAuth(h.cfg.Username, h.cfg.Password)
		req.Header.Set("Accept", "application/json")
		resp, err := h.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("harbor: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		link := resp.Header.Get("Link")
		status := resp.StatusCode
		resp.Body.Close()
		if status != 200 {
			return nil, fmt.Errorf("harbor: status %d", status)
		}
		var page1 []namedEntity
		if err := json.Unmarshal(body, &page1); err != nil {
			return nil, fmt.Errorf("harbor: decode list: %w", err)
		}
		acc = append(acc, page1...)
		// Stop when this page is short (or empty) and Harbor advertises no next page.
		if len(page1) == 0 || (len(page1) < pageSize && !strings.Contains(link, `rel="next"`)) {
			break
		}
	}
	return acc, nil
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
	base := strings.TrimRight(g.cfg.Endpoint, "/")

	// 1. Enumerate the token's membership projects (paginated). There is no valid
	// instance-wide registry-repositories list endpoint; discovery is per-project.
	projects, err := gitlabGetPaged[glProject](ctx, g, base+"/api/v4/projects", url.Values{"membership": {"true"}})
	if err != nil {
		return nil, err
	}

	// 2. Per project, enumerate container-registry repositories (paginated).
	out := []Image{}
	for _, p := range projects {
		endpoint := fmt.Sprintf("%s/api/v4/projects/%d/registry/repositories", base, p.ID)
		repos, err := gitlabGetPaged[glRepo](ctx, g, endpoint, nil)
		if err != nil {
			return nil, err
		}
		for _, r := range repos {
			out = append(out, Image{
				Repository: r.Location,
				Tags:       g.repoTags(ctx, base, r.ID),
				PushedAt:   r.Updated.UTC().Format(time.RFC3339),
			})
		}
	}
	return out, nil
}

type glProject struct {
	ID int `json:"id"`
}

type glRepo struct {
	ID       int       `json:"id"`
	Path     string    `json:"path"`
	Location string    `json:"location"`
	Updated  time.Time `json:"updated_at"`
}

// gitlabGetPaged fetches a GitLab list endpoint across all pages, following the
// X-Next-Page header, JSON-decoding each page into []T. extra carries endpoint-
// specific query params (e.g. membership=true).
func gitlabGetPaged[T any](ctx context.Context, g *GitLab, endpoint string, extra url.Values) ([]T, error) {
	var acc []T
	page := "1"
	for page != "" {
		q := url.Values{"per_page": {"100"}, "page": {page}}
		for k, vs := range extra {
			for _, v := range vs {
				q.Add(k, v)
			}
		}
		u := endpoint + "?" + q.Encode()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("PRIVATE-TOKEN", g.cfg.Token)
		req.Header.Set("Accept", "application/json")
		resp, err := g.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("gitlab: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		next := resp.Header.Get("X-Next-Page")
		status := resp.StatusCode
		resp.Body.Close()
		if status != 200 {
			return nil, fmt.Errorf("gitlab: status %d", status)
		}
		var pg []T
		if err := json.Unmarshal(body, &pg); err != nil {
			return nil, fmt.Errorf("gitlab: decode list: %w", err)
		}
		acc = append(acc, pg...)
		page = next
	}
	return acc, nil
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
	base := strings.TrimRight(j.cfg.Endpoint, "/")
	host := stripSchemeReg(j.cfg.Endpoint)

	// 1. Discover the Docker repositories via Artifactory's repositories API rather
	// than assuming a single repo key. Each entry's "key" is a Docker repo (local,
	// remote, or virtual per its "type"); "packageType" confirms it is Docker.
	repoBody, err := j.get(ctx, base+"/api/repositories?type=docker")
	if err != nil {
		return nil, err
	}
	var dockerRepos []struct {
		Key         string `json:"key"`
		Type        string `json:"type"`        // local | remote | virtual (mode)
		PackageType string `json:"packageType"` // "Docker"
	}
	if err := json.Unmarshal(repoBody, &dockerRepos); err != nil {
		return nil, fmt.Errorf("jfrog: decode repositories: %w", err)
	}

	// 2. For each Docker repo key, enumerate its images via the repo-scoped v2
	// catalog. Images are addressed as <host>/<repoKey>/<image>.
	out := []Image{}
	for _, dr := range dockerRepos {
		if dr.Key == "" {
			continue
		}
		catBody, err := j.get(ctx, base+"/api/docker/"+url.PathEscape(dr.Key)+"/v2/_catalog?n=500")
		if err != nil {
			// A single unreadable repo (e.g. a remote proxy) must not abort the walk.
			continue
		}
		var cat struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.Unmarshal(catBody, &cat); err != nil {
			continue
		}
		for _, r := range cat.Repositories {
			out = append(out, Image{Repository: host + "/" + dr.Key + "/" + r})
		}
	}
	populateTagsViaV2(ctx, j.client, out, j.cfg.Token)
	return out, nil
}

// get performs an authenticated Artifactory GET and returns the body, mapping non-200
// to an error. Auth is a bearer token when supplied, else basic auth with the
// configured username (falling back to "anonymous") + password.
func (j *JFrog) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if j.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+j.cfg.Token)
	} else {
		user := j.cfg.Username
		if user == "" {
			user = "anonymous"
		}
		req.SetBasicAuth(user, j.cfg.Password)
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
	return body, nil
}

func (j *JFrog) ResolveDigest(ctx context.Context, ref string) (string, error) {
	return resolveDigestViaV2(ctx, j.client, ref, j.cfg.Token)
}

// stripSchemeReg trims a leading http(s):// and any trailing slash, yielding the bare
// host(:port)[/path] used to qualify repository names.
func stripSchemeReg(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.TrimRight(s, "/")
}
