package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
)

const manifestAccept = "application/vnd.oci.image.manifest.v1+json,application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.docker.distribution.manifest.list.v2+json"

type ManifestMetadata struct {
	ImageRef         string               `json:"image_ref,omitempty"`
	ManifestDigest   string               `json:"manifest_digest,omitempty"`
	IndexDigest      string               `json:"index_digest,omitempty"`
	MediaType        string               `json:"media_type,omitempty"`
	Config           *ManifestDescriptor  `json:"config,omitempty"`
	Layers           []ManifestDescriptor `json:"layers,omitempty"`
	Architectures    []string             `json:"architectures,omitempty"`
	SelectedPlatform string               `json:"selected_platform,omitempty"`
	TotalSizeBytes   int64                `json:"total_size_bytes,omitempty"`
}

type ManifestDescriptor struct {
	MediaType   string            `json:"media_type,omitempty"`
	Digest      string            `json:"digest,omitempty"`
	SizeBytes   int64             `json:"size_bytes,omitempty"`
	Platform    string            `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// resolveDigestViaV2 issues a HEAD against the registry v2 manifest endpoint and reads
// the Docker-Content-Digest response header. For registries that require auth even on
// public reads (docker.io, ghcr.io), it performs the v2 challenge dance: get a bearer
// token from the realm advertised in WWW-Authenticate, then retry the HEAD.
func ResolveDigestReference(ctx context.Context, ref string) (string, error) {
	return resolveDigestViaV2(ctx, nil, ref, "")
}

func resolveDigestViaV2(ctx context.Context, client *http.Client, ref, token string) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	host, repo, tag, err := parseRef(ref)
	if err != nil {
		return "", err
	}
	// docker.io's v2 endpoint is at registry-1.docker.io; the user-facing host is just for refs.
	v2Host := host
	if host == "docker.io" {
		v2Host = "registry-1.docker.io"
	}
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", v2Host, repo, tag)
	digest, err := headManifest(ctx, client, url, manifestAccept, token)
	if err == nil {
		return fmt.Sprintf("%s/%s@%s", host, repo, digest), nil
	}

	// 401? Try to acquire an anonymous token using the WWW-Authenticate challenge.
	var unauth *errUnauthorized
	if errors.As(err, &unauth) {
		anonToken, terr := fetchTokenFromChallenge(ctx, client, unauth.challenge)
		if terr != nil {
			return "", fmt.Errorf("registry: token grant: %w", terr)
		}
		digest, err = headManifest(ctx, client, url, manifestAccept, anonToken)
		if err == nil {
			return fmt.Sprintf("%s/%s@%s", host, repo, digest), nil
		}
	}
	return "", err
}

// InspectManifestReference fetches registry manifest metadata for a tag or digest ref.
// For manifest lists and OCI indexes, platform selects a child manifest when supplied.
func InspectManifestReference(ctx context.Context, ref, platform string) (*ManifestMetadata, error) {
	return inspectManifestViaV2(ctx, nil, ref, "", platform)
}

func inspectManifestViaV2(ctx context.Context, client *http.Client, ref, token, platform string) (*ManifestMetadata, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	host, repo, reference, err := parseManifestRef(ref)
	if err != nil {
		return nil, err
	}
	v2Host := host
	if host == "docker.io" {
		v2Host = "registry-1.docker.io"
	}
	body, digest, contentType, err := getManifestBody(ctx, client, manifestURL(v2Host, repo, reference), manifestAccept, token)
	if err != nil {
		var unauth *errUnauthorized
		if errors.As(err, &unauth) {
			anonToken, terr := fetchTokenFromChallenge(ctx, client, unauth.challenge)
			if terr != nil {
				return nil, fmt.Errorf("registry: token grant: %w", terr)
			}
			body, digest, contentType, err = getManifestBody(ctx, client, manifestURL(v2Host, repo, reference), manifestAccept, anonToken)
			if err != nil {
				return nil, err
			}
			token = anonToken
		} else {
			return nil, err
		}
	}
	if digest == "" && strings.HasPrefix(reference, "sha256:") {
		digest = reference
	}
	return manifestMetadataFromBody(ctx, client, v2Host, host, repo, ref, body, digest, contentType, token, platform)
}

func manifestMetadataFromBody(ctx context.Context, client *http.Client, v2Host, refHost, repo, imageRef string, body []byte, digest, contentType, token, platform string) (*ManifestMetadata, error) {
	var header struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
	}
	if err := json.Unmarshal(body, &header); err != nil {
		return nil, fmt.Errorf("registry: decode manifest: %w", err)
	}
	mediaType := firstNonEmpty(header.MediaType, strings.Split(contentType, ";")[0])
	if isManifestList(mediaType) {
		var index struct {
			Manifests []struct {
				MediaType   string            `json:"mediaType"`
				Digest      string            `json:"digest"`
				Size        int64             `json:"size"`
				Annotations map[string]string `json:"annotations"`
				Platform    struct {
					Architecture string `json:"architecture"`
					OS           string `json:"os"`
					Variant      string `json:"variant"`
				} `json:"platform"`
			} `json:"manifests"`
		}
		if err := json.Unmarshal(body, &index); err != nil {
			return nil, fmt.Errorf("registry: decode manifest index: %w", err)
		}
		architectures := make([]string, 0, len(index.Manifests))
		var selectedDigest string
		var selectedPlatform string
		for _, manifest := range index.Manifests {
			plat := platformString(manifest.Platform.OS, manifest.Platform.Architecture, manifest.Platform.Variant)
			if plat != "" {
				architectures = append(architectures, plat)
			}
			if selectedDigest == "" && platformMatches(platform, manifest.Platform.OS, manifest.Platform.Architecture, manifest.Platform.Variant) {
				selectedDigest = manifest.Digest
				selectedPlatform = plat
			}
		}
		if selectedDigest == "" && strings.TrimSpace(platform) == "" && len(index.Manifests) == 1 {
			selectedDigest = index.Manifests[0].Digest
			selectedPlatform = platformString(index.Manifests[0].Platform.OS, index.Manifests[0].Platform.Architecture, index.Manifests[0].Platform.Variant)
		}
		if selectedDigest == "" {
			return nil, fmt.Errorf("registry: platform required for multi-platform manifest %s (available: %s)", digest, strings.Join(architectures, ","))
		}
		childBody, childDigest, childContentType, err := getManifestBody(ctx, client, manifestURL(v2Host, repo, selectedDigest), manifestAccept, token)
		if err != nil {
			return nil, err
		}
		if childDigest == "" {
			childDigest = selectedDigest
		}
		meta, err := manifestMetadataFromBody(ctx, client, v2Host, refHost, repo, refHost+"/"+repo+"@"+selectedDigest, childBody, childDigest, childContentType, token, "")
		if err != nil {
			return nil, err
		}
		meta.ImageRef = imageRef
		meta.IndexDigest = digest
		meta.Architectures = architectures
		meta.SelectedPlatform = selectedPlatform
		return meta, nil
	}

	var manifest struct {
		Config struct {
			MediaType   string            `json:"mediaType"`
			Digest      string            `json:"digest"`
			Size        int64             `json:"size"`
			Annotations map[string]string `json:"annotations"`
		} `json:"config"`
		Layers []struct {
			MediaType   string            `json:"mediaType"`
			Digest      string            `json:"digest"`
			Size        int64             `json:"size"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("registry: decode image manifest: %w", err)
	}
	layers := make([]ManifestDescriptor, 0, len(manifest.Layers))
	var total int64
	for _, layer := range manifest.Layers {
		layers = append(layers, ManifestDescriptor{
			MediaType:   layer.MediaType,
			Digest:      layer.Digest,
			SizeBytes:   layer.Size,
			Annotations: layer.Annotations,
		})
		total += layer.Size
	}
	config := &ManifestDescriptor{
		MediaType:   manifest.Config.MediaType,
		Digest:      manifest.Config.Digest,
		SizeBytes:   manifest.Config.Size,
		Annotations: manifest.Config.Annotations,
	}
	return &ManifestMetadata{
		ImageRef:       imageRef,
		ManifestDigest: digest,
		MediaType:      mediaType,
		Config:         config,
		Layers:         layers,
		TotalSizeBytes: total,
	}, nil
}

func getManifestBody(ctx context.Context, client *http.Client, url, accept, token string) ([]byte, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", "", err
	}
	req.Header.Set("Accept", accept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", "", fmt.Errorf("registry: GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return nil, "", "", &errUnauthorized{challenge: resp.Header.Get("Www-Authenticate")}
	}
	if resp.StatusCode >= 400 {
		return nil, "", "", fmt.Errorf("registry: GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, "", "", err
	}
	return body, resp.Header.Get("Docker-Content-Digest"), resp.Header.Get("Content-Type"), nil
}

// errUnauthorized carries the WWW-Authenticate challenge so the caller can fetch a token.
type errUnauthorized struct{ challenge string }

func (e *errUnauthorized) Error() string { return "registry: 401 " + e.challenge }

func headManifest(ctx context.Context, client *http.Client, url, accept, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", accept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("registry: HEAD %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return "", &errUnauthorized{challenge: resp.Header.Get("Www-Authenticate")}
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("registry: HEAD %s: status %d", url, resp.StatusCode)
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		// Some registries (Docker Hub) require GET (not HEAD) to set the header. Retry GET.
		return getManifestDigest(ctx, client, url, accept, token)
	}
	return digest, nil
}

// getManifestDigest fetches the manifest with GET to coax registries that don't set the
// Docker-Content-Digest header on HEAD.
func getManifestDigest(ctx context.Context, client *http.Client, url, accept, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", accept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return "", &errUnauthorized{challenge: resp.Header.Get("Www-Authenticate")}
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("registry: GET %s: status %d", url, resp.StatusCode)
	}
	if digest := resp.Header.Get("Docker-Content-Digest"); digest != "" {
		return digest, nil
	}
	_, _ = io.ReadAll(resp.Body)
	return "", errors.New("registry: response missing Docker-Content-Digest even on GET")
}

func manifestURL(v2Host, repo, reference string) string {
	return fmt.Sprintf("https://%s/v2/%s/manifests/%s", v2Host, repo, reference)
}

func isManifestList(mediaType string) bool {
	return mediaType == "application/vnd.oci.image.index.v1+json" ||
		mediaType == "application/vnd.docker.distribution.manifest.list.v2+json"
}

func platformString(osName, arch, variant string) string {
	if osName == "" || arch == "" {
		return ""
	}
	out := osName + "/" + arch
	if variant != "" {
		out += "/" + variant
	}
	return out
}

func platformMatches(want, osName, arch, variant string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	got := platformString(osName, arch, variant)
	if got == want {
		return true
	}
	return variant == "" && osName+"/"+arch == want
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

// fetchTokenFromChallenge parses a "Bearer realm=…,service=…,scope=…" header and asks the
// realm for an anonymous token.
func fetchTokenFromChallenge(ctx context.Context, client *http.Client, challenge string) (string, error) {
	if !strings.HasPrefix(challenge, "Bearer ") {
		return "", fmt.Errorf("registry: not a Bearer challenge: %q", challenge)
	}
	params := parseChallengeParams(strings.TrimPrefix(challenge, "Bearer "))
	realm := params["realm"]
	if realm == "" {
		return "", errors.New("registry: challenge missing realm")
	}
	url := realm + "?"
	if s := params["service"]; s != "" {
		url += "service=" + s + "&"
	}
	if s := params["scope"]; s != "" {
		url += "scope=" + s + "&"
	}
	url = strings.TrimSuffix(url, "&")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("registry: token endpoint status %d", resp.StatusCode)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", err
	}
	if tok.Token != "" {
		return tok.Token, nil
	}
	return tok.AccessToken, nil
}

func parseChallengeParams(s string) map[string]string {
	out := map[string]string{}
	for _, part := range splitChallenge(s) {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		out[key] = val
	}
	return out
}

func splitChallenge(s string) []string {
	out := []string{}
	depth := 0
	last := 0
	for i, r := range s {
		switch r {
		case '"':
			if depth == 0 {
				depth = 1
			} else {
				depth = 0
			}
		case ',':
			if depth == 0 {
				out = append(out, s[last:i])
				last = i + 1
			}
		}
	}
	out = append(out, s[last:])
	return out
}

// parseRef splits "host/repo:tag" into its parts.
func parseRef(ref string) (host, repo, tag string, err error) {
	if strings.Contains(ref, "@") {
		return "", "", "", errors.New("registry: ref already pinned by digest")
	}
	slash := strings.Index(ref, "/")
	if slash < 0 {
		return "", "", "", errors.New("registry: ref must include a registry host")
	}
	host = ref[:slash]
	rest := ref[slash+1:]
	colon := strings.LastIndex(rest, ":")
	if colon < 0 {
		return host, rest, "latest", nil
	}
	return host, rest[:colon], rest[colon+1:], nil
}

// populateTagsViaV2 fills Tags for each image that has none by enumerating the
// registry v2 /v2/<repo>/tags/list endpoint. It is best-effort: a repo whose tags
// cannot be listed is left untouched, so the caller's downstream tag policy simply
// falls back to its default selection rather than aborting the whole registry walk.
// Without this, connectors that only return repositories (empty Tags) cause the
// server to scan repo:latest only, making scan_policy tag_selection="all" a no-op.
func populateTagsViaV2(ctx context.Context, client *http.Client, images []Image, token string) {
	for i := range images {
		if len(images[i].Tags) > 0 {
			continue
		}
		if tags, err := listTagsViaV2(ctx, client, images[i].Repository, token); err == nil && len(tags) > 0 {
			images[i].Tags = tags
		}
	}
}

// listTagsViaV2 enumerates a repository's tags via the registry v2 tags/list
// endpoint, following Link-header pagination and performing the WWW-Authenticate
// challenge dance (anonymous pull token) when the registry requires auth for tag
// listing. repoRef is a host-qualified repository such as "ghcr.io/owner/app"
// (no tag), mirroring Image.Repository.
func listTagsViaV2(ctx context.Context, client *http.Client, repoRef, token string) ([]string, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	host, repo := splitHostRepo(repoRef)
	if host == "" || repo == "" {
		return nil, fmt.Errorf("registry: tags/list requires a host-qualified repository, got %q", repoRef)
	}
	v2Host := host
	if host == "docker.io" {
		v2Host = "registry-1.docker.io"
	}
	next := fmt.Sprintf("https://%s/v2/%s/tags/list?n=100", v2Host, repo)
	var out []string
	triedAnon := false
	for next != "" {
		tags, link, err := getTagsPage(ctx, client, next, token)
		if err != nil {
			var unauth *errUnauthorized
			if errors.As(err, &unauth) && !triedAnon {
				triedAnon = true
				anonToken, terr := fetchTokenFromChallenge(ctx, client, unauth.challenge)
				if terr != nil {
					return out, fmt.Errorf("registry: token grant: %w", terr)
				}
				token = anonToken
				continue // retry the same page now that we hold a token
			}
			return out, err
		}
		out = append(out, tags...)
		next = link
	}
	return out, nil
}

// getTagsPage fetches one page of a v2 tags/list response and returns the tags
// plus the resolved URL of the next page (empty when there is none).
func getTagsPage(ctx context.Context, client *http.Client, url, token string) ([]string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("registry: GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return nil, "", &errUnauthorized{challenge: resp.Header.Get("Www-Authenticate")}
	}
	if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("registry: GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, "", err
	}
	var doc struct {
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("registry: decode tags: %w", err)
	}
	return doc.Tags, nextLinkURL(resp.Header.Get("Link"), url), nil
}

// nextLinkURL extracts the rel="next" target from a v2 Link header and resolves
// it against the current page URL. Returns "" when there is no next page.
func nextLinkURL(link, current string) string {
	link = strings.TrimSpace(link)
	if link == "" || !strings.Contains(link, `rel="next"`) {
		return ""
	}
	start := strings.Index(link, "<")
	end := strings.Index(link, ">")
	if start < 0 || end < 0 || end < start {
		return ""
	}
	target := strings.TrimSpace(link[start+1 : end])
	base, err := neturl.Parse(current)
	if err != nil {
		return ""
	}
	ref, err := neturl.Parse(target)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

// splitHostRepo splits a host-qualified repository ("ghcr.io/owner/app") into its
// registry host and repository path. Returns empty strings when no host is present.
func splitHostRepo(ref string) (host, repo string) {
	ref = strings.TrimSpace(ref)
	slash := strings.Index(ref, "/")
	if slash < 0 {
		return "", ""
	}
	return ref[:slash], ref[slash+1:]
}

func parseManifestRef(ref string) (host, repo, reference string, err error) {
	slash := strings.Index(ref, "/")
	if slash < 0 {
		return "", "", "", errors.New("registry: ref must include a registry host")
	}
	host = ref[:slash]
	rest := ref[slash+1:]
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		reference = strings.TrimSpace(rest[at+1:])
		if reference == "" {
			return "", "", "", errors.New("registry: digest reference is empty")
		}
		return host, rest[:at], reference, nil
	}
	colon := strings.LastIndex(rest, ":")
	if colon < 0 {
		return host, rest, "latest", nil
	}
	return host, rest[:colon], rest[colon+1:], nil
}
