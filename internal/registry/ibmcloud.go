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

// IBMCloud is the IBM Cloud Container Registry (icr.io) connector.
//
// Auth: IBM Cloud IAM. The customer supplies an API key (Config.Password); we
// exchange it for a short-lived IAM OAuth bearer token at the IAM token endpoint
// (Config.TokenURL, default https://iam.cloud.ibm.com/identity/token) using the
// urn:ibm:params:oauth:grant-type:apikey grant. Repository enumeration then hits
// the registry's proprietary /api/v1/images API with that bearer token and the
// account GUID in the Account header. This models NeuVector controller/scan/ibmcloud.go
// (aquireToken + getImages), adapted to Constellation's Connector shape.
type IBMCloud struct {
	cfg    Config
	client *http.Client
}

// ibmAPIKeyGrant is the IBM Cloud IAM grant type for exchanging an API key for a
// bearer token (matches NeuVector's grantType constant).
const ibmAPIKeyGrant = "urn:ibm:params:oauth:grant-type:apikey"

// defaultIBMTokenURL is the public IAM token-exchange endpoint used when the
// caller does not override Config.TokenURL.
const defaultIBMTokenURL = "https://iam.cloud.ibm.com/identity/token"

func NewIBMCloud(cfg Config) *IBMCloud {
	return &IBMCloud{cfg: cfg, client: cfg.httpClient(30 * time.Second)}
}

func (r *IBMCloud) Name() string { return "ibmcloud" }

// ibmImage mirrors NeuVector's ibmImage: the registry returns each image as a set
// of fully-qualified RepoTags (e.g. "us.icr.io/ns/app:1.2.3").
type ibmImage struct {
	RepoTags []string `json:"RepoTags"`
}

func (r *IBMCloud) tokenURL() string {
	if strings.TrimSpace(r.cfg.TokenURL) != "" {
		return r.cfg.TokenURL
	}
	return defaultIBMTokenURL
}

// acquireToken swaps the API key (cfg.Password) for an IAM OAuth bearer token.
func (r *IBMCloud) acquireToken(ctx context.Context) (string, error) {
	if r.cfg.Password == "" {
		return "", errors.New("ibmcloud: Password (IBM Cloud IAM API key) required")
	}
	form := url.Values{}
	form.Set("grant_type", ibmAPIKeyGrant)
	form.Set("apikey", r.cfg.Password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ibmcloud: token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ibmcloud: token exchange status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("ibmcloud: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", errors.New("ibmcloud: token exchange returned empty access_token")
	}
	return tok.AccessToken, nil
}

func (r *IBMCloud) ListImages(ctx context.Context) ([]Image, error) {
	if r.cfg.Endpoint == "" {
		return nil, errors.New("ibmcloud: Endpoint=<region>.icr.io required")
	}
	if r.cfg.Account == "" {
		return nil, errors.New("ibmcloud: Account (IBM Cloud account GUID) required")
	}
	token, err := r.acquireToken(ctx)
	if err != nil {
		return nil, err
	}

	host := stripSchemeIBM(r.cfg.Endpoint)
	endpoint := "https://" + host + "/api/v1/images"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Account", r.cfg.Account)
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ibmcloud: list images: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ibmcloud: list images status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var images []ibmImage
	if err := json.Unmarshal(body, &images); err != nil {
		return nil, fmt.Errorf("ibmcloud: decode images: %w", err)
	}

	// Collapse RepoTags into one Image per repository, collecting its tags.
	byRepo := map[string][]string{}
	order := []string{}
	for _, im := range images {
		for _, rt := range im.RepoTags {
			repo, tag := splitRepoTag(rt)
			if repo == "" {
				continue
			}
			if _, ok := byRepo[repo]; !ok {
				order = append(order, repo)
			}
			if tag != "" {
				byRepo[repo] = append(byRepo[repo], tag)
			}
		}
	}
	out := make([]Image, 0, len(order))
	for _, repo := range order {
		out = append(out, Image{Repository: repo, Tags: byRepo[repo]})
	}
	return out, nil
}

func (r *IBMCloud) ResolveDigest(ctx context.Context, ref string) (string, error) {
	// icr.io is v2-compliant; the IAM bearer token authenticates the manifest HEAD.
	token, err := r.acquireToken(ctx)
	if err != nil {
		// Fall back to an anonymous v2 lookup (public images) rather than hard-failing.
		return resolveDigestViaV2(ctx, r.client, ref, "")
	}
	return resolveDigestViaV2(ctx, r.client, ref, token)
}

// splitRepoTag splits a fully-qualified "host/ns/repo:tag" into its repository
// (host/ns/repo) and tag. A missing tag yields an empty tag string. Mirrors the
// intent of NeuVector's getRepoName but preserves the registry host so the
// scanner can pin a fully-qualified ref.
func splitRepoTag(rt string) (repo, tag string) {
	rt = strings.TrimSpace(rt)
	if rt == "" {
		return "", ""
	}
	// A ':' after the last '/' is the tag separator; a ':' before it is a port.
	if slash := strings.LastIndex(rt, "/"); slash >= 0 {
		if colon := strings.LastIndex(rt[slash:], ":"); colon > 0 {
			return rt[:slash+colon], rt[slash+colon+1:]
		}
		return rt, ""
	}
	if colon := strings.LastIndex(rt, ":"); colon > 0 {
		return rt[:colon], rt[colon+1:]
	}
	return rt, ""
}

func stripSchemeIBM(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.TrimRight(s, "/")
}
