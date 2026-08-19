package registry

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenShift is the RedHat / OpenShift internal image-registry connector.
//
// The OpenShift internal registry (image-registry.openshift-image-registry.svc,
// or an exposed route host) is Docker Registry v2-compliant. Auth is either a
// short-lived OAuth bearer token (`oc whoami -t`) supplied as Config.Token
// (AuthWithToken in NeuVector's model), or a username/password service-account
// login. Enumeration uses the v2 /_catalog endpoint. This models NeuVector
// controller/scan/openshift.go, adapted to Constellation's Connector shape:
// Constellation talks to the registry's v2 API directly rather than going
// through an in-cluster ORCH login, so it works from the scanner side-car.
type OpenShift struct {
	cfg    Config
	client *http.Client
}

func NewOpenShift(cfg Config) *OpenShift {
	client := cfg.httpClient(30 * time.Second)
	// OpenShift internal registries commonly present a self-signed/router cert;
	// honor the opt-in Insecure flag when the caller did not wire a shared client.
	if cfg.Insecure && cfg.HTTPClient == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
			// #nosec G402 -- opt-in only via Config.Insecure for internal cluster registries.
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		}
	}
	return &OpenShift{cfg: cfg, client: client}
}

func (r *OpenShift) Name() string { return "openshift" }

// authWithToken reports whether the connector authenticates with a bearer token
// (Config.Token set) rather than username/password (mirrors
// CLUSRegistryConfig.AuthWithToken).
func (r *OpenShift) authWithToken() bool { return strings.TrimSpace(r.cfg.Token) != "" }

func (r *OpenShift) setAuth(req *http.Request) error {
	if r.authWithToken() {
		req.Header.Set("Authorization", "Bearer "+r.cfg.Token)
		return nil
	}
	if r.cfg.Username == "" || r.cfg.Password == "" {
		return errors.New("openshift: Token (oc whoami -t) or Username+Password required")
	}
	req.SetBasicAuth(r.cfg.Username, r.cfg.Password)
	return nil
}

func (r *OpenShift) ListImages(ctx context.Context) ([]Image, error) {
	if r.cfg.Endpoint == "" {
		return nil, errors.New("openshift: Endpoint=<registry-route-host> required")
	}
	host := stripSchemeIBM(r.cfg.Endpoint)
	endpoint := "https://" + host + "/v2/_catalog?n=500"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if err := r.setAuth(req); err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openshift: catalog: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openshift: catalog status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var doc struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("openshift: decode catalog: %w", err)
	}
	out := make([]Image, 0, len(doc.Repositories))
	for _, repo := range doc.Repositories {
		out = append(out, Image{Repository: host + "/" + repo})
	}
	populateTagsViaV2(ctx, r.client, out, r.cfg.Token)
	return out, nil
}

func (r *OpenShift) ResolveDigest(ctx context.Context, ref string) (string, error) {
	return resolveDigestViaV2(ctx, r.client, ref, r.cfg.Token)
}
