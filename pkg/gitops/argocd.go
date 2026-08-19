// Package gitops implements GitOps drift detection.
//
// v1 scope (per spec FR-25 + Phase 3 GitOps drift detection):
//   - Argo CD applications: pull /api/v1/applications, compare declared vs in-cluster
//     state for security-sensitive resources, emit DriftFinding for divergence
//   - Flux HelmReleases: pull /api/v2beta1/HelmReleases (when the Flux source-controller
//     exposes them); same compare loop
//
// "Security-sensitive resource" set: RoleBinding, ClusterRoleBinding, NetworkPolicy,
// ValidatingWebhookConfiguration, MutatingWebhookConfiguration, Secret, PodSecurityPolicy.
// Out-of-band changes to these are the highest-signal drift the spec calls for.
package gitops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// SensitiveResourceKinds is the spec's curated list. Drift on these emits a finding.
var SensitiveResourceKinds = []string{
	"RoleBinding", "ClusterRoleBinding", "NetworkPolicy",
	"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration",
	"Secret", "PodSecurityPolicy", "ServiceAccount",
}

// IsSensitive reports whether a kind is in the sensitive set.
func IsSensitive(kind string) bool {
	for _, k := range SensitiveResourceKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Resource is the minimal shape of a K8s object we compare.
type Resource struct {
	Kind      string
	Name      string
	Namespace string
	Spec      map[string]any
}

// Hash returns a stable hash of the resource's spec, sorted by key so insertion order
// doesn't affect the digest.
func (r Resource) Hash() string {
	b, _ := json.Marshal(sortMap(r.Spec))
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// DriftFinding is one detected out-of-band change.
type DriftFinding struct {
	Source        string // "argocd" | "flux"
	Application   string
	Kind          string
	Name          string
	Namespace     string
	DeclaredHash  string
	ObservedHash  string
	DiffSummary   string
	Detected      time.Time
}

// ArgoCDClient hits an Argo CD API server.
type ArgoCDClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func NewArgoCDClient(baseURL, token string) *ArgoCDClient {
	return &ArgoCDClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// ListApplications returns all Application names visible to the bearer token.
func (a *ArgoCDClient) ListApplications(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.BaseURL+"/api/v1/applications", nil)
	if err != nil {
		return nil, err
	}
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("argocd: list apps: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("argocd: status %d", resp.StatusCode)
	}
	var doc struct {
		Items []struct {
			Metadata struct{ Name string `json:"name"` } `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Items))
	for _, it := range doc.Items {
		out = append(out, it.Metadata.Name)
	}
	return out, nil
}

// ManagedResources returns the declared and observed-live state for sensitive resources
// in the application. Argo CD's /managed-resources endpoint returns both sides of the
// diff in one call, which is exactly what we need for drift detection.
func (a *ArgoCDClient) ManagedResources(ctx context.Context, appName string) (declared, live []Resource, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/api/v1/applications/%s/managed-resources", a.BaseURL, appName), nil)
	if err != nil {
		return nil, nil, err
	}
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("argocd: managed-resources: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("argocd: managed-resources status %d", resp.StatusCode)
	}
	var doc struct {
		Items []struct {
			Kind      string `json:"kind"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			TargetState string `json:"targetState"` // declared JSON-as-string
			LiveState   string `json:"liveState"`   // observed JSON-as-string
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil, err
	}
	for _, it := range doc.Items {
		if !IsSensitive(it.Kind) {
			continue
		}
		declSpec, _ := decodeSpec(it.TargetState)
		liveSpec, _ := decodeSpec(it.LiveState)
		declared = append(declared, Resource{Kind: it.Kind, Name: it.Name, Namespace: it.Namespace, Spec: declSpec})
		live = append(live, Resource{Kind: it.Kind, Name: it.Name, Namespace: it.Namespace, Spec: liveSpec})
	}
	return declared, live, nil
}

// DetectDrift compares declared vs live and emits a DriftFinding per divergence.
func DetectDrift(source, application string, declared, live []Resource) []DriftFinding {
	byKey := map[string]Resource{}
	for _, r := range declared {
		byKey[key(r)] = r
	}
	out := []DriftFinding{}
	now := time.Now().UTC()
	for _, l := range live {
		k := key(l)
		d, ok := byKey[k]
		if !ok {
			// Live resource has no declared counterpart — pure out-of-band creation.
			out = append(out, DriftFinding{
				Source:       source,
				Application:  application,
				Kind:         l.Kind,
				Name:         l.Name,
				Namespace:    l.Namespace,
				DeclaredHash: "",
				ObservedHash: l.Hash(),
				DiffSummary:  "resource exists in cluster but is not declared in Git",
				Detected:     now,
			})
			continue
		}
		dh, lh := d.Hash(), l.Hash()
		if dh != lh {
			out = append(out, DriftFinding{
				Source:       source,
				Application:  application,
				Kind:         l.Kind,
				Name:         l.Name,
				Namespace:    l.Namespace,
				DeclaredHash: dh,
				ObservedHash: lh,
				DiffSummary:  fmt.Sprintf("declared sha=%s observed sha=%s", short(dh), short(lh)),
				Detected:     now,
			})
		}
		delete(byKey, k)
	}
	for _, d := range byKey {
		out = append(out, DriftFinding{
			Source:       source,
			Application:  application,
			Kind:         d.Kind,
			Name:         d.Name,
			Namespace:    d.Namespace,
			DeclaredHash: d.Hash(),
			ObservedHash: "",
			DiffSummary:  "declared in Git but missing from cluster",
			Detected:     now,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind+out[i].Name < out[j].Kind+out[j].Name })
	return out
}

func key(r Resource) string {
	return r.Kind + "|" + r.Namespace + "|" + r.Name
}

func decodeSpec(jsonStr string) (map[string]any, error) {
	if jsonStr == "" {
		return nil, errors.New("gitops: empty spec")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &doc); err != nil {
		return nil, err
	}
	if s, ok := doc["spec"].(map[string]any); ok {
		return s, nil
	}
	return doc, nil
}

func sortMap(m map[string]any) map[string]any {
	// json.Marshal already sorts keys, so this is a placeholder for future extensions
	// (e.g. canonicalizing slice ordering on labels). Kept as a function so callers can
	// be sure of stability semantics.
	return m
}

func short(h string) string {
	if len(h) < 12 {
		return h
	}
	return h[:12]
}
