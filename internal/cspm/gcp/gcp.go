// Package gcp is the GCP cloud-CSPM connector.
//
// v1 scope (matches the AWS pattern):
//   - IAM over-privilege: project bindings granting roles/owner or roles/editor to
//     non-service-account principals
//   - Public GCS buckets: IAM policy granting "roles/storage.objectViewer" to allUsers
//     or allAuthenticatedUsers
//
// Auth: OAuth2 access token (typically from a service-account key the customer
// configures via `gcloud iam service-accounts keys create`). v1 keeps things thin —
// the Cloud Resource Manager + Cloud Storage REST APIs are well-documented and we just
// hit them directly with net/http. Future cuts can swap in cloud.google.com/go SDKs if
// we need streaming or batched calls.
package gcp

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

// Finding mirrors the cspm/aws.Finding shape so the ingest pipeline doesn't need cloud-
// specific handlers.
type Finding struct {
	ExternalID  string
	Title       string
	Description string
	Severity    string
	Resource    string
	Evidence    map[string]any
	Detected    time.Time
}

// HTTPClient is the subset of *http.Client we use; lets tests fake responses.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Connector reads GCP project IAM + GCS bucket policies and emits Findings.
type Connector struct {
	HTTP      HTTPClient
	Token     string // OAuth2 access token
	ProjectID string
}

// New constructs a Connector. Caller supplies the OAuth2 access token.
func New(token, projectID string) *Connector {
	return &Connector{
		HTTP:      &http.Client{Timeout: 30 * time.Second},
		Token:     token,
		ProjectID: projectID,
	}
}

// Scan returns the union of IAM + Storage findings.
func (c *Connector) Scan(ctx context.Context) ([]Finding, error) {
	if c.Token == "" {
		return nil, errors.New("gcp: OAuth access token required")
	}
	if c.ProjectID == "" {
		return nil, errors.New("gcp: ProjectID required")
	}
	iamF, ierr := c.ScanIAM(ctx)
	storageF, serr := c.ScanStorage(ctx)
	out := append(iamF, storageF...)
	// Surface a failure whenever ANY sub-scan fails so a partial scan (e.g. IAM
	// denied, storage ok) is not reported as a clean, complete scan.
	if err := errors.Join(ierr, serr); err != nil {
		return out, fmt.Errorf("gcp: scan incomplete: %w", err)
	}
	return out, nil
}

// ScanIAM checks project-level IAM bindings.
func (c *Connector) ScanIAM(ctx context.Context) ([]Finding, error) {
	body := strings.NewReader(`{"options":{"requestedPolicyVersion":3}}`)
	urlStr := fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s:getIamPolicy",
		url.PathEscape(c.ProjectID))
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, body)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcp: getIamPolicy: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("gcp: getIamPolicy status %d: %s", resp.StatusCode, raw)
	}
	var policy struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		return nil, fmt.Errorf("gcp: decode IAM policy: %w", err)
	}

	now := time.Now().UTC()
	out := []Finding{}
	for _, b := range policy.Bindings {
		if !isOverPrivilegedRole(b.Role) {
			continue
		}
		for _, member := range b.Members {
			if !isHumanPrincipal(member) {
				continue
			}
			out = append(out, Finding{
				ExternalID:  fmt.Sprintf("gcp-iam-overprivilege-%s-%s", c.ProjectID, sanitize(member)),
				Title:       fmt.Sprintf("GCP project %q grants %s to %s", c.ProjectID, b.Role, member),
				Description: "Project-level IAM grants a high-privilege role to a non-service-account principal.",
				Severity:    "high",
				Resource:    fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", c.ProjectID),
				Detected:    now,
				Evidence: map[string]any{
					"role":    b.Role,
					"member":  member,
					"project": c.ProjectID,
				},
			})
		}
	}
	return out, nil
}

// ScanStorage checks every GCS bucket in the project for public-access bindings.
func (c *Connector) ScanStorage(ctx context.Context) ([]Finding, error) {
	listURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s",
		url.QueryEscape(c.ProjectID))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcp: list buckets: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("gcp: list buckets status %d", resp.StatusCode)
	}
	var list struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	out := []Finding{}
	for _, b := range list.Items {
		policyURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/iam",
			url.PathEscape(b.Name))
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, policyURL, nil)
		req.Header.Set("Authorization", "Bearer "+c.Token)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		var pol struct {
			Bindings []struct {
				Role    string   `json:"role"`
				Members []string `json:"members"`
			} `json:"bindings"`
		}
		if err := json.Unmarshal(raw, &pol); err != nil {
			continue
		}
		for _, binding := range pol.Bindings {
			for _, member := range binding.Members {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					out = append(out, Finding{
						ExternalID:  fmt.Sprintf("gcp-gcs-public-%s", b.Name),
						Title:       fmt.Sprintf("GCS bucket %q grants %s to %s", b.Name, binding.Role, member),
						Description: "Bucket-level IAM grants public access.",
						Severity:    "high",
						Resource:    "//storage.googleapis.com/" + b.Name,
						Detected:    now,
						Evidence: map[string]any{
							"bucket": b.Name,
							"role":   binding.Role,
							"member": member,
						},
					})
				}
			}
		}
	}
	return out, nil
}

func isOverPrivilegedRole(role string) bool {
	switch role {
	case "roles/owner", "roles/editor", "roles/iam.securityAdmin", "roles/resourcemanager.organizationAdmin":
		return true
	}
	return false
}

// isHumanPrincipal returns true when the binding member is a user/group, not a service
// account. Service accounts are excluded because role-grant on them is operationally
// expected; we want to flag *human* over-privilege.
func isHumanPrincipal(member string) bool {
	if strings.HasPrefix(member, "user:") || strings.HasPrefix(member, "group:") {
		return true
	}
	return false
}

func sanitize(s string) string {
	r := strings.NewReplacer(":", "-", "@", "-at-", ".", "-")
	return r.Replace(s)
}
