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
	if c.HTTP == nil {
		return nil, errors.New("gcp: HTTP client required")
	}
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
	var policy struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if err := c.requestJSON(ctx, http.MethodPost, urlStr, body, &policy); err != nil {
		return nil, fmt.Errorf("gcp: getIamPolicy: %w", err)
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
	now := time.Now().UTC()
	out := []Finding{}
	pageToken := ""
	seenPages := map[string]bool{}
	for {
		listURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s", url.QueryEscape(c.ProjectID))
		if pageToken != "" {
			listURL += "&pageToken=" + url.QueryEscape(pageToken)
		}
		var list struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := c.requestJSON(ctx, http.MethodGet, listURL, nil, &list); err != nil {
			return out, fmt.Errorf("gcp: list buckets: %w", err)
		}
		for _, bucket := range list.Items {
			if bucket.Name == "" {
				return out, errors.New("gcp: bucket response has no name")
			}
			policyURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/iam",
				url.PathEscape(bucket.Name))
			var pol struct {
				Bindings []struct {
					Role    string   `json:"role"`
					Members []string `json:"members"`
				} `json:"bindings"`
			}
			if err := c.requestJSON(ctx, http.MethodGet, policyURL, nil, &pol); err != nil {
				return out, fmt.Errorf("gcp: get IAM policy for bucket %q: %w", bucket.Name, err)
			}
			for _, binding := range pol.Bindings {
				for _, member := range binding.Members {
					if member == "allUsers" || member == "allAuthenticatedUsers" {
						out = append(out, Finding{
							ExternalID:  fmt.Sprintf("gcp-gcs-public-%s", bucket.Name),
							Title:       fmt.Sprintf("GCS bucket %q grants %s to %s", bucket.Name, binding.Role, member),
							Description: "Bucket-level IAM grants public access.",
							Severity:    "high",
							Resource:    "//storage.googleapis.com/" + bucket.Name,
							Detected:    now,
							Evidence: map[string]any{
								"bucket": bucket.Name,
								"role":   binding.Role,
								"member": member,
							},
						})
					}
				}
			}
		}
		if list.NextPageToken == "" {
			break
		}
		if seenPages[list.NextPageToken] {
			return out, errors.New("gcp: list buckets returned a repeated page token")
		}
		seenPages[list.NextPageToken] = true
		pageToken = list.NextPageToken
	}
	return out, nil
}

func (c *Connector) requestJSON(ctx context.Context, method, endpoint string, body io.Reader, target any) error {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return errors.New("invalid API request")
	}
	request.Header.Set("Authorization", "Bearer "+c.Token)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.HTTP.Do(request)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d", response.StatusCode)
	}
	const maxResponseBytes = 4 << 20
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read API response: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return errors.New("API response exceeds size limit")
	}
	if strings.TrimSpace(string(raw)) == "null" {
		return errors.New("empty API response")
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return errors.New("invalid API response JSON")
	}
	return nil
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
