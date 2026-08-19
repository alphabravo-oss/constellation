// Package azure is the Azure cloud-CSPM connector.
//
// v1 scope:
//   - Subscription-level role assignments granting "Owner" or "Contributor" to non-
//     service-principal identities
//   - Storage account blob containers with publicAccess != "None"
//
// Auth: customer hands us an Azure AD bearer token + subscription ID. We hit the ARM
// REST API directly. Future cuts can swap in github.com/Azure/azure-sdk-for-go/sdk/...
// when we want streaming or pagination cursors.
package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Finding mirrors the cspm/{aws,gcp}.Finding shape.
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

// Connector reads Azure role assignments + storage container public-access settings.
type Connector struct {
	HTTP           HTTPClient
	Token          string
	SubscriptionID string
}

// New constructs a Connector from a pre-acquired bearer token.
func New(token, subscriptionID string) *Connector {
	return &Connector{HTTP: &http.Client{Timeout: 30 * time.Second}, Token: token, SubscriptionID: subscriptionID}
}

// Scan returns role-assignment + storage findings.
func (c *Connector) Scan(ctx context.Context) ([]Finding, error) {
	if c.Token == "" || c.SubscriptionID == "" {
		return nil, errors.New("azure: Token + SubscriptionID required")
	}
	roleF, rerr := c.ScanRoleAssignments(ctx)
	storF, serr := c.ScanStorage(ctx)
	out := append(roleF, storF...)
	if rerr != nil && serr != nil {
		return out, fmt.Errorf("azure: both scans failed: %v; %v", rerr, serr)
	}
	return out, nil
}

// ScanRoleAssignments lists subscription-scoped role assignments and flags Owner/
// Contributor grants to non-service-principal identities.
func (c *Connector) ScanRoleAssignments(ctx context.Context) ([]Finding, error) {
	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01",
		c.SubscriptionID)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure: list role assignments: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("azure: list role assignments status %d", resp.StatusCode)
	}
	var doc struct {
		Value []struct {
			Properties struct {
				RoleDefinitionID string `json:"roleDefinitionId"`
				PrincipalID      string `json:"principalId"`
				PrincipalType    string `json:"principalType"` // User | Group | ServicePrincipal
				Scope            string `json:"scope"`
			} `json:"properties"`
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	out := []Finding{}
	for _, ra := range doc.Value {
		if !isOverPrivilegedRoleID(ra.Properties.RoleDefinitionID) {
			continue
		}
		if ra.Properties.PrincipalType == "ServicePrincipal" {
			continue
		}
		out = append(out, Finding{
			ExternalID:  fmt.Sprintf("azure-rbac-overprivilege-%s", ra.Name),
			Title:       fmt.Sprintf("Azure subscription role assignment grants Owner/Contributor to %s", ra.Properties.PrincipalType),
			Description: "Subscription-scoped role assignment grants high-privilege role to a human/group.",
			Severity:    "high",
			Resource:    ra.Properties.Scope,
			Detected:    now,
			Evidence: map[string]any{
				"principal_id":    ra.Properties.PrincipalID,
				"principal_type":  ra.Properties.PrincipalType,
				"role_definition": ra.Properties.RoleDefinitionID,
				"assignment_name": ra.Name,
			},
		})
	}
	return out, nil
}

// ScanStorage enumerates storage accounts in the subscription and flags blob containers
// with publicAccess != "None".
func (c *Connector) ScanStorage(ctx context.Context) ([]Finding, error) {
	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01",
		c.SubscriptionID)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure: list storage accounts: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("azure: list storage status %d", resp.StatusCode)
	}
	var accts struct {
		Value []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Properties struct {
				AllowBlobPublicAccess *bool `json:"allowBlobPublicAccess"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &accts); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	out := []Finding{}
	for _, a := range accts.Value {
		// AllowBlobPublicAccess=true is the storage-account-level switch that permits
		// any container's publicAccess to actually serve anonymous reads. Flag any
		// account that has it enabled.
		if a.Properties.AllowBlobPublicAccess != nil && *a.Properties.AllowBlobPublicAccess {
			out = append(out, Finding{
				ExternalID:  fmt.Sprintf("azure-storage-public-allowed-%s", a.Name),
				Title:       fmt.Sprintf("Azure storage account %q has AllowBlobPublicAccess=true", a.Name),
				Description: "Storage account permits container-level public access. Disable unless explicitly required.",
				Severity:    "high",
				Resource:    a.ID,
				Detected:    now,
				Evidence:    map[string]any{"allowBlobPublicAccess": true, "name": a.Name},
			})
		}
	}
	return out, nil
}

// isOverPrivilegedRoleID returns true when the role definition GUID matches Owner or
// Contributor. These IDs are fixed by Azure and won't change.
func isOverPrivilegedRoleID(roleDefinitionID string) bool {
	// Format: /subscriptions/<sub>/providers/Microsoft.Authorization/roleDefinitions/<guid>
	switch roleDefinitionID[strings.LastIndex(roleDefinitionID, "/")+1:] {
	case "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": // Owner
		return true
	case "b24988ac-6180-42a0-ab88-20f7382dd24c": // Contributor
		return true
	case "00482a5a-887f-4fb3-b363-3b7fe8e74483": // User Access Administrator
		return true
	}
	return false
}
