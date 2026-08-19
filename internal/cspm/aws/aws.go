// Package aws is the AWS cloud-CSPM connector.
//
// v1 scope (per the spec's "Cloud Posture (cloud-CSPM) Pillar" — IAM + storage + control plane):
//
//   - IAM over-privilege detection: roles with AdministratorAccess attached or inline
//     policies containing Effect=Allow, Action="*", Resource="*"
//   - Public S3 buckets: ACLs that grant READ/WRITE to AllUsers or AuthenticatedUsers,
//     or BlockPublicAccess settings that don't fully block public access
//
// The connector is intentionally read-only: customer hands us an IAM role (preferred) or
// AccessKey/SecretKey + Region; we list resources and emit Findings with kind=cloud-config.
// EKS control-plane misconfig coverage is queued for a later cut.
package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// IAMLister is the subset of the IAM client we depend on. Lets tests inject a fake.
type IAMLister interface {
	ListRoles(ctx context.Context, in *iam.ListRolesInput, opts ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListAttachedRolePolicies(ctx context.Context, in *iam.ListAttachedRolePoliciesInput, opts ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(ctx context.Context, in *iam.ListRolePoliciesInput, opts ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(ctx context.Context, in *iam.GetRolePolicyInput, opts ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
}

// S3Lister is the subset of the S3 client we depend on.
type S3Lister interface {
	ListBuckets(ctx context.Context, in *s3.ListBucketsInput, opts ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketAcl(ctx context.Context, in *s3.GetBucketAclInput, opts ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
	GetPublicAccessBlock(ctx context.Context, in *s3.GetPublicAccessBlockInput, opts ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

// Finding is the cloud-CSPM-shaped finding the connector emits. Maps to the platform
// Finding schema with kind=cloud-config at ingest time.
type Finding struct {
	ExternalID  string
	Title       string
	Description string
	Severity    string
	Resource    string
	Evidence    map[string]any
	Detected    time.Time
}

// Connector wires IAM + S3 scanners. NewFromConfig opens the AWS SDK default config
// (env, ~/.aws, instance metadata, IRSA — whatever the deployment supplies).
type Connector struct {
	IAM IAMLister
	S3  S3Lister
}

// NewFromConfig builds a connector from the default credential chain.
func NewFromConfig(ctx context.Context, region string) (*Connector, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws: load config: %w", err)
	}
	return &Connector{IAM: iam.NewFromConfig(cfg), S3: s3.NewFromConfig(cfg)}, nil
}

// Scan returns the union of IAM + S3 findings.
func (c *Connector) Scan(ctx context.Context) ([]Finding, error) {
	if c.IAM == nil || c.S3 == nil {
		return nil, errors.New("aws: connector missing IAM or S3 client")
	}
	iamF, ierr := c.ScanIAM(ctx)
	s3F, serr := c.ScanS3(ctx)

	out := append(iamF, s3F...)
	// Surface a failure whenever ANY sub-scan fails: a partial scan (e.g. an
	// AccessDenied on iam:ListRoles with a healthy S3 scan) must not be reported
	// clean, or operators conclude an unscanned source is compliant.
	if err := errors.Join(ierr, serr); err != nil {
		return out, fmt.Errorf("aws: scan incomplete: %w", err)
	}
	return out, nil
}

// ScanIAM enumerates roles and flags wildcard-grant inline + AdministratorAccess attached.
func (c *Connector) ScanIAM(ctx context.Context) ([]Finding, error) {
	out := []Finding{}
	now := time.Now().UTC()

	// IAM ListRoles returns ≤100 roles/page; loop until IsTruncated is false so
	// a wildcard-grant role beyond the first page is not silently skipped.
	var rolesMarker *string
	for {
		rolesOut, err := c.IAM.ListRoles(ctx, &iam.ListRolesInput{Marker: rolesMarker})
		if err != nil {
			return out, fmt.Errorf("aws: list roles: %w", err)
		}
		for _, role := range rolesOut.Roles {
			roleName := awssdk.ToString(role.RoleName)

			// Attached managed policies — flag AdministratorAccess + similar.
			var attMarker *string
			for {
				attached, err := c.IAM.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: role.RoleName, Marker: attMarker})
				if err != nil {
					break
				}
				for _, p := range attached.AttachedPolicies {
					name := awssdk.ToString(p.PolicyName)
					if isOverPrivilegedManagedPolicy(name) {
						out = append(out, Finding{
							ExternalID:  fmt.Sprintf("aws-iam-overprivilege-%s-%s", roleName, name),
							Title:       fmt.Sprintf("IAM role %q has %s attached", roleName, name),
							Description: "AWS managed policy granting broad privileges is attached to this role.",
							Severity:    "high",
							Resource:    awssdk.ToString(role.Arn),
							Detected:    now,
							Evidence: map[string]any{
								"role":           roleName,
								"managed_policy": name,
								"policy_arn":     awssdk.ToString(p.PolicyArn),
							},
						})
					}
				}
				if !attached.IsTruncated || attached.Marker == nil {
					break
				}
				attMarker = attached.Marker
			}

			// Inline policies — flag wildcard Action+Resource.
			var inlineMarker *string
			for {
				inline, err := c.IAM.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: role.RoleName, Marker: inlineMarker})
				if err != nil {
					break
				}
				for _, polName := range inline.PolicyNames {
					doc, err := c.IAM.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
						RoleName:   role.RoleName,
						PolicyName: awssdk.String(polName),
					})
					if err != nil {
						continue
					}
					body := awssdk.ToString(doc.PolicyDocument)
					if isWildcardGrant(body) {
						out = append(out, Finding{
							ExternalID:  fmt.Sprintf("aws-iam-wildcard-%s-%s", roleName, polName),
							Title:       fmt.Sprintf("IAM role %q has wildcard-grant inline policy %q", roleName, polName),
							Description: "Inline policy contains Effect=Allow with Action=* and Resource=*.",
							Severity:    "critical",
							Resource:    awssdk.ToString(role.Arn),
							Detected:    now,
							Evidence: map[string]any{
								"role":          roleName,
								"inline_policy": polName,
								"document":      truncate(decodePolicyDoc(body), 1024),
							},
						})
					}
				}
				if !inline.IsTruncated || inline.Marker == nil {
					break
				}
				inlineMarker = inline.Marker
			}
		}
		if !rolesOut.IsTruncated || rolesOut.Marker == nil {
			break
		}
		rolesMarker = rolesOut.Marker
	}
	return out, nil
}

// ScanS3 lists buckets and flags ones with public-read/public-write ACLs or weak
// public-access-block settings.
func (c *Connector) ScanS3(ctx context.Context) ([]Finding, error) {
	out := []Finding{}
	now := time.Now().UTC()

	// ListBuckets is paginated via ContinuationToken; loop until it is empty so
	// buckets beyond the first page are still evaluated.
	var buckets []s3types.Bucket
	var contToken *string
	for {
		bucketsOut, err := c.S3.ListBuckets(ctx, &s3.ListBucketsInput{ContinuationToken: contToken})
		if err != nil {
			return out, fmt.Errorf("aws: list buckets: %w", err)
		}
		buckets = append(buckets, bucketsOut.Buckets...)
		if bucketsOut.ContinuationToken == nil || *bucketsOut.ContinuationToken == "" {
			break
		}
		contToken = bucketsOut.ContinuationToken
	}
	for _, b := range buckets {
		name := awssdk.ToString(b.Name)

		// ACL: read all grants and flag AllUsers/AuthenticatedUsers grantees.
		acl, err := c.S3.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: b.Name})
		if err == nil {
			for _, g := range acl.Grants {
				uri := ""
				if g.Grantee != nil && g.Grantee.URI != nil {
					uri = *g.Grantee.URI
				}
				if isPublicGroupURI(uri) {
					out = append(out, Finding{
						ExternalID:  fmt.Sprintf("aws-s3-public-acl-%s", name),
						Title:       fmt.Sprintf("S3 bucket %q has public ACL grant", name),
						Description: fmt.Sprintf("Bucket grants %s to %s.", g.Permission, uri),
						Severity:    severityForS3Permission(g.Permission),
						Resource:    fmt.Sprintf("arn:aws:s3:::%s", name),
						Detected:    now,
						Evidence: map[string]any{
							"grantee_uri": uri,
							"permission":  string(g.Permission),
						},
					})
				}
			}
		}

		// PublicAccessBlock: any of the four flags being false = at-risk.
		block, err := c.S3.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: b.Name})
		switch {
		case err != nil:
			// No PAB config at all → flag as the lowest-cost remediation suggestion.
			out = append(out, Finding{
				ExternalID:  fmt.Sprintf("aws-s3-no-pab-%s", name),
				Title:       fmt.Sprintf("S3 bucket %q has no Public Access Block", name),
				Description: "Bucket-level Public Access Block is not configured.",
				Severity:    "medium",
				Resource:    fmt.Sprintf("arn:aws:s3:::%s", name),
				Detected:    now,
				Evidence:    map[string]any{"err": err.Error()},
			})
		case block.PublicAccessBlockConfiguration != nil:
			cfg := block.PublicAccessBlockConfiguration
			if cfg.BlockPublicAcls == nil || !*cfg.BlockPublicAcls ||
				cfg.IgnorePublicAcls == nil || !*cfg.IgnorePublicAcls ||
				cfg.BlockPublicPolicy == nil || !*cfg.BlockPublicPolicy ||
				cfg.RestrictPublicBuckets == nil || !*cfg.RestrictPublicBuckets {
				out = append(out, Finding{
					ExternalID:  fmt.Sprintf("aws-s3-pab-incomplete-%s", name),
					Title:       fmt.Sprintf("S3 bucket %q PAB does not fully block public access", name),
					Description: "One or more of the four PAB flags is not enabled.",
					Severity:    "high",
					Resource:    fmt.Sprintf("arn:aws:s3:::%s", name),
					Detected:    now,
					Evidence: map[string]any{
						"BlockPublicAcls":       boolPtr(cfg.BlockPublicAcls),
						"IgnorePublicAcls":      boolPtr(cfg.IgnorePublicAcls),
						"BlockPublicPolicy":     boolPtr(cfg.BlockPublicPolicy),
						"RestrictPublicBuckets": boolPtr(cfg.RestrictPublicBuckets),
					},
				})
			}
		}
	}
	return out, nil
}

// ---------- helpers --------------------------------------------------------------------

func isOverPrivilegedManagedPolicy(name string) bool {
	switch name {
	case "AdministratorAccess", "PowerUserAccess", "IAMFullAccess":
		return true
	}
	return false
}

// decodePolicyDoc URL-decodes an IAM policy document. GetRolePolicy returns the
// inline policy document URL-encoded; AWS only decodes it for you in some SDKs, so
// we decode defensively. A non-encoded document round-trips unchanged.
func decodePolicyDoc(body string) string {
	if decoded, err := url.QueryUnescape(body); err == nil {
		return decoded
	}
	return body
}

// isWildcardGrant reports whether the policy body contains any Effect=Allow
// statement granting Action=* on Resource=*. The body may be URL-encoded (the form
// GetRolePolicy returns) and is parsed structurally so the string/array shapes of
// Statement/Action/Resource are all handled — a substring match against the
// percent-escaped JSON never fires, which is the fail-open this replaces.
func isWildcardGrant(body string) bool {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(decodePolicyDoc(body)), &doc); err != nil {
		return false
	}
	var stmts []map[string]json.RawMessage
	switch stmtRaw := jsonField(doc, "statement"); {
	case stmtRaw == nil:
		// Bare statement object with no "Statement" wrapper.
		stmts = []map[string]json.RawMessage{doc}
	case len(stmtRaw) > 0 && stmtRaw[0] == '[':
		_ = json.Unmarshal(stmtRaw, &stmts)
	default:
		var single map[string]json.RawMessage
		if json.Unmarshal(stmtRaw, &single) == nil {
			stmts = []map[string]json.RawMessage{single}
		}
	}
	for _, s := range stmts {
		effect := strings.Trim(strings.ToLower(string(jsonField(s, "effect"))), `"`)
		if effect != "allow" {
			continue
		}
		if jsonValueHasWildcard(jsonField(s, "action")) && jsonValueHasWildcard(jsonField(s, "resource")) {
			return true
		}
	}
	return false
}

// jsonField does a case-insensitive key lookup in a decoded JSON object. IAM
// canonicalizes keys to PascalCase, but we don't rely on that.
func jsonField(m map[string]json.RawMessage, key string) json.RawMessage {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return nil
}

// jsonValueHasWildcard reports whether a JSON value that is either a string or an
// array of strings contains the "*" wildcard.
func jsonValueHasWildcard(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == "*"
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		for _, v := range arr {
			if v == "*" {
				return true
			}
		}
	}
	return false
}

func isPublicGroupURI(uri string) bool {
	return uri == "http://acs.amazonaws.com/groups/global/AllUsers" ||
		uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
}

func severityForS3Permission(p s3types.Permission) string {
	switch p {
	case s3types.PermissionWrite, s3types.PermissionWriteAcp, s3types.PermissionFullControl:
		return "critical"
	case s3types.PermissionRead, s3types.PermissionReadAcp:
		return "high"
	}
	return "medium"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func boolPtr(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

// silence unused-import warnings when adapter types haven't been used directly in this file.
var _ = iamtypes.Role{}
