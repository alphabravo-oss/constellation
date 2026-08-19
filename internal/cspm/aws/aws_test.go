package aws

import (
	"context"
	"errors"
	"net/url"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// fakeIAM injects canned responses + records call counts so the connector can be tested
// without an AWS account.
type fakeIAM struct {
	roles           []iamtypes.Role
	attachedByRole  map[string][]iamtypes.AttachedPolicy
	inlineByRole    map[string][]string
	inlineDocByRole map[string]map[string]string
}

func (f *fakeIAM) ListRoles(_ context.Context, _ *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{Roles: f.roles}, nil
}
func (f *fakeIAM) ListAttachedRolePolicies(_ context.Context, in *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: f.attachedByRole[awssdk.ToString(in.RoleName)]}, nil
}
func (f *fakeIAM) ListRolePolicies(_ context.Context, in *iam.ListRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	return &iam.ListRolePoliciesOutput{PolicyNames: f.inlineByRole[awssdk.ToString(in.RoleName)]}, nil
}
func (f *fakeIAM) GetRolePolicy(_ context.Context, in *iam.GetRolePolicyInput, _ ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	doc := f.inlineDocByRole[awssdk.ToString(in.RoleName)][awssdk.ToString(in.PolicyName)]
	return &iam.GetRolePolicyOutput{PolicyDocument: &doc}, nil
}

type fakeS3 struct {
	buckets     []s3types.Bucket
	aclByBucket map[string][]s3types.Grant
	pabByBucket map[string]*s3types.PublicAccessBlockConfiguration
	pabMissing  map[string]bool
}

func (f *fakeS3) ListBuckets(_ context.Context, _ *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: f.buckets}, nil
}
func (f *fakeS3) GetBucketAcl(_ context.Context, in *s3.GetBucketAclInput, _ ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	return &s3.GetBucketAclOutput{Grants: f.aclByBucket[awssdk.ToString(in.Bucket)]}, nil
}
func (f *fakeS3) GetPublicAccessBlock(_ context.Context, in *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	name := awssdk.ToString(in.Bucket)
	if f.pabMissing[name] {
		return nil, errAmazon404
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: f.pabByBucket[name]}, nil
}

var errAmazon404 = error404{}

type error404 struct{}

func (error404) Error() string { return "NoSuchPublicAccessBlockConfiguration" }

func TestScanIAM_FlagsOverPrivilegedAndWildcard(t *testing.T) {
	roleA := iamtypes.Role{RoleName: awssdk.String("admin-role"), Arn: awssdk.String("arn:aws:iam::123:role/admin-role")}
	roleB := iamtypes.Role{RoleName: awssdk.String("dev-role"), Arn: awssdk.String("arn:aws:iam::123:role/dev-role")}
	roleC := iamtypes.Role{RoleName: awssdk.String("read-role"), Arn: awssdk.String("arn:aws:iam::123:role/read-role")}

	c := &Connector{
		IAM: &fakeIAM{
			roles: []iamtypes.Role{roleA, roleB, roleC},
			attachedByRole: map[string][]iamtypes.AttachedPolicy{
				"admin-role": {{PolicyName: awssdk.String("AdministratorAccess"), PolicyArn: awssdk.String("arn:aws:iam::aws:policy/AdministratorAccess")}},
				"read-role":  {{PolicyName: awssdk.String("ReadOnlyAccess"), PolicyArn: awssdk.String("arn:aws:iam::aws:policy/ReadOnlyAccess")}},
			},
			inlineByRole: map[string][]string{"dev-role": {"wildcard-allow"}},
			inlineDocByRole: map[string]map[string]string{
				"dev-role": {"wildcard-allow": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
			},
		},
		S3: &fakeS3{},
	}

	out, err := c.ScanIAM(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 IAM findings, got %d: %+v", len(out), out)
	}
	hasAdmin := false
	hasWildcard := false
	for _, f := range out {
		if f.Title == `IAM role "admin-role" has AdministratorAccess attached` {
			hasAdmin = true
		}
		if f.Title == `IAM role "dev-role" has wildcard-grant inline policy "wildcard-allow"` {
			hasWildcard = true
			if f.Severity != "critical" {
				t.Fatalf("wildcard severity: %q", f.Severity)
			}
		}
	}
	if !hasAdmin || !hasWildcard {
		t.Fatalf("missing expected findings: admin=%v wildcard=%v", hasAdmin, hasWildcard)
	}
}

func TestScanS3_FlagsPublicAclAndWeakPAB(t *testing.T) {
	bucketA := s3types.Bucket{Name: awssdk.String("public-bucket")}
	bucketB := s3types.Bucket{Name: awssdk.String("missing-pab")}
	bucketC := s3types.Bucket{Name: awssdk.String("locked-down")}

	tFalse := false
	tTrue := true
	c := &Connector{
		IAM: &fakeIAM{},
		S3: &fakeS3{
			buckets: []s3types.Bucket{bucketA, bucketB, bucketC},
			aclByBucket: map[string][]s3types.Grant{
				"public-bucket": {{
					Permission: s3types.PermissionRead,
					Grantee: &s3types.Grantee{
						Type: s3types.TypeGroup,
						URI:  awssdk.String("http://acs.amazonaws.com/groups/global/AllUsers"),
					},
				}},
			},
			pabByBucket: map[string]*s3types.PublicAccessBlockConfiguration{
				"public-bucket": {
					BlockPublicAcls:       &tFalse,
					IgnorePublicAcls:      &tFalse,
					BlockPublicPolicy:     &tFalse,
					RestrictPublicBuckets: &tFalse,
				},
				"locked-down": {
					BlockPublicAcls:       &tTrue,
					IgnorePublicAcls:      &tTrue,
					BlockPublicPolicy:     &tTrue,
					RestrictPublicBuckets: &tTrue,
				},
			},
			pabMissing: map[string]bool{"missing-pab": true},
		},
	}
	out, err := c.ScanS3(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Expect: public-bucket ACL (high) + public-bucket PAB-incomplete (high) + missing-pab no-PAB (medium).
	if len(out) != 3 {
		t.Fatalf("expected 3 S3 findings, got %d: %+v", len(out), out)
	}
	severities := map[string]int{}
	for _, f := range out {
		severities[f.Severity]++
	}
	if severities["high"] != 2 || severities["medium"] != 1 {
		t.Fatalf("severity counts: %+v", severities)
	}
}

func TestIsWildcardGrant(t *testing.T) {
	if !isWildcardGrant(`{"Effect":"Allow","Action":"*","Resource":"*"}`) {
		t.Fatal("should detect wildcard")
	}
	if isWildcardGrant(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`) {
		t.Fatal("should not flag non-wildcard action")
	}
	if isWildcardGrant(`{"Effect":"Deny","Action":"*","Resource":"*"}`) {
		t.Fatal("Deny statements aren't wildcards-of-concern")
	}
}

// TestIsWildcardGrant_URLEncoded is the regression for H4: GetRolePolicy returns the
// policy document URL-encoded, and the old substring matcher never fired on it.
func TestIsWildcardGrant_URLEncoded(t *testing.T) {
	plain := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	encoded := url.QueryEscape(plain)
	if encoded == plain {
		t.Fatal("test precondition: encoded form should differ from plain")
	}
	if !isWildcardGrant(encoded) {
		t.Fatalf("URL-encoded Allow */* must be detected, got false for %q", encoded)
	}
}

// TestIsWildcardGrant_Shapes covers array-valued Action/Resource and a multi-statement
// document where only a non-leading statement is the wildcard grant.
func TestIsWildcardGrant_Shapes(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"action array wildcard", `{"Statement":[{"Effect":"Allow","Action":["*"],"Resource":["*"]}]}`, true},
		{"action array no wildcard", `{"Statement":[{"Effect":"Allow","Action":["s3:Get*"],"Resource":["*"]}]}`, false},
		{"wildcard in later statement", `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Effect":"Allow","Action":"*","Resource":"*"}]}`, true},
		{"lowercase keys", `{"statement":[{"effect":"allow","action":"*","resource":"*"}]}`, true},
		{"garbage", `not json`, false},
	}
	for _, tc := range cases {
		if got := isWildcardGrant(tc.body); got != tc.want {
			t.Errorf("%s: isWildcardGrant=%v want %v", tc.name, got, tc.want)
		}
	}
}

// errIAM fails ListRoles to exercise the partial-failure path.
type errIAM struct{ fakeIAM }

func (*errIAM) ListRoles(_ context.Context, _ *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return nil, errors.New("AccessDenied: iam:ListRoles")
}

// TestScan_PartialFailureSurfaces is the regression for the CSPM fail-open: a single
// failed sub-scan must surface an error, not be reported as a clean scan.
func TestScan_PartialFailureSurfaces(t *testing.T) {
	c := &Connector{
		IAM: &errIAM{},
		S3: &fakeS3{
			buckets: []s3types.Bucket{{Name: awssdk.String("b")}},
			aclByBucket: map[string][]s3types.Grant{
				"b": {{Permission: s3types.PermissionRead, Grantee: &s3types.Grantee{URI: awssdk.String("http://acs.amazonaws.com/groups/global/AllUsers")}}},
			},
			pabMissing: map[string]bool{"b": true},
		},
	}
	out, err := c.Scan(context.Background())
	if err == nil {
		t.Fatal("expected Scan to surface the IAM sub-scan failure, got nil")
	}
	if len(out) == 0 {
		t.Fatal("expected partial S3 findings to still be returned alongside the error")
	}
}

// pagingIAM returns two pages of roles to exercise the ListRoles Marker loop.
type pagingIAM struct {
	fakeIAM
	page1, page2 []iamtypes.Role
}

func (p *pagingIAM) ListRoles(_ context.Context, in *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	if in.Marker == nil {
		return &iam.ListRolesOutput{Roles: p.page1, IsTruncated: true, Marker: awssdk.String("next")}, nil
	}
	return &iam.ListRolesOutput{Roles: p.page2, IsTruncated: false}, nil
}

// TestScanIAM_PaginatesRoles is the regression for the no-pagination fail-open: a
// wildcard-grant role on the second page must still be flagged.
func TestScanIAM_PaginatesRoles(t *testing.T) {
	p := &pagingIAM{
		page1: []iamtypes.Role{{RoleName: awssdk.String("page1-role"), Arn: awssdk.String("arn:p1")}},
		page2: []iamtypes.Role{{RoleName: awssdk.String("page2-role"), Arn: awssdk.String("arn:p2")}},
	}
	p.inlineByRole = map[string][]string{"page2-role": {"wild"}}
	p.inlineDocByRole = map[string]map[string]string{
		"page2-role": {"wild": url.QueryEscape(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)},
	}
	c := &Connector{IAM: p, S3: &fakeS3{}}
	out, err := c.ScanIAM(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range out {
		if f.Title == `IAM role "page2-role" has wildcard-grant inline policy "wild"` {
			found = true
		}
	}
	if !found {
		t.Fatalf("second-page wildcard role not flagged: %+v", out)
	}
}
