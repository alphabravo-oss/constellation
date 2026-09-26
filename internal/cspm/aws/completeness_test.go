package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type incompleteIAM struct {
	fakeIAM
	fail string
}

func (client *incompleteIAM) ListAttachedRolePolicies(ctx context.Context, input *iam.ListAttachedRolePoliciesInput, options ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	if client.fail == "attached" {
		return nil, errors.New("AccessDenied")
	}
	return client.fakeIAM.ListAttachedRolePolicies(ctx, input, options...)
}

func (client *incompleteIAM) ListRolePolicies(ctx context.Context, input *iam.ListRolePoliciesInput, options ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	if client.fail == "inline" {
		return nil, errors.New("AccessDenied")
	}
	return client.fakeIAM.ListRolePolicies(ctx, input, options...)
}

func (client *incompleteIAM) GetRolePolicy(ctx context.Context, input *iam.GetRolePolicyInput, options ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	if client.fail == "document" {
		return nil, errors.New("AccessDenied")
	}
	return client.fakeIAM.GetRolePolicy(ctx, input, options...)
}

func TestScanIAMNestedFailuresNeverReportComplete(t *testing.T) {
	for _, failure := range []string{"attached", "inline", "document", "malformed"} {
		t.Run(failure, func(t *testing.T) {
			client := &incompleteIAM{fail: failure, fakeIAM: fakeIAM{
				roles:           []iamtypes.Role{{RoleName: awssdk.String("sensitive")}},
				inlineByRole:    map[string][]string{"sensitive": {"policy"}},
				inlineDocByRole: map[string]map[string]string{"sensitive": {"policy": "invalid-secret-document"}},
			}}
			connector := &Connector{IAM: client, S3: &fakeS3{}}
			_, err := connector.Scan(context.Background())
			if err == nil || !strings.Contains(err.Error(), "scan incomplete") {
				t.Fatalf("scan should fail closed: %v", err)
			}
			if strings.Contains(err.Error(), "invalid-secret-document") {
				t.Fatal("error leaked policy contents")
			}
		})
	}
}

type incompleteS3 struct {
	fakeS3
	fail string
}

func (client *incompleteS3) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput, options ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	if client.fail == "acl" {
		return nil, errors.New("AccessDenied")
	}
	return client.fakeS3.GetBucketAcl(ctx, input, options...)
}

func (client *incompleteS3) GetPublicAccessBlock(ctx context.Context, input *s3.GetPublicAccessBlockInput, options ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if client.fail == "block" {
		return nil, errors.New("AccessDenied")
	}
	return client.fakeS3.GetPublicAccessBlock(ctx, input, options...)
}

func TestScanS3DistinguishesInaccessibleFromAbsent(t *testing.T) {
	for _, failure := range []string{"acl", "block", "empty"} {
		t.Run(failure, func(t *testing.T) {
			client := &incompleteS3{fail: failure, fakeS3: fakeS3{
				buckets: []s3types.Bucket{{Name: awssdk.String("bucket")}},
				aclByBucket: map[string][]s3types.Grant{"bucket": {{
					Permission: s3types.PermissionRead,
					Grantee:    &s3types.Grantee{URI: awssdk.String("http://acs.amazonaws.com/groups/global/AllUsers")},
				}}},
			}}
			connector := &Connector{IAM: &fakeIAM{}, S3: client}
			findings, err := connector.Scan(context.Background())
			if err == nil {
				t.Fatal("inaccessible or empty evidence must not report success")
			}
			if failure != "acl" && len(findings) != 1 {
				t.Fatalf("expected partial ACL finding, got %+v", findings)
			}
			for _, finding := range findings {
				if strings.Contains(finding.ExternalID, "no-pab") {
					t.Fatal("inaccessible configuration was misreported as absent")
				}
			}
		})
	}
}

func TestCheckNextPageRejectsMissingAndCyclicTokens(t *testing.T) {
	seen := map[string]bool{}
	for _, marker := range []*string{nil, awssdk.String("")} {
		if err := checkNextPage(marker, seen); err == nil {
			t.Fatal("truncated page without a marker was accepted")
		}
	}
	for _, marker := range []string{"first", "second"} {
		if err := checkNextPage(&marker, seen); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkNextPage(awssdk.String("first"), seen); err == nil {
		t.Fatal("pagination cycle was accepted")
	}
}

func TestWildcardGrantRejectsUnverifiableDocuments(t *testing.T) {
	for _, document := range []string{"", "null", "{}", `{"Statement":42}`, `{"Statement":[null]}`, `{"Statement":[{"Effect":"unknown"}]}`} {
		if _, err := wildcardGrant(document); err == nil {
			t.Errorf("unverifiable document accepted: %s", document)
		}
	}
	plain := `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Sid":"keep+literal%20"}}`
	if decoded := decodePolicyDoc(plain); decoded != plain {
		t.Fatalf("plain JSON was modified: %s", decoded)
	}
}
