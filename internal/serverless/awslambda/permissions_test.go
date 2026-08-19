package awslambda

import (
	"context"
	"errors"
	"net/url"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func TestIAMRoleAnalyzerFindsManagedAndInlinePermissionRisks(t *testing.T) {
	managedDoc := url.QueryEscape(`{
	  "Version": "2012-10-17",
	  "Statement": [
	    {"Effect": "Allow", "Action": ["iam:*", "s3:GetObject"], "Resource": "*"},
	    {"Effect": "Deny", "Action": "*", "Resource": "*"}
	  ]
	}`)
	inlineDoc := url.QueryEscape(`{
	  "Version": "2012-10-17",
	  "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}
	}`)
	client := &fakeIAMRolePermissionAPI{
		attached: []iamtypes.AttachedPolicy{{
			PolicyName: awssdk.String("PowerUserAccess"),
			PolicyArn:  awssdk.String("arn:aws:iam::aws:policy/PowerUserAccess"),
		}},
		policies: map[string]iamtypes.Policy{
			"arn:aws:iam::aws:policy/PowerUserAccess": {
				DefaultVersionId: awssdk.String("v1"),
				PolicyName:       awssdk.String("PowerUserAccess"),
			},
		},
		policyDocs: map[string]string{
			"arn:aws:iam::aws:policy/PowerUserAccess:v1": managedDoc,
		},
		inlineNames: []string{"wildcard"},
		inlineDocs:  map[string]string{"wildcard": inlineDoc},
	}
	got, err := (IAMRoleAnalyzer{Client: client}).AnalyzeRole(context.Background(), "arn:aws:iam::123456789012:role/service-role/payments")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "complete" || got.RoleName != "payments" || got.Level != "critical" {
		t.Fatalf("analysis = %+v", got)
	}
	if len(got.AttachedPolicies) != 1 || got.AttachedPolicies[0].Name != "PowerUserAccess" {
		t.Fatalf("attached policies = %+v", got.AttachedPolicies)
	}
	if len(got.InlinePolicies) != 1 || got.InlinePolicies[0] != "wildcard" {
		t.Fatalf("inline policies = %+v", got.InlinePolicies)
	}
	if !hasPermissionFinding(got.Findings, "aws-lambda-role-high-privilege-managed-policy") ||
		!hasPermissionFinding(got.Findings, "aws-lambda-role-sensitive-service-admin") ||
		!hasPermissionFinding(got.Findings, "aws-lambda-role-wildcard-admin") {
		t.Fatalf("findings = %+v", got.Findings)
	}
	if len(got.SensitiveActions) == 0 {
		t.Fatalf("sensitive actions missing: %+v", got)
	}
}

func TestIAMRoleAnalyzerReportsIncompleteCoverageOnFetchError(t *testing.T) {
	client := &fakeIAMRolePermissionAPI{
		attached: []iamtypes.AttachedPolicy{{
			PolicyName: awssdk.String("CustomPolicy"),
			PolicyArn:  awssdk.String("arn:aws:iam::123456789012:policy/CustomPolicy"),
		}},
		getPolicyErr: errors.New("access denied"),
		inlineNames:  []string{"inline-one"},
		getInlineErr: errors.New("access denied"),
	}
	got, err := (IAMRoleAnalyzer{Client: client}).AnalyzeRole(context.Background(), "arn:aws:iam::123456789012:role/service-role/payments")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "partial" {
		t.Fatalf("expected status partial when coverage is lost, got %q (%+v)", got.Status, got)
	}
	if !hasPermissionFinding(got.Findings, "aws-lambda-role-analysis-incomplete") {
		t.Fatalf("expected incomplete-coverage finding, findings = %+v", got.Findings)
	}
	// Both the unreadable managed and inline policies must be named.
	var managedNoted, inlineNoted bool
	for _, f := range got.Findings {
		if f.ID != "aws-lambda-role-analysis-incomplete" {
			continue
		}
		switch f.PolicyType {
		case "managed":
			managedNoted = true
		case "inline":
			inlineNoted = true
		}
	}
	if !managedNoted || !inlineNoted {
		t.Fatalf("expected both managed and inline unread policies noted, findings = %+v", got.Findings)
	}
}

func TestAnalyzePolicyDocumentHandlesNotAction(t *testing.T) {
	findings, _ := analyzePolicyDocument(`{
	  "Statement": {"Effect": "Allow", "NotAction": "iam:DeleteRole", "Resource": "*"}
	}`, "inline", "broad-notaction", "")
	if !hasPermissionFinding(findings, "aws-lambda-role-broad-notaction") {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestRoleNameFromARN(t *testing.T) {
	got := roleNameFromARN("arn:aws:iam::123456789012:role/service-role/payments")
	if got != "payments" {
		t.Fatalf("role name = %q", got)
	}
	if roleNameFromARN("not-an-arn") != "" {
		t.Fatal("expected invalid ARN to return empty role name")
	}
}

func hasPermissionFinding(findings []RolePermissionFinding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

type fakeIAMRolePermissionAPI struct {
	attached     []iamtypes.AttachedPolicy
	inlineNames  []string
	inlineDocs   map[string]string
	policies     map[string]iamtypes.Policy
	policyDocs   map[string]string
	getPolicyErr error
	getInlineErr error
}

func (f *fakeIAMRolePermissionAPI) ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: f.attached}, nil
}

func (f *fakeIAMRolePermissionAPI) ListRolePolicies(context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	return &iam.ListRolePoliciesOutput{PolicyNames: f.inlineNames}, nil
}

func (f *fakeIAMRolePermissionAPI) GetRolePolicy(_ context.Context, in *iam.GetRolePolicyInput, _ ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	if f.getInlineErr != nil {
		return nil, f.getInlineErr
	}
	return &iam.GetRolePolicyOutput{
		PolicyName:     in.PolicyName,
		RoleName:       in.RoleName,
		PolicyDocument: awssdk.String(f.inlineDocs[awssdk.ToString(in.PolicyName)]),
	}, nil
}

func (f *fakeIAMRolePermissionAPI) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	if f.getPolicyErr != nil {
		return nil, f.getPolicyErr
	}
	policy := f.policies[awssdk.ToString(in.PolicyArn)]
	return &iam.GetPolicyOutput{Policy: &policy}, nil
}

func (f *fakeIAMRolePermissionAPI) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	key := awssdk.ToString(in.PolicyArn) + ":" + awssdk.ToString(in.VersionId)
	return &iam.GetPolicyVersionOutput{
		PolicyVersion: &iamtypes.PolicyVersion{
			Document:  awssdk.String(f.policyDocs[key]),
			VersionId: in.VersionId,
		},
	}, nil
}
