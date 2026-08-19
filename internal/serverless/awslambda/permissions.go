package awslambda

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type RoleAnalyzer interface {
	AnalyzeRole(ctx context.Context, roleARN string) (RolePermissionAnalysis, error)
}

type IAMRolePermissionAPI interface {
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

type IAMRoleAnalyzer struct {
	Client IAMRolePermissionAPI
}

type RolePermissionAnalysis struct {
	Status           string                  `json:"status"`
	Level            string                  `json:"level"`
	RoleARN          string                  `json:"role_arn,omitempty"`
	RoleName         string                  `json:"role_name,omitempty"`
	Error            string                  `json:"error,omitempty"`
	AttachedPolicies []RolePolicyRef         `json:"attached_policies,omitempty"`
	InlinePolicies   []string                `json:"inline_policies,omitempty"`
	Findings         []RolePermissionFinding `json:"findings,omitempty"`
	SensitiveActions []string                `json:"sensitive_actions,omitempty"`
	ActionCount      int                     `json:"action_count,omitempty"`
}

type RolePolicyRef struct {
	Name string `json:"name,omitempty"`
	ARN  string `json:"arn,omitempty"`
}

type RolePermissionFinding struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	PolicyType  string   `json:"policy_type,omitempty"`
	PolicyName  string   `json:"policy_name,omitempty"`
	PolicyARN   string   `json:"policy_arn,omitempty"`
	Actions     []string `json:"actions,omitempty"`
	Resources   []string `json:"resources,omitempty"`
}

func (a IAMRoleAnalyzer) AnalyzeRole(ctx context.Context, roleARN string) (RolePermissionAnalysis, error) {
	roleName := roleNameFromARN(roleARN)
	if roleName == "" {
		return RolePermissionAnalysis{}, fmt.Errorf("role name not found in ARN %q", roleARN)
	}
	if a.Client == nil {
		return RolePermissionAnalysis{}, fmt.Errorf("iam client required")
	}
	out := RolePermissionAnalysis{
		Status:   "complete",
		Level:    "low",
		RoleARN:  strings.TrimSpace(roleARN),
		RoleName: roleName,
	}
	if err := a.collectAttachedPolicies(ctx, roleName, &out); err != nil {
		return out, err
	}
	if err := a.collectInlinePolicies(ctx, roleName, &out); err != nil {
		return out, err
	}
	out.Level = permissionLevel(out.Findings)
	sort.Strings(out.InlinePolicies)
	sort.Slice(out.AttachedPolicies, func(i, j int) bool {
		return out.AttachedPolicies[i].Name < out.AttachedPolicies[j].Name
	})
	sort.Strings(out.SensitiveActions)
	return out, nil
}

func (a IAMRoleAnalyzer) collectAttachedPolicies(ctx context.Context, roleName string, out *RolePermissionAnalysis) error {
	var marker *string
	for {
		list, err := a.Client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: awssdk.String(roleName),
			Marker:   marker,
		})
		if err != nil {
			return fmt.Errorf("list attached role policies: %w", err)
		}
		for _, policy := range list.AttachedPolicies {
			ref := RolePolicyRef{Name: awssdk.ToString(policy.PolicyName), ARN: awssdk.ToString(policy.PolicyArn)}
			out.AttachedPolicies = append(out.AttachedPolicies, ref)
			out.Findings = append(out.Findings, managedPolicyNameFindings(ref)...)
			doc, err := a.managedPolicyDocument(ctx, policy)
			if err != nil {
				out.noteIncompleteCoverage("managed", ref.Name, ref.ARN, err)
				continue
			}
			findings, actions := analyzePolicyDocument(doc, "managed", ref.Name, ref.ARN)
			out.Findings = append(out.Findings, findings...)
			out.SensitiveActions = mergeUniqueStrings(out.SensitiveActions, actions)
			out.ActionCount += len(actions)
		}
		if !list.IsTruncated || list.Marker == nil || strings.TrimSpace(*list.Marker) == "" {
			break
		}
		marker = list.Marker
	}
	return nil
}

// noteIncompleteCoverage records that a policy could not be fetched or decoded so
// the analysis never reports Status=complete when coverage was actually lost. An
// unread policy could be effectively-admin, so the result is downgraded to partial
// and an unknown-severity finding names the policy that went unanalyzed.
func (out *RolePermissionAnalysis) noteIncompleteCoverage(policyType, policyName, policyARN string, err error) {
	out.Status = "partial"
	out.Findings = append(out.Findings, RolePermissionFinding{
		ID:          "aws-lambda-role-analysis-incomplete",
		Severity:    "unknown",
		Title:       "Lambda execution role policy could not be analyzed",
		Description: fmt.Sprintf("failed to read %s policy %q: %v; permission coverage is incomplete", policyType, policyName, err),
		PolicyType:  policyType,
		PolicyName:  policyName,
		PolicyARN:   policyARN,
	})
}

func (a IAMRoleAnalyzer) managedPolicyDocument(ctx context.Context, policy iamtypes.AttachedPolicy) (string, error) {
	policyARN := awssdk.ToString(policy.PolicyArn)
	if policyARN == "" {
		return "", fmt.Errorf("policy ARN missing")
	}
	meta, err := a.Client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: awssdk.String(policyARN)})
	if err != nil {
		return "", err
	}
	if meta.Policy == nil || strings.TrimSpace(awssdk.ToString(meta.Policy.DefaultVersionId)) == "" {
		return "", fmt.Errorf("policy default version missing")
	}
	version, err := a.Client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: awssdk.String(policyARN),
		VersionId: meta.Policy.DefaultVersionId,
	})
	if err != nil {
		return "", err
	}
	if version.PolicyVersion == nil {
		return "", fmt.Errorf("policy version missing")
	}
	return decodeIAMPolicyDocument(awssdk.ToString(version.PolicyVersion.Document)), nil
}

func (a IAMRoleAnalyzer) collectInlinePolicies(ctx context.Context, roleName string, out *RolePermissionAnalysis) error {
	var marker *string
	for {
		list, err := a.Client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
			RoleName: awssdk.String(roleName),
			Marker:   marker,
		})
		if err != nil {
			return fmt.Errorf("list inline role policies: %w", err)
		}
		for _, name := range list.PolicyNames {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			out.InlinePolicies = append(out.InlinePolicies, name)
			doc, err := a.Client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName:   awssdk.String(roleName),
				PolicyName: awssdk.String(name),
			})
			if err != nil {
				out.noteIncompleteCoverage("inline", name, "", err)
				continue
			}
			findings, actions := analyzePolicyDocument(decodeIAMPolicyDocument(awssdk.ToString(doc.PolicyDocument)), "inline", name, "")
			out.Findings = append(out.Findings, findings...)
			out.SensitiveActions = mergeUniqueStrings(out.SensitiveActions, actions)
			out.ActionCount += len(actions)
		}
		if !list.IsTruncated || list.Marker == nil || strings.TrimSpace(*list.Marker) == "" {
			break
		}
		marker = list.Marker
	}
	return nil
}

func managedPolicyNameFindings(policy RolePolicyRef) []RolePermissionFinding {
	switch policy.Name {
	case "AdministratorAccess":
		return []RolePermissionFinding{{
			ID:          "aws-lambda-role-administrator-access",
			Severity:    "critical",
			Title:       "Lambda execution role has AdministratorAccess",
			Description: "The AWS managed AdministratorAccess policy grants broad account control to the Lambda execution role.",
			PolicyType:  "managed",
			PolicyName:  policy.Name,
			PolicyARN:   policy.ARN,
			Actions:     []string{"*"},
			Resources:   []string{"*"},
		}}
	case "PowerUserAccess", "IAMFullAccess", "AWSLambdaFullAccess":
		return []RolePermissionFinding{{
			ID:          "aws-lambda-role-high-privilege-managed-policy",
			Severity:    "high",
			Title:       "Lambda execution role has a high-privilege managed policy",
			Description: "The attached AWS managed policy is commonly broader than a Lambda runtime needs.",
			PolicyType:  "managed",
			PolicyName:  policy.Name,
			PolicyARN:   policy.ARN,
		}}
	default:
		return nil
	}
}

type policyDocument struct {
	Statement policyStatements `json:"Statement"`
}

type policyStatements []policyStatement

func (s *policyStatements) UnmarshalJSON(data []byte) error {
	var many []policyStatement
	if err := json.Unmarshal(data, &many); err == nil {
		*s = many
		return nil
	}
	var one policyStatement
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*s = []policyStatement{one}
	return nil
}

type policyStatement struct {
	Effect      string     `json:"Effect"`
	Action      stringList `json:"Action"`
	NotAction   stringList `json:"NotAction"`
	Resource    stringList `json:"Resource"`
	NotResource stringList `json:"NotResource"`
}

type stringList []string

func (s *stringList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		if strings.TrimSpace(one) == "" {
			*s = nil
		} else {
			*s = []string{strings.TrimSpace(one)}
		}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	out := make([]string, 0, len(many))
	for _, value := range many {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	*s = out
	return nil
}

func analyzePolicyDocument(raw string, policyType string, policyName string, policyARN string) ([]RolePermissionFinding, []string) {
	var doc policyDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, nil
	}
	findings := []RolePermissionFinding{}
	sensitiveActions := []string{}
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(strings.TrimSpace(stmt.Effect), "allow") {
			continue
		}
		actions := normalizePolicyValues(stmt.Action)
		resources := normalizePolicyValues(stmt.Resource)
		if len(resources) == 0 {
			resources = []string{"*"}
		}
		if len(stmt.NotAction) > 0 && hasWildcardResource(resources) {
			findings = append(findings, RolePermissionFinding{
				ID:          "aws-lambda-role-broad-notaction",
				Severity:    "critical",
				Title:       "Lambda execution role allows broad NotAction access",
				Description: "Allow plus NotAction on broad resources usually grants most AWS actions except the listed exclusions.",
				PolicyType:  policyType,
				PolicyName:  policyName,
				PolicyARN:   policyARN,
				Actions:     normalizePolicyValues(stmt.NotAction),
				Resources:   resources,
			})
			continue
		}
		if len(actions) == 0 {
			continue
		}
		sensitiveActions = mergeUniqueStrings(sensitiveActions, sensitivePolicyActions(actions))
		switch {
		case hasAction(actions, "*") && hasWildcardResource(resources):
			findings = append(findings, RolePermissionFinding{
				ID:          "aws-lambda-role-wildcard-admin",
				Severity:    "critical",
				Title:       "Lambda execution role allows all actions on all resources",
				Description: "The policy contains Effect=Allow with Action=* and Resource=*.",
				PolicyType:  policyType,
				PolicyName:  policyName,
				PolicyARN:   policyARN,
				Actions:     actions,
				Resources:   resources,
			})
		case hasSensitiveServiceWildcard(actions) && hasWildcardResource(resources):
			findings = append(findings, RolePermissionFinding{
				ID:          "aws-lambda-role-sensitive-service-admin",
				Severity:    "high",
				Title:       "Lambda execution role allows sensitive service wildcard access",
				Description: "The policy grants wildcard access to services that commonly allow privilege escalation or data exposure.",
				PolicyType:  policyType,
				PolicyName:  policyName,
				PolicyARN:   policyARN,
				Actions:     sensitivePolicyActions(actions),
				Resources:   resources,
			})
		case hasAction(actions, "iam:PassRole") && hasWildcardResource(resources):
			findings = append(findings, RolePermissionFinding{
				ID:          "aws-lambda-role-passrole-wildcard",
				Severity:    "high",
				Title:       "Lambda execution role can pass arbitrary IAM roles",
				Description: "iam:PassRole on broad resources can enable privilege escalation through other AWS services.",
				PolicyType:  policyType,
				PolicyName:  policyName,
				PolicyARN:   policyARN,
				Actions:     []string{"iam:PassRole"},
				Resources:   resources,
			})
		}
	}
	return findings, sensitiveActions
}

func decodeIAMPolicyDocument(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return raw
	}
	return decoded
}

func roleNameFromARN(roleARN string) string {
	roleARN = strings.TrimSpace(roleARN)
	const marker = ":role/"
	idx := strings.LastIndex(roleARN, marker)
	if idx < 0 {
		return ""
	}
	name := roleARN[idx+len(marker):]
	if slash := strings.LastIndex(name, "/"); slash >= 0 {
		name = name[slash+1:]
	}
	return strings.TrimSpace(name)
}

func normalizePolicyValues(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sensitivePolicyActions(actions []string) []string {
	out := []string{}
	for _, action := range actions {
		lower := strings.ToLower(strings.TrimSpace(action))
		switch {
		case lower == "*",
			lower == "iam:passrole",
			lower == "sts:assumerole",
			strings.HasSuffix(lower, ":*") && isSensitiveService(strings.TrimSuffix(lower, ":*")):
			out = append(out, action)
		}
	}
	return normalizePolicyValues(out)
}

func hasAction(actions []string, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	for _, action := range actions {
		if strings.ToLower(strings.TrimSpace(action)) == want {
			return true
		}
	}
	return false
}

func hasWildcardResource(resources []string) bool {
	if len(resources) == 0 {
		return true
	}
	for _, resource := range resources {
		if strings.TrimSpace(resource) == "*" {
			return true
		}
	}
	return false
}

func hasSensitiveServiceWildcard(actions []string) bool {
	for _, action := range actions {
		lower := strings.ToLower(strings.TrimSpace(action))
		if strings.HasSuffix(lower, ":*") && isSensitiveService(strings.TrimSuffix(lower, ":*")) {
			return true
		}
	}
	return false
}

func isSensitiveService(service string) bool {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "iam", "sts", "lambda", "ec2", "s3", "kms", "secretsmanager", "ssm", "ecr", "organizations":
		return true
	default:
		return false
	}
}

func permissionLevel(findings []RolePermissionFinding) string {
	level := "low"
	for _, finding := range findings {
		switch strings.ToLower(finding.Severity) {
		case "critical":
			return "critical"
		case "high":
			level = "high"
		case "medium":
			if level == "low" {
				level = "medium"
			}
		}
	}
	return level
}

func mergeUniqueStrings(existing []string, values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(existing)+len(values))
	for _, value := range append(existing, values...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}
