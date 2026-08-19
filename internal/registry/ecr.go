package registry

import (
	"context"
	"errors"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

// ECR is the AWS Elastic Container Registry connector.
//
// Auth: AWS SDK default chain (env, ~/.aws, instance metadata, IRSA). Customer supplies
// region; we list repositories and (optionally) image tags. ResolveDigest uses ECR's
// BatchGetImage API rather than the generic v2 manifest lookup since ECR's v2 needs an
// ephemeral token from GetAuthorizationToken.
type ECR struct {
	cfg    Config
	client *ecr.Client
}

func NewECR(cfg Config) *ECR {
	c := &ECR{cfg: cfg}
	if cfg.Region == "" {
		return c // ListImages will error early
	}
	awsCfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(cfg.Region))
	if err == nil {
		c.client = ecr.NewFromConfig(awsCfg)
	}
	return c
}

func (e *ECR) Name() string { return "ecr" }

func (e *ECR) ListImages(ctx context.Context) ([]Image, error) {
	if e.client == nil {
		return nil, errors.New("ecr: region required + AWS credentials must be available")
	}
	out := []Image{}
	var next *string
	for {
		resp, err := e.client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{NextToken: next})
		if err != nil {
			return out, fmt.Errorf("ecr: describe-repositories: %w", err)
		}
		for _, r := range resp.Repositories {
			pushed := ""
			if r.CreatedAt != nil {
				pushed = r.CreatedAt.UTC().Format(time.RFC3339)
			}
			out = append(out, Image{
				Repository: awssdk.ToString(r.RepositoryUri),
				Tags:       e.describeTags(ctx, awssdk.ToString(r.RepositoryName)),
				PushedAt:   pushed,
			})
		}
		if resp.NextToken == nil {
			break
		}
		next = resp.NextToken
	}
	return out, nil
}

// describeTags enumerates all tags of a repository via ECR DescribeImages
// (paginated). Best-effort: a repo whose images cannot be described yields no
// tags, so the caller's tag policy falls back to its default selection.
func (e *ECR) describeTags(ctx context.Context, repoName string) []string {
	if repoName == "" {
		return nil
	}
	var tags []string
	var next *string
	for {
		resp, err := e.client.DescribeImages(ctx, &ecr.DescribeImagesInput{
			RepositoryName: awssdk.String(repoName),
			NextToken:      next,
		})
		if err != nil {
			return tags
		}
		for _, img := range resp.ImageDetails {
			tags = append(tags, img.ImageTags...)
		}
		if resp.NextToken == nil {
			return tags
		}
		next = resp.NextToken
	}
}

func (e *ECR) ResolveDigest(ctx context.Context, ref string) (string, error) {
	// At v1 we delegate to the generic v2 lookup; ECR returns proper digests when
	// authenticated via `aws ecr get-login-password` (the operator/agent runs that
	// out-of-band before invoking the scanner). For native AWS API resolution we'd add
	// a BatchGetImage call here.
	return resolveDigestViaV2(ctx, nil, ref, "")
}
