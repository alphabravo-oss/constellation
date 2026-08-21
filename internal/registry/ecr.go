package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// ECR is the AWS Elastic Container Registry connector.
//
// Auth: STATIC access keys when the registry config supplies them
// (Config.AccessKeyID/SecretAccessKey, optionally SessionToken), otherwise the AWS SDK
// default chain (env, ~/.aws, instance metadata, IRSA). Customer supplies the region.
// We list repositories and (optionally) image tags via the ECR API, and resolve
// digests via BatchGetImage (which authenticates with the same credentials, so private
// registries resolve without an out-of-band `docker login`).
//
// A short-lived docker authorization token (GetAuthorizationToken, ~12h TTL) is
// available via AuthToken for the scanner to pull images; it is cached and refreshed
// before expiry.
type ECR struct {
	cfg    Config
	client *ecr.Client
}

func NewECR(cfg Config) *ECR {
	c := &ECR{cfg: cfg}
	if cfg.Region == "" {
		return c // ListImages will error early
	}
	opts := []func(*config.LoadOptions) error{config.WithRegion(cfg.Region)}
	// Honor static access keys from the registry config instead of relying solely on
	// the ambient credential chain. Without this, non-manual scan cadences against a
	// registry configured with explicit keys would fall back to whatever (if anything)
	// the process environment provides.
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, cfg.SessionToken),
		))
	}
	// Route AWS SDK traffic through the shared outbound client when one was wired, so
	// the runtime egress-proxy / TLS knobs apply to ECR too.
	if cfg.HTTPClient != nil {
		opts = append(opts, config.WithHTTPClient(cfg.HTTPClient))
	}
	awsCfg, err := config.LoadDefaultConfig(context.Background(), opts...)
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

// ResolveDigest resolves a (repo, tag) reference to a fully-qualified digest ref using
// ECR's BatchGetImage API, which authenticates with the connector's configured
// credentials (static keys or the ambient chain). Falls back to the generic anonymous
// v2 lookup when the native call is unavailable.
func (e *ECR) ResolveDigest(ctx context.Context, ref string) (string, error) {
	if e.client == nil {
		return resolveDigestViaV2(ctx, nil, ref, "")
	}
	host, repo, tag, err := parseRef(ref)
	if err != nil {
		return "", err
	}
	resp, err := e.client.BatchGetImage(ctx, &ecr.BatchGetImageInput{
		RepositoryName: awssdk.String(repo),
		ImageIds:       []ecrtypes.ImageIdentifier{{ImageTag: awssdk.String(tag)}},
		AcceptedMediaTypes: []string{
			"application/vnd.docker.distribution.manifest.v2+json",
			"application/vnd.oci.image.manifest.v1+json",
			"application/vnd.docker.distribution.manifest.list.v2+json",
			"application/vnd.oci.image.index.v1+json",
		},
	})
	if err != nil {
		return "", fmt.Errorf("ecr: batch-get-image: %w", err)
	}
	for _, img := range resp.Images {
		if img.ImageId != nil && img.ImageId.ImageDigest != nil {
			return fmt.Sprintf("%s/%s@%s", host, repo, awssdk.ToString(img.ImageId.ImageDigest)), nil
		}
	}
	return "", fmt.Errorf("ecr: no digest for %s", ref)
}

// AuthToken returns docker-login credentials for this ECR registry, obtained via
// GetAuthorizationToken and cached until shortly before the ~12h token expiry. The
// returned username is always "AWS"; password is the decoded secret. proxyEndpoint is
// the registry URL the credentials authenticate against. Intended for the scanner to
// pull images without an out-of-band `aws ecr get-login-password`.
func (e *ECR) AuthToken(ctx context.Context) (username, password, proxyEndpoint string, err error) {
	if e.client == nil {
		return "", "", "", errors.New("ecr: region required + AWS credentials must be available")
	}
	cacheKey := tokenCacheKey("ecr-auth", e.cfg.Region, e.cfg.AccessKeyID)
	if cached, ok := tokenCacheGet(cacheKey); ok {
		user, pass, ep, perr := splitECRAuth(cached)
		if perr == nil {
			return user, pass, ep, nil
		}
	}
	resp, err := e.client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return "", "", "", fmt.Errorf("ecr: get-authorization-token: %w", err)
	}
	if len(resp.AuthorizationData) == 0 || resp.AuthorizationData[0].AuthorizationToken == nil {
		return "", "", "", errors.New("ecr: empty authorization data")
	}
	data := resp.AuthorizationData[0]
	proxyEndpoint = awssdk.ToString(data.ProxyEndpoint)
	tokenB64 := awssdk.ToString(data.AuthorizationToken)
	user, pass, err := decodeECRAuthToken(tokenB64)
	if err != nil {
		return "", "", "", err
	}
	expiry := time.Now().Add(11 * time.Hour)
	if data.ExpiresAt != nil {
		expiry = *data.ExpiresAt
	}
	// Cache the raw "endpoint\x00user:pass" so proxy endpoint survives the round-trip.
	tokenCachePut(cacheKey, proxyEndpoint+"\x00"+user+":"+pass, expiry)
	return user, pass, proxyEndpoint, nil
}

// decodeECRAuthToken decodes the base64 "user:password" authorization token.
func decodeECRAuthToken(b64 string) (user, pass string, err error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", "", fmt.Errorf("ecr: decode authorization token: %w", err)
	}
	u, p, ok := strings.Cut(string(raw), ":")
	if !ok {
		return "", "", errors.New("ecr: malformed authorization token")
	}
	return u, p, nil
}

// splitECRAuth reverses the cache encoding "endpoint\x00user:pass".
func splitECRAuth(s string) (user, pass, endpoint string, err error) {
	ep, up, ok := strings.Cut(s, "\x00")
	if !ok {
		return "", "", "", errors.New("ecr: malformed cached auth")
	}
	u, p, ok := strings.Cut(up, ":")
	if !ok {
		return "", "", "", errors.New("ecr: malformed cached auth")
	}
	return u, p, ep, nil
}
