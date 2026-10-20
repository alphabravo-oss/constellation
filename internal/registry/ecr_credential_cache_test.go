package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

type ecrCredentialFixture struct {
	actual        awssdk.Credentials
	providerCalls int
	requests      int
	failProvider  bool
	denyRequest   bool
	rotateOnRead  bool
}

func (f *ecrCredentialFixture) provider(_ context.Context) (awssdk.Credentials, error) {
	f.providerCalls++
	if f.failProvider {
		return awssdk.Credentials{}, errors.New("owned provider unavailable")
	}
	if f.rotateOnRead {
		return awssdk.Credentials{AccessKeyID: fmt.Sprintf("owned-access-%d", f.providerCalls), SecretAccessKey: "owned-secret"}, nil
	}
	return f.actual, nil
}

func (f *ecrCredentialFixture) client(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		f.requests++
		if f.denyRequest {
			return credentialResponse(r, http.StatusBadRequest, `{"__type":"InvalidSignatureException","message":"owned credential refused"}`), nil
		}
		if f.rotateOnRead && !strings.Contains(r.Header.Get("Authorization"), "Credential=owned-access-1/") {
			t.Fatal("SDK minted with a different credential than the reviewed cache identity")
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("AWS:owned-password-%d", f.requests)))
		body := fmt.Sprintf(`{"authorizationData":[{"authorizationToken":%q,"proxyEndpoint":"https://owned.ecr.example","expiresAt":%d}]}`, encoded, time.Now().Add(time.Hour).Unix())
		return credentialResponse(r, http.StatusOK, body), nil
	})}
}

func scopedECRFixture(t *testing.T, fixture *ecrCredentialFixture) *ECR {
	t.Helper()
	cfg := Config{CredentialCacheScope: ownedCredentialScope(t), Region: "us-east-1"}
	client := ecr.NewFromConfig(awssdk.Config{Region: cfg.Region,
		Credentials: awssdk.CredentialsProviderFunc(fixture.provider), HTTPClient: fixture.client(t)})
	return &ECR{cfg: cfg, client: client}
}

func checkECRCredentialBoundary(t *testing.T, change string) {
	t.Helper()
	isolateTokenCache(t)
	fixture := &ecrCredentialFixture{actual: awssdk.Credentials{AccessKeyID: "owned-access", SecretAccessKey: "owned-secret", SessionToken: "owned-session"}}
	connector := scopedECRFixture(t, fixture)
	_, first, _, err := connector.AuthToken(t.Context())
	if err != nil || first == "" || fixture.requests != 1 {
		t.Fatal("initial ECR mint failed")
	}
	switch change {
	case "same-identity":
	case "wrong-secret":
		fixture.actual.SecretAccessKey = "owned-wrong-secret"
		fixture.denyRequest = true
	case "rotated-secret":
		fixture.actual.SecretAccessKey = "owned-new-secret"
	case "rotated-session":
		fixture.actual.SessionToken = "owned-new-session"
	case "sibling-scope":
		connector.cfg.CredentialCacheScope = ownedCredentialScope(t)
	case "missing-scope":
		connector.cfg.CredentialCacheScope = ""
	case "failed-provider":
		fixture.failProvider = true
	}
	_, second, _, err := connector.AuthToken(t.Context())
	if change == "wrong-secret" || change == "failed-provider" {
		if err == nil || second != "" {
			t.Fatal("unauthenticated effective credential borrowed a cached ECR token")
		}
		return
	}
	wantRequests := 2
	if change == "same-identity" {
		wantRequests = 1
	}
	if err != nil || second == "" || fixture.requests != wantRequests || (first == second) != (change == "same-identity") {
		t.Fatal("ECR cache did not bind effective credential, session and owner")
	}
}

func TestECRCacheBindsEffectiveProviderCredentialAndOwner(t *testing.T) {
	for _, change := range []string{"same-identity", "wrong-secret", "rotated-secret", "rotated-session", "sibling-scope", "missing-scope", "failed-provider"} {
		t.Run(change, func(t *testing.T) { checkECRCredentialBoundary(t, change) })
	}
}

func TestECRMintUsesTheSameCredentialSnapshotAsCacheIdentity(t *testing.T) {
	isolateTokenCache(t)
	fixture := &ecrCredentialFixture{rotateOnRead: true}
	connector := scopedECRFixture(t, fixture)
	if _, password, _, err := connector.AuthToken(t.Context()); err != nil || password == "" {
		t.Fatal("owned rotating-provider mint failed")
	}
	if fixture.providerCalls != 1 || fixture.requests != 1 {
		t.Fatal("effective provider was retrieved again between cache identity and mint")
	}
}

func checkECRPartialCredentialRejected(t *testing.T, cfg Config) {
	t.Helper()
	requests := 0
	cfg.Region = "us-east-1"
	cfg.HTTPClient = &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		return credentialResponse(r, http.StatusOK, `{}`), nil
	})}
	connector := NewECR(cfg)
	if images, err := connector.ListImages(t.Context()); err == nil || len(images) != 0 {
		t.Fatal("partial credentials used an ambient inventory identity")
	}
	if digest, err := connector.ResolveDigest(t.Context(), "owned.ecr.example/repo:tag"); err == nil || digest != "" {
		t.Fatal("partial credentials used an ambient or anonymous digest identity")
	}
	if user, password, endpoint, err := connector.AuthToken(t.Context()); err == nil || user != "" || password != "" || endpoint != "" {
		t.Fatal("partial credentials minted an ambient registry token")
	}
	if requests != 0 {
		t.Fatal("partial explicit credentials dispatched a request")
	}
}

func TestECRPartialExplicitCredentialsNeverFallBackToAmbientOrAnonymous(t *testing.T) {
	// A valid ambient source must not rescue an explicitly incomplete identity.
	t.Setenv("AWS_ACCESS_KEY_ID", "owned-ambient-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "owned-ambient-secret")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	for name, cfg := range map[string]Config{
		"access-only":    {AccessKeyID: "owned-access"},
		"secret-only":    {SecretAccessKey: "owned-secret"},
		"session-only":   {SessionToken: "owned-session"},
		"access-session": {AccessKeyID: "owned-access", SessionToken: "owned-session"},
		"secret-session": {SecretAccessKey: "owned-secret", SessionToken: "owned-session"},
	} {
		t.Run(name, func(t *testing.T) { checkECRPartialCredentialRejected(t, cfg) })
	}
}

func TestECRFullyAmbientAndCompleteExplicitCredentialsRemainSupported(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "owned-ambient-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "owned-ambient-secret")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	for name, cfg := range map[string]Config{
		"ambient": {},
		"static":  {AccessKeyID: "owned-access", SecretAccessKey: "owned-secret"},
		"session": {AccessKeyID: "owned-access", SecretAccessKey: "owned-secret", SessionToken: "owned-session"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.Region = "us-east-1"
			cfg.HTTPClient = &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
				return credentialResponse(r, http.StatusOK, `{"repositories":[]}`), nil
			})}
			if _, err := NewECR(cfg).ListImages(t.Context()); err != nil {
				t.Fatal("supported ambient/complete explicit identity stopped authenticating")
			}
		})
	}
}

func TestECRPartialCredentialWithoutRegionRefusesAnonymousDigest(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		response := credentialResponse(r, http.StatusOK, `{}`)
		response.Header.Set("Docker-Content-Digest", "sha256:must-not-publish")
		return response, nil
	})}
	// The legacy nil-SDK fallback deliberately constructs a client with nil
	// transport; intercept that exact path too, rather than relying on DNS failure.
	previous := http.DefaultTransport
	http.DefaultTransport = client.Transport
	t.Cleanup(func() { http.DefaultTransport = previous })
	connector := NewECR(Config{AccessKeyID: "owned-incomplete", HTTPClient: client})
	if digest, err := connector.ResolveDigest(t.Context(), "owned.ecr.example/repo:tag"); err == nil || digest != "" || requests != 0 {
		t.Fatal("missing region disguised explicit partial credentials as anonymous lookup")
	}
}
