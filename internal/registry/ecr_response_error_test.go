package registry

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/smithy-go"
)

func ecrErrorClient(transport http.RoundTripper, provider awssdk.CredentialsProvider) *ECR {
	return &ECR{client: ecr.NewFromConfig(awssdk.Config{
		Region: "us-east-1", Credentials: provider,
		HTTPClient: &http.Client{Transport: transport},
	}, func(options *ecr.Options) { options.RetryMaxAttempts = 1 })}
}

func ecrErrorOperation(t *testing.T, connector *ECR, operation string) error {
	t.Helper()
	switch operation {
	case "repositories":
		rows, err := connector.ListImages(t.Context())
		if len(rows) != 0 {
			t.Fatal("failed inventory returned rows")
		}
		return err
	case "image":
		digest, err := connector.ResolveDigest(t.Context(), "owned.ecr.example/repo:tag")
		if digest != "" {
			t.Fatal("failed lookup returned a digest")
		}
		return err
	default:
		user, password, endpoint, err := connector.AuthToken(t.Context())
		if user != "" || password != "" || endpoint != "" {
			t.Fatal("failed authorization returned credentials")
		}
		return err
	}
}

func checkECRErrorBoundary(t *testing.T, operation, fault string) {
	t.Helper()
	cause := errors.New("owned SDK failure " + responseSecretCanary)
	requests := 0
	provider := awssdk.CredentialsProviderFunc(func(context.Context) (awssdk.Credentials, error) {
		if fault == "credentials" {
			return awssdk.Credentials{}, cause
		}
		return awssdk.Credentials{AccessKeyID: "owned-access", SecretAccessKey: "owned-secret"}, nil
	})
	transport := registryPageTransport(func(request *http.Request) (*http.Response, error) {
		requests++
		if fault == "transport" {
			return nil, cause
		}
		return credentialResponse(request, http.StatusBadRequest,
			`{"__type":"InvalidParameterException","message":"`+responseSecretCanary+`"}`), nil
	})
	err := ecrErrorOperation(t, ecrErrorClient(transport, provider), operation)
	if err == nil || strings.Contains(err.Error(), responseSecretCanary) {
		t.Fatal("SDK error disclosed remote diagnostic values")
	}
	var safe *providerResponseError
	if !errors.As(err, &safe) || safe.stage != "ecr "+operation || safe.category != "SDK request failed" {
		t.Fatal("error lost constant operation context")
	}
	if fault == "status" {
		var apiError smithy.APIError
		if !errors.As(err, &apiError) || apiError.ErrorMessage() != responseSecretCanary {
			t.Fatal("typed SDK cause was not preserved")
		}
	} else if !errors.Is(err, cause) {
		t.Fatal("SDK cause was not preserved")
	}
	wantRequests := 1
	if fault == "credentials" {
		wantRequests = 0
	}
	if requests != wantRequests {
		t.Fatal("failure changed SDK dispatch count")
	}
}

func TestECRSDKFailuresDoNotDiscloseRemoteValues(t *testing.T) {
	for _, operation := range []string{"repositories", "image", "authorization"} {
		for _, fault := range []string{"credentials", "transport", "status"} {
			t.Run(operation+"/"+fault, func(t *testing.T) { checkECRErrorBoundary(t, operation, fault) })
		}
	}
}

func TestECRMissingDigestDoesNotEchoReference(t *testing.T) {
	transport := registryPageTransport(func(request *http.Request) (*http.Response, error) {
		return credentialResponse(request, http.StatusOK, `{"images":[]}`), nil
	})
	provider := awssdk.CredentialsProviderFunc(func(context.Context) (awssdk.Credentials, error) {
		return awssdk.Credentials{AccessKeyID: "owned-access", SecretAccessKey: "owned-secret"}, nil
	})
	digest, err := ecrErrorClient(transport, provider).ResolveDigest(t.Context(), "owned.ecr.example/"+responseSecretCanary+":tag")
	if digest != "" || err == nil || strings.Contains(err.Error(), responseSecretCanary) {
		t.Fatal("missing digest exposed the supplied reference")
	}
}

func TestECRCatalogRetainsCompletedPagesOnSafeFailure(t *testing.T) {
	requests := 0
	transport := registryPageTransport(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			// An absent repositoryName deliberately avoids the independent best-effort tag call.
			return credentialResponse(request, http.StatusOK,
				`{"repositories":[{"repositoryUri":"owned.ecr.example/first"}],"nextToken":"owned-next"}`), nil
		}
		return credentialResponse(request, http.StatusBadRequest,
			`{"__type":"InvalidParameterException","message":"`+responseSecretCanary+`"}`), nil
	})
	provider := awssdk.CredentialsProviderFunc(func(context.Context) (awssdk.Credentials, error) {
		return awssdk.Credentials{AccessKeyID: "owned-access", SecretAccessKey: "owned-secret"}, nil
	})
	rows, err := ecrErrorClient(transport, provider).ListImages(t.Context())
	if requests != 2 || len(rows) != 1 || rows[0].Repository != "owned.ecr.example/first" {
		t.Fatal("failure changed earlier completed pages or continued enumeration")
	}
	if err == nil || strings.Contains(err.Error(), responseSecretCanary) {
		t.Fatal("later page exposed SDK diagnostics")
	}
}
