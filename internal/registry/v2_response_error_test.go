package registry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func invokeV2ErrorOperation(ctx context.Context, client *http.Client, operation, url string) error {
	switch operation {
	case "head":
		_, err := headManifest(ctx, client, url, manifestAccept, "owned-token")
		return err
	case "body":
		_, _, _, err := getManifestBody(ctx, client, url, manifestAccept, "owned-token")
		return err
	case "digest":
		_, err := getManifestDigest(ctx, client, url, manifestAccept, "owned-token")
		return err
	case "tags":
		_, _, err := getTagsPage(ctx, client, url, "owned-token")
		return err
	default:
		_, err := fetchTokenFromChallenge(ctx, client, `Bearer realm="`+url+`",service="owned"`)
		return err
	}
}

func checkV2ErrorBoundary(t *testing.T, operation, fault string) {
	t.Helper()
	fixture := &redactionFixture{fault: fault, payload: `{}`, failure: errors.New("owned failure " + responseSecretCanary)}
	client := &http.Client{Transport: registryPageTransport(func(request *http.Request) (*http.Response, error) {
		response, err := fixture.response(request)
		if response != nil {
			response.Header.Set("WWW-Authenticate", `Bearer realm="https://owned.example/?token=`+responseSecretCanary+`"`)
		}
		return response, err
	})}
	err := invokeV2ErrorOperation(t.Context(), client, operation, "https://owned.example/"+responseSecretCanary)
	if err == nil || strings.Contains(err.Error(), responseSecretCanary) {
		t.Fatal("V2 failure exposed upstream values")
	}
	if fault == "status" && operation != "token" {
		var unauthorized *errUnauthorized
		if !errors.As(err, &unauthorized) || !strings.Contains(unauthorized.challenge, responseSecretCanary) {
			t.Fatal("safe error lost the internal authentication challenge")
		}
	} else {
		assertCategoricalResponseError(t, err, fixture)
	}
	for _, body := range fixture.bodies {
		if body.closed != 1 {
			t.Fatal("response was not closed exactly once")
		}
	}
}

func TestV2FailuresDoNotDiscloseRemoteValues(t *testing.T) {
	for _, operation := range []string{"head", "body", "digest", "tags", "token"} {
		for _, fault := range []string{"transport", "read", "close", "status"} {
			if operation == "head" && fault == "read" {
				continue
			}
			t.Run(operation+"/"+fault, func(t *testing.T) { checkV2ErrorBoundary(t, operation, fault) })
		}
	}
}

func TestV2MalformedRequestDoesNotEchoURL(t *testing.T) {
	for _, operation := range []string{"head", "body", "digest", "tags", "token"} {
		t.Run(operation, func(t *testing.T) {
			client := &http.Client{Transport: registryPageTransport(func(*http.Request) (*http.Response, error) {
				t.Fatal("malformed request reached transport")
				return nil, errors.New("unexpected dispatch")
			})}
			err := invokeV2ErrorOperation(t.Context(), client, operation, "https://owned.example/"+responseSecretCanary+"%zz")
			if err == nil || strings.Contains(err.Error(), responseSecretCanary) {
				t.Fatal("malformed URL escaped error boundary")
			}
			var safe *providerResponseError
			if !errors.As(err, &safe) || safe.category != "request creation failed" {
				t.Fatal("request failure lost its stage")
			}
		})
	}
}

func TestV2DecodeErrorsKeepTypedCausePrivate(t *testing.T) {
	for _, operation := range []string{"tags", "token"} {
		t.Run(operation, func(t *testing.T) {
			payload := `{"tags":` + responseSecretCanary + `}`
			if operation == "token" {
				payload = `{"token":` + responseSecretCanary + `}`
			}
			fixture := &redactionFixture{fault: "json", payload: payload}
			err := invokeV2ErrorOperation(t.Context(), fixture.client(), operation, "https://owned.example/")
			assertCategoricalResponseError(t, err, fixture)
		})
	}
}

func TestV2ManifestDecodeErrorsKeepTypedCausePrivate(t *testing.T) {
	for name, payload := range map[string]string{
		"header": `{"schemaVersion":` + responseSecretCanary + `}`,
		"index":  `{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":` + responseSecretCanary + `}`,
		"image":  `{"config":{"size":` + responseSecretCanary + `}}`,
	} {
		t.Run(name, func(t *testing.T) {
			result, err := manifestMetadataFromBody(t.Context(), nil, "owned.example", "owned.example", "repo", "ref", []byte(payload), "digest", "", "", "")
			if result != nil || err == nil || strings.Contains(err.Error(), responseSecretCanary) {
				t.Fatal("manifest decode exposed remote diagnostics")
			}
			var typed *json.UnmarshalTypeError
			var safe *providerResponseError
			if !errors.As(err, &typed) || !errors.As(err, &safe) {
				t.Fatal("manifest decode lost its typed cause or safe boundary")
			}
		})
	}
}

func TestV2ValidationErrorsExcludeUntrustedValues(t *testing.T) {
	_, challengeErr := fetchTokenFromChallenge(t.Context(), nil, "Basic "+responseSecretCanary)
	_, repositoryErr := listTagsViaV2(t.Context(), nil, responseSecretCanary, "")
	_, _, _, platformErr := selectManifestPlatform(nil, responseSecretCanary, responseSecretCanary)
	for _, err := range []error{challengeErr, repositoryErr, platformErr} {
		if err == nil || strings.Contains(err.Error(), responseSecretCanary) {
			t.Fatal("validation echoed untrusted values")
		}
	}
}
