package registry

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func v2TagsFallbackClient(t *testing.T, failedPage *trackedResponseBody) *http.Client {
	t.Helper()
	return &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		header := make(http.Header)
		var body io.ReadCloser
		switch r.URL.Path {
		case "/v2/broken/tags/list":
			body = failedPage
			if r.URL.Query().Get("page") != "2" {
				body = io.NopCloser(strings.NewReader(`{"tags":["partial-must-not-populate"]}`))
				header.Set("Link", `</v2/broken/tags/list?page=2>; rel="next"`)
			}
		case "/v2/healthy/tags/list":
			body = io.NopCloser(strings.NewReader(`{"tags":["healthy-v2"]}`))
		default:
			t.Fatal("unexpected repository lookup, including already-populated tags")
			return nil, io.ErrUnexpectedEOF
		}
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: body, Request: r}, nil
	})}
}

func checkV2PartialTags(t *testing.T, fault string) {
	t.Helper()
	body := faultResponseBody(`{"tags":["failed-page-must-not-appear"]}`, fault, 4<<20)
	tags, err := listTagsViaV2(t.Context(), v2TagsFallbackClient(t, body), "registry.example/broken", "")
	assertResponseFailed(t, err, body, fault)
	if strings.Join(tags, ",") != "partial-must-not-populate" {
		t.Fatal("partial tag enumeration lost earlier pages or accepted failed-page tags")
	}
}

func TestV2TagsReturnEarlierPagesWithFailure(t *testing.T) {
	for _, fault := range []string{"read", "close", "overflow"} {
		t.Run(fault, func(t *testing.T) { checkV2PartialTags(t, fault) })
	}
}

func checkV2PopulateFallback(t *testing.T, fault string) {
	t.Helper()
	body := faultResponseBody(`{"tags":["failed-page-must-not-appear"]}`, fault, 4<<20)
	images := []Image{
		{Repository: "registry.example/broken"},
		{Repository: "registry.example/populated", Tags: []string{"existing"}},
		{Repository: "registry.example/healthy"},
	}
	populateTagsViaV2(t.Context(), v2TagsFallbackClient(t, body), images, "")
	if len(images[0].Tags) != 0 || strings.Join(images[1].Tags, ",") != "existing" || strings.Join(images[2].Tags, ",") != "healthy-v2" || body.closed != 1 {
		t.Fatal("failed repository tags displaced the no-tag fallback, existing tags or healthy repository")
	}
}

func TestV2PopulateTagsRetainsPerRepositoryFallback(t *testing.T) {
	for _, fault := range []string{"read", "close", "overflow"} {
		t.Run(fault, func(t *testing.T) { checkV2PopulateFallback(t, fault) })
	}
}

const v2OwnedIndex = `{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"digest":"sha256:child","platform":{"os":"linux","architecture":"amd64"}}]}`
const v2OwnedChild = `{"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:config","size":3},"layers":[{"digest":"sha256:layer","size":7}]}`

func TestV2ManifestChallengeClosesBeforeRetryAndRetainsChildToken(t *testing.T) {
	var paths []string
	var bodies []*trackedResponseBody
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		if len(bodies) > 0 && bodies[len(bodies)-1].closed != 1 {
			t.Fatal("next request dispatched before prior response closed")
		}
		paths = append(paths, r.URL.Path)
		header := make(http.Header)
		status, payload := http.StatusOK, v2OwnedIndex
		switch len(paths) {
		case 1:
			status, payload = http.StatusUnauthorized, ""
			header.Set("WWW-Authenticate", `Bearer realm="https://registry.example/token",service="registry.example",scope="repository:acme/api:pull"`)
		case 2:
			payload = `{"token":"owned-token"}`
			if r.URL.Query().Get("scope") != "repository:acme/api:pull" || r.URL.Query().Get("service") != "registry.example" {
				t.Fatal("challenge grant parameters changed")
			}
		case 3:
			if r.Header.Get("Authorization") != "Bearer owned-token" {
				t.Fatal("retried index request lost challenge token")
			}
		case 4:
			payload = v2OwnedChild
			if r.Header.Get("Authorization") != "Bearer owned-token" {
				t.Fatal("selected child request lost challenge token")
			}
		default:
			t.Fatal("unexpected extra manifest request")
		}
		body := &trackedResponseBody{reader: strings.NewReader(payload)}
		bodies = append(bodies, body)
		return &http.Response{StatusCode: status, Header: header, Body: body, Request: r}, nil
	})}
	meta, err := inspectManifestViaV2(t.Context(), client, "registry.example/acme/api@sha256:index", "initial-token", "linux/amd64")
	if err != nil || meta == nil {
		t.Fatal("valid manifest challenge/index/child sequence failed")
	}
	assertV2ManifestChallengeResult(t, meta, paths, bodies)
}

func assertV2ManifestChallengeResult(t *testing.T, meta *ManifestMetadata, paths []string, bodies []*trackedResponseBody) {
	t.Helper()
	if strings.Join(paths, ",") != "/v2/acme/api/manifests/sha256:index,/token,/v2/acme/api/manifests/sha256:index,/v2/acme/api/manifests/sha256:child" || bodies[len(bodies)-1].closed != 1 {
		t.Fatal("challenge retry or child selection request sequence changed")
	}
	if meta.IndexDigest != "sha256:index" || meta.ManifestDigest != "sha256:child" || meta.SelectedPlatform != "linux/amd64" || meta.TotalSizeBytes != 7 || meta.ImageRef != "registry.example/acme/api@sha256:index" {
		t.Fatal("parent/child digest fallback or metadata overlays changed")
	}
}

func TestV2ManifestChallengeRetriesOnlyOnce(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		status, payload := http.StatusUnauthorized, ""
		header := make(http.Header)
		header.Set("WWW-Authenticate", `Bearer realm="https://registry.example/token"`)
		if r.URL.Path == "/token" {
			status, payload = http.StatusOK, `{"token":"owned-token"}`
		}
		if calls > 3 {
			t.Fatal("manifest challenge exceeded one retry")
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(payload)), Request: r}, nil
	})}
	meta, err := inspectManifestViaV2(t.Context(), client, "registry.example/acme/api:latest", "", "")
	if err == nil || meta != nil || calls != 3 {
		t.Fatal("repeated unauthorized response did not stop after one challenge grant")
	}
}

func TestV2FailedTokenStopsManifestRetry(t *testing.T) {
	for _, fault := range []string{"read", "close", "overflow"} {
		t.Run(fault, func(t *testing.T) { checkV2FailedTokenStopsRetry(t, fault) })
	}
}

func checkV2FailedTokenStopsRetry(t *testing.T, fault string) {
	t.Helper()
	body := faultResponseBody(`{"token":"must-not-use"}`, fault, 1<<20)
	calls := 0
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		header := make(http.Header)
		if calls == 1 {
			header.Set("WWW-Authenticate", `Bearer realm="https://registry.example/token"`)
			return &http.Response{StatusCode: http.StatusUnauthorized, Header: header, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		}
		if r.URL.Path != "/token" || calls != 2 {
			t.Fatal("failed grant token was used for a manifest retry")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: body, Request: r}, nil
	})}
	meta, err := inspectManifestViaV2(t.Context(), client, "registry.example/acme/api:latest", "", "")
	assertResponseFailed(t, err, body, fault)
	if meta != nil || calls != 2 {
		t.Fatal("failed token grant exposed manifest metadata")
	}
}

type v2SelectionCase struct {
	name, manifests, platform, digest, selected, architectures string
	wantErr                                                    bool
}

func v2SelectionCases() []v2SelectionCase {
	const amd64 = `{"digest":"sha256:first","platform":{"os":"linux","architecture":"amd64"}}`
	const second = `{"digest":"sha256:second","platform":{"os":"linux","architecture":"amd64"}}`
	const arm64 = `{"digest":"sha256:arm","platform":{"os":"linux","architecture":"arm64","variant":"v8"}}`
	return []v2SelectionCase{
		{"first-matching-in-source-order", amd64 + "," + second, " linux/amd64 ", "sha256:first", "linux/amd64", "linux/amd64,linux/amd64", false},
		{"exact-variant", amd64 + "," + arm64, "linux/arm64/v8", "sha256:arm", "linux/arm64/v8", "linux/amd64,linux/arm64/v8", false},
		{"missing-variant-not-selected", arm64, "linux/arm64", "", "", "", true},
		{"blank-single-fallback", arm64, " ", "sha256:arm", "linux/arm64/v8", "linux/arm64/v8", false},
		{"blank-multiple-requires-selection", amd64 + "," + arm64, "", "", "", "", true},
		{"missing-first-digest-skipped", `{"platform":{"os":"linux","architecture":"amd64"}},` + second, "linux/amd64", "sha256:second", "linux/amd64", "linux/amd64,linux/amd64", false},
		{"single-missing-platform", `{"digest":"sha256:first"}`, "", "sha256:first", "", "", false},
		{"invalid-unused-size", `{"digest":"sha256:first","size":"invalid"}`, "", "", "", "", true},
		{"invalid-unused-media-type", `{"digest":"sha256:first","mediaType":12}`, "", "", "", "", true},
		{"invalid-unused-annotations", `{"digest":"sha256:first","annotations":{"key":12}}`, "", "", "", "", true},
		{"empty-index", "", "linux/amd64", "", "", "", true},
		{"unsupported-platform", amd64, "windows/amd64", "", "", "", true},
	}
}

func checkV2ManifestSelection(t *testing.T, test v2SelectionCase) {
	t.Helper()
	childCalls := 0
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		header := make(http.Header)
		payload := v2OwnedChild
		if r.URL.Path == "/v2/acme/api/manifests/sha256:index" {
			header.Set("Content-Type", "application/vnd.oci.image.index.v1+json; charset=utf-8")
			payload = `{"schemaVersion":2,"manifests":[` + test.manifests + `]}`
		} else {
			childCalls++
			if r.URL.Path != "/v2/acme/api/manifests/"+test.digest {
				t.Fatal("selection changed manifest source order/platform or fetched an unexpected child")
			}
		}
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(payload)), Request: r}, nil
	})}
	meta, err := inspectManifestViaV2(t.Context(), client, "registry.example/acme/api@sha256:index", "", test.platform)
	if test.wantErr {
		if err == nil || meta != nil || childCalls != 0 {
			t.Fatal("unresolved platform produced metadata or fetched a child")
		}
		return
	}
	if err != nil || meta == nil {
		t.Fatal("compatible manifest selection failed")
	}
	if childCalls != 1 || meta.ManifestDigest != test.digest || meta.IndexDigest != "sha256:index" || meta.SelectedPlatform != test.selected || strings.Join(meta.Architectures, ",") != test.architectures {
		t.Fatal("selected platform, architecture order or digest fallback changed")
	}
}

func TestV2ManifestSelectionCompatibility(t *testing.T) {
	for _, test := range v2SelectionCases() {
		t.Run(test.name, func(t *testing.T) { checkV2ManifestSelection(t, test) })
	}
}

func v2SelectedChildClient(t *testing.T, body *trackedResponseBody, status int) *http.Client {
	t.Helper()
	return &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		header := make(http.Header)
		if r.URL.Path == "/v2/acme/api/manifests/sha256:index" {
			return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(v2OwnedIndex)), Request: r}, nil
		}
		if r.URL.Path != "/v2/acme/api/manifests/sha256:child" {
			t.Fatal("selected child failure triggered an unexpected auth grant or alternate request")
		}
		header.Set("WWW-Authenticate", `Bearer realm="https://registry.example/token"`)
		return &http.Response{StatusCode: status, Header: header, Body: body, Request: r}, nil
	})}
}

func TestV2SelectedChildFailureWithholdsParentMetadata(t *testing.T) {
	for _, fault := range []string{"read", "close", "overflow"} {
		t.Run(fault, func(t *testing.T) {
			body := faultResponseBody(v2OwnedChild, fault, 8<<20)
			meta, err := inspectManifestViaV2(t.Context(), v2SelectedChildClient(t, body, http.StatusOK), "registry.example/acme/api@sha256:index", "", "linux/amd64")
			assertResponseFailed(t, err, body, fault)
			if meta != nil {
				t.Fatal("failed child response exposed partial parent metadata")
			}
		})
	}
}

func TestV2SelectedChildUnauthorizedDoesNotAddChallengeRetry(t *testing.T) {
	body := &trackedResponseBody{reader: strings.NewReader("")}
	meta, err := inspectManifestViaV2(t.Context(), v2SelectedChildClient(t, body, http.StatusUnauthorized), "registry.example/acme/api@sha256:index", "owned-token", "linux/amd64")
	if err == nil || meta != nil || body.closed != 1 {
		t.Fatal("unauthorized selected child response was accepted or not closed")
	}
}
