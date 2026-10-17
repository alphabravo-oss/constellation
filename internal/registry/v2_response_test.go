package registry

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type v2ResponseCase struct {
	name    string
	payload string
	limit   int
	call    func(*testing.T, *http.Client) (bool, error)
}

func v2ResponseCases() []v2ResponseCase {
	return []v2ResponseCase{
		{"manifest", `{"schemaVersion":2}`, 8 << 20, func(t *testing.T, client *http.Client) (bool, error) {
			body, digest, mediaType, err := getManifestBody(t.Context(), client, "https://registry.example/manifest", manifestAccept, "")
			return len(body) != 0 || digest != "" || mediaType != "", err
		}},
		{"digest", "manifest body", 8 << 20, func(t *testing.T, client *http.Client) (bool, error) {
			digest, err := getManifestDigest(t.Context(), client, "https://registry.example/manifest", manifestAccept, "")
			return digest != "", err
		}},
		{"tags", `{"tags":["v1"]}`, 4 << 20, func(t *testing.T, client *http.Client) (bool, error) {
			tags, next, err := getTagsPage(t.Context(), client, "https://registry.example/tags", "")
			return len(tags) != 0 || next != "", err
		}},
		{"token", `{"token":"owned-token"}`, 1 << 20, func(t *testing.T, client *http.Client) (bool, error) {
			token, err := fetchTokenFromChallenge(t.Context(), client, `Bearer realm="https://registry.example/token"`)
			return token != "", err
		}},
	}
}

func v2ResponseClient(body io.ReadCloser, status int) *http.Client {
	return &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("Docker-Content-Digest", "sha256:owned")
		header.Set("Content-Type", "application/json")
		header.Set("Link", `</next>; rel="next"`)
		header.Set("WWW-Authenticate", `Bearer realm="https://registry.example/token"`)
		return &http.Response{StatusCode: status, Header: header, Body: body, Request: r}, nil
	})}
}

func checkV2ResponseFailure(t *testing.T, test v2ResponseCase, fault string) {
	t.Helper()
	body := faultResponseBody(test.payload, fault, test.limit)
	accepted, err := test.call(t, v2ResponseClient(body, http.StatusOK))
	assertResponseFailed(t, err, body, fault)
	if accepted {
		t.Fatal("failed response exposed a body, digest, token, tags or continuation")
	}
}

func TestV2ResponseFailuresNeverExposeSuccessfulData(t *testing.T) {
	for _, test := range v2ResponseCases() {
		for _, fault := range []string{"read", "close", "overflow"} {
			t.Run(test.name+"/"+fault, func(t *testing.T) { checkV2ResponseFailure(t, test, fault) })
		}
	}
}

func TestV2ResponseExactBoundsRemainAccepted(t *testing.T) {
	for _, test := range v2ResponseCases() {
		t.Run(test.name, func(t *testing.T) {
			payload := test.payload + strings.Repeat(" ", test.limit-len(test.payload))
			body := &trackedResponseBody{reader: strings.NewReader(payload)}
			accepted, err := test.call(t, v2ResponseClient(body, http.StatusOK))
			if err != nil || !accepted || body.closed != 1 {
				t.Fatal("complete response at the byte limit was not accepted and closed exactly once")
			}
		})
	}
}

func TestV2ResponseStatusFailureClosesAndWithholdsData(t *testing.T) {
	for _, test := range v2ResponseCases() {
		t.Run(test.name, func(t *testing.T) {
			body := &trackedResponseBody{reader: strings.NewReader(test.payload)}
			accepted, err := test.call(t, v2ResponseClient(body, http.StatusServiceUnavailable))
			if err == nil || accepted || body.closed != 1 {
				t.Fatal("status failure exposed response data or left its body open")
			}
		})
	}
}

func TestV2TokenRequiresCompleteSingleDocument(t *testing.T) {
	for _, payload := range []string{`{"token":"owned-token"} {}`, `{"token":"owned-token"} trailing`, `{"token":`} {
		t.Run(payload, func(t *testing.T) {
			body := &trackedResponseBody{reader: strings.NewReader(payload)}
			token, err := fetchTokenFromChallenge(t.Context(), v2ResponseClient(body, http.StatusOK), `Bearer realm="https://registry.example/token"`)
			if err == nil || token != "" || body.closed != 1 {
				t.Fatal("incomplete or trailing token document was accepted")
			}
		})
	}
}

func TestV2TokenFieldCompatibility(t *testing.T) {
	for _, test := range []struct{ name, payload, want string }{
		{"preferred-token", `{"token":"owned-token","access_token":"owned-access"}`, "owned-token"},
		{"access-token-fallback", `{"access_token":"owned-access","expires_in":60}`, "owned-access"},
		{"empty-fields", `{}`, ""},
		{"trailing-whitespace", "{\"token\":\"owned-token\"}\n\t ", "owned-token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &trackedResponseBody{reader: strings.NewReader(test.payload)}
			token, err := fetchTokenFromChallenge(t.Context(), v2ResponseClient(body, http.StatusOK), `Bearer realm="https://registry.example/token"`)
			if err != nil || token != test.want || body.closed != 1 {
				t.Fatal("compatible token fields changed or response was not closed")
			}
		})
	}
}

func TestV2HEADCloseFailureStopsDigestAndGETFallback(t *testing.T) {
	for _, digest := range []string{"", "sha256:owned"} {
		t.Run("digest="+digest, func(t *testing.T) {
			body := faultResponseBody("", "close", 0)
			calls := 0
			client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodHead {
					t.Fatal("GET dispatched after HEAD close failure")
				}
				header := make(http.Header)
				header.Set("Docker-Content-Digest", digest)
				return &http.Response{StatusCode: http.StatusOK, Header: header, Body: body, Request: r}, nil
			})}
			got, err := headManifest(t.Context(), client, "https://registry.example/manifest", manifestAccept, "")
			assertResponseFailed(t, err, body, "close")
			if got != "" || calls != 1 {
				t.Fatal("failed HEAD published a digest or dispatched another request")
			}
		})
	}
}

func TestV2HEADClosesBeforeGETFallback(t *testing.T) {
	head := &trackedResponseBody{reader: strings.NewReader("")}
	get := &trackedResponseBody{reader: strings.NewReader("non-JSON body with valid digest header")}
	var methods []string
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		methods = append(methods, r.Method)
		header := make(http.Header)
		var body io.ReadCloser = head
		if r.Method == http.MethodGet {
			if head.closed != 1 {
				t.Fatal("GET dispatched before HEAD closed")
			}
			body = get
			header.Set("Docker-Content-Digest", "sha256:owned")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: body, Request: r}, nil
	})}
	digest, err := headManifest(t.Context(), client, "https://registry.example/manifest", manifestAccept, "")
	if err != nil || digest != "sha256:owned" || strings.Join(methods, ",") != "HEAD,GET" || get.closed != 1 {
		t.Fatal("bounded GET fallback changed digest behavior or request lifecycle")
	}
}

type v2CountingReader struct {
	reader io.Reader
	bytes  int
}

func (r *v2CountingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytes += n
	return n, err
}

func TestV2MissingDigestDrainIsBoundedAndChecked(t *testing.T) {
	const limit = 8 << 20
	reader := &v2CountingReader{reader: strings.NewReader(strings.Repeat("x", limit+100))}
	body := &trackedResponseBody{reader: reader}
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: r}, nil
	})}
	digest, err := getManifestDigest(t.Context(), client, "https://registry.example/manifest", manifestAccept, "")
	if err == nil || digest != "" || reader.bytes != limit+1 || body.closed != 1 {
		t.Fatal("missing-digest response was not bounded and closed")
	}
}

func TestV2MissingDigestPropagatesLateReadFailure(t *testing.T) {
	body := faultResponseBody("manifest body", "read", 8<<20)
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: r}, nil
	})}
	digest, err := getManifestDigest(t.Context(), client, "https://registry.example/manifest", manifestAccept, "")
	if digest != "" || !errors.Is(err, errResponseTransportFailure) || body.closed != 1 {
		t.Fatal("missing-digest drain discarded its read failure")
	}
}

func TestV2ResponsesRejectOneByteOverLimit(t *testing.T) {
	for _, test := range v2ResponseCases() {
		t.Run(test.name, func(t *testing.T) {
			payload := test.payload + strings.Repeat(" ", test.limit-len(test.payload)+1)
			body := &trackedResponseBody{reader: strings.NewReader(payload)}
			accepted, err := test.call(t, v2ResponseClient(body, http.StatusOK))
			if err == nil || accepted || body.closed != 1 {
				t.Fatal("one-byte overflow returned successful data or left the body open")
			}
		})
	}
}
