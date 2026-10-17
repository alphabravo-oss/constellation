package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const oidcResponseSentinel = "private-provider-response-sentinel"

type oidcTestBody struct {
	reader            io.Reader
	readErr, closeErr error
	readBytes, closes int
}

func (b *oidcTestBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.readBytes += n
	if errors.Is(err, io.EOF) && b.readErr != nil {
		return n, b.readErr
	}
	return n, err
}

func (b *oidcTestBody) Close() error {
	b.closes++
	return b.closeErr
}

type oidcResponseCase struct {
	name, body        string
	status            int
	readErr, closeErr error
	wantError         bool
}

func TestOIDCResponseBodiesBoundReadAndCheckClose(t *testing.T) {
	for _, phase := range []string{"discovery", "token"} {
		for _, tc := range []oidcResponseCase{
			{name: "success", body: `{}`, status: 200},
			{name: "exact limit", body: strings.Repeat(" ", maxOIDCResponseBytes), status: 200},
			{name: "overflow", body: strings.Repeat(" ", maxOIDCResponseBytes+20), status: 200, wantError: true},
			{name: "provider error", body: oidcResponseSentinel, status: 400, wantError: true},
			{name: "unexpected success status", body: `{}`, status: 201, wantError: true},
			{name: "read failure", body: `{}`, status: 200, readErr: errors.New(oidcResponseSentinel), wantError: true},
			{name: "close failure", body: `{}`, status: 200, closeErr: errors.New(oidcResponseSentinel), wantError: true},
		} {
			t.Run(phase+"/"+tc.name, func(t *testing.T) { assertOIDCResponseHandling(t, phase, tc) })
		}
	}
}

func assertOIDCResponseHandling(t *testing.T, phase string, tc oidcResponseCase) {
	t.Helper()
	body := &oidcTestBody{reader: strings.NewReader(tc.body), readErr: tc.readErr, closeErr: tc.closeErr}
	data, err := readOIDCResponse(&http.Response{StatusCode: tc.status, Body: body}, phase)
	if (err != nil) != tc.wantError || body.closes != 1 || body.readBytes > maxOIDCResponseBytes+1 {
		t.Fatalf("response handling: error=%v closes=%d bytes=%d", err != nil, body.closes, body.readBytes)
	}
	if err != nil && (data != nil || strings.Contains(err.Error(), oidcResponseSentinel)) {
		t.Fatal("failed response returned provider bytes or leaked a diagnostic")
	}
	if err == nil && string(data) != tc.body {
		t.Fatal("successful response changed")
	}
}

func TestOIDCResponseErrorsPreserveOnlyCancellationIdentity(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		body := &oidcTestBody{reader: strings.NewReader(`{}`), readErr: cause}
		_, err := readOIDCResponse(&http.Response{StatusCode: 200, Body: body}, "token")
		if !errors.Is(err, cause) || body.closes != 1 {
			t.Fatal("cancellation identity or body cleanup lost")
		}
	}
	for _, response := range []*http.Response{nil, {StatusCode: 200}} {
		if _, err := readOIDCResponse(response, "token"); err == nil {
			t.Fatal("missing provider response accepted")
		}
	}
}

func TestOIDCDiscoveryChecksBoundedCompleteJSON(t *testing.T) {
	metadata := `{"authorization_endpoint":"https://idp.example.test/authorize","token_endpoint":"https://idp.example.test/token"}`
	for _, tc := range []struct {
		name, body           string
		status, missingBytes int
		wantError            bool
	}{
		{name: "normal", body: metadata, status: 200},
		{name: "exact limit", body: metadata + strings.Repeat(" ", maxOIDCResponseBytes-len(metadata)), status: 200},
		{name: "overflow", body: metadata + strings.Repeat(" ", maxOIDCResponseBytes), status: 200, wantError: true},
		{name: "truncated HTTP body", body: metadata, status: 200, missingBytes: 7, wantError: true},
		{name: "malformed JSON", body: `{"authorization_endpoint":`, status: 200, wantError: true},
		{name: "trailing JSON", body: metadata + ` {}`, status: 200, wantError: true},
		{name: "provider error", body: oidcResponseSentinel, status: 400, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) { assertOIDCDiscoveryResponse(t, tc.body, tc.status, tc.missingBytes, tc.wantError) })
	}
}

func assertOIDCDiscoveryResponse(t *testing.T, body string, status, missingBytes int, wantError bool) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)+missingBytes))
		w.WriteHeader(status)
		if _, err := io.WriteString(w, body); err != nil && !wantError {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	client, err := NewOIDCClient(t.Context(), OIDCConfig{IssuerURL: server.URL})
	if (err != nil) != wantError || (wantError && client != nil) {
		t.Fatalf("discovery error=%v want=%v", err != nil, wantError)
	}
	if err != nil && strings.Contains(err.Error(), oidcResponseSentinel) {
		t.Fatal("provider body leaked")
	}
}

type oidcResponseTransport func(*http.Request) (*http.Response, error)

func (f oidcResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestOIDCTokenErrorsDoNotExposeProviderOrRequestData(t *testing.T) {
	for _, mode := range []string{"status", "read", "close", "malformed", "transport", "invalid URL", "overflow", "cancel"} {
		t.Run(mode, func(t *testing.T) { assertOIDCTokenErrorIsCategorical(t, mode) })
	}
}

func assertOIDCTokenErrorIsCategorical(t *testing.T, mode string) {
	t.Helper()
	body := &oidcTestBody{reader: strings.NewReader(oidcResponseSentinel)}
	status, calls := 400, 0
	switch mode {
	case "read":
		body.readErr = errors.New(oidcResponseSentinel)
	case "close":
		body.closeErr = errors.New(oidcResponseSentinel)
	case "cancel":
		body.readErr = context.Canceled
	case "malformed":
		status = 200
	case "overflow":
		status = 200
		body.reader = strings.NewReader(strings.Repeat(" ", maxOIDCResponseBytes+1))
	}
	client := &OIDCClient{provider: providerMetadata{TokenURL: "https://private-user:private-pass@idp.example.test/token?code=" + oidcResponseSentinel}}
	if mode == "invalid URL" {
		client.provider.TokenURL += "\x7f"
	}
	client.http = &http.Client{Transport: oidcResponseTransport(func(*http.Request) (*http.Response, error) {
		calls++
		if mode == "transport" {
			return nil, errors.New(oidcResponseSentinel)
		}
		return &http.Response{StatusCode: status, Body: body}, nil
	})}
	claims, token, err := client.Exchange(t.Context(), "code", "verifier", "nonce")
	if err == nil || claims != nil || token != "" {
		t.Fatal("failed exchange returned identity")
	}
	for _, sentinel := range []string{oidcResponseSentinel, "private-user", "private-pass", "idp.example.test"} {
		if strings.Contains(err.Error(), sentinel) {
			t.Fatal("provider/request data escaped error boundary")
		}
	}
	if mode == "invalid URL" && calls != 0 {
		t.Fatal("invalid URL reached transport")
	}
	if mode == "cancel" && !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation identity lost")
	}
}

func TestOIDCDiscoveryRequestErrorsAreCategorical(t *testing.T) {
	_, err := NewOIDCClient(t.Context(), OIDCConfig{IssuerURL: "https://private-user:private-pass@idp.example.test/" + oidcResponseSentinel + "\x7f"})
	if err == nil || strings.Contains(err.Error(), oidcResponseSentinel) || strings.Contains(err.Error(), "private-pass") {
		t.Fatal("invalid discovery URL leaked or succeeded")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = NewOIDCClient(ctx, OIDCConfig{IssuerURL: "https://idp.example.test"})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("discovery cancellation identity lost")
	}
}
