package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// The fault is after a complete, legitimately signed token JSON document. The
// old ignored read/close errors accepted that identity, so malformed-token-only
// coverage cannot detect this boundary.
func TestOIDCTokenRejectsIncompleteSignedResponse(t *testing.T) {
	for _, mode := range []string{"trailing read error", "close error", "over limit", "truncated JSON"} {
		t.Run(mode, func(t *testing.T) { assertSignedOIDCResponseFails(t, mode) })
	}
}

func assertSignedOIDCResponseFails(t *testing.T, mode string) {
	t.Helper()
	server, _ := fakeIdP(t)
	t.Cleanup(server.Close)
	client, err := NewOIDCClient(t.Context(), OIDCConfig{IssuerURL: server.URL, ClientID: "client-test", RedirectURL: "http://localhost/callback"})
	if err != nil {
		t.Fatal(err)
	}
	claims, access, err := client.Exchange(t.Context(), "code", "verifier", fakeIdPNonce)
	if err != nil || claims == nil || claims.Subject != "user-42" || access != "test-access-token" {
		t.Fatal("valid signed baseline rejected")
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/token", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.http.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := readOIDCResponse(response, "token")
	if err != nil {
		t.Fatal(err)
	}
	data := strings.TrimSpace(string(raw))
	body := &oidcTestBody{reader: strings.NewReader(data)}
	switch mode {
	case "trailing read error":
		body.readErr = errors.New(oidcResponseSentinel)
	case "close error":
		body.closeErr = errors.New(oidcResponseSentinel)
	case "over limit":
		body.reader = strings.NewReader(data + strings.Repeat(" ", maxOIDCResponseBytes-len(data)+1))
	case "truncated JSON":
		body.reader = strings.NewReader(data[:len(data)-1])
	}
	client.http.Transport = oidcResponseTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	})
	claims, access, err = client.Exchange(t.Context(), "code", "verifier", fakeIdPNonce)
	if err == nil || claims != nil || access != "" {
		t.Fatal("incomplete signed response returned an authenticated identity")
	}
	if body.closes != 1 {
		t.Fatal("failed response not closed exactly once")
	}
	if strings.Contains(err.Error(), oidcResponseSentinel) {
		t.Fatal("read/close diagnostic leaked")
	}
}
