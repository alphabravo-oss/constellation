package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func samlBrowserTestHandler(t *testing.T) *Auth {
	t.Helper()
	provider, err := auth.NewSAMLProvider(auth.SAMLConfig{
		ACSURL: "https://console.example.com/api/v1/auth/saml/acs",
		IdPMetadataXML: []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/sso">
<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
</IDPSSODescriptor></EntityDescriptor>`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return NewAuth(nil, nil, nil, provider, nil, nil)
}

func startSAMLBrowserTestLogin(t *testing.T, handler *Auth) *http.Cookie {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://console.example.com/api/v1/auth/saml/login?relay_state=attacker-controlled", nil)
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	response := httptest.NewRecorder()
	handler.SAMLLogin(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("login = %d: %s", response.Code, response.Body.String())
	}
	redirect, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != samlBrowserCookieName || len(cookie.Value) != 43 || cookie.Value != redirect.Query().Get("RelayState") {
		t.Fatal("redirect must carry the random cookie nonce, not caller RelayState")
	}
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteNoneMode || cookie.MaxAge != 300 {
		t.Fatalf("unsafe state cookie: %s", cookie)
	}
	if !cookie.Expires.After(time.Now()) || cookie.Expires.After(time.Now().Add(samlBrowserBindingTTL)) || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("state must expire shortly and must not be cached")
	}
	return cookie
}

func samlBrowserTestACS(cookie *http.Cookie, relay string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://console.example.com/api/v1/auth/saml/acs", strings.NewReader(url.Values{
		"RelayState": {relay}, "SAMLResponse": {"secret-assertion"},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://idp.example.com")
	if cookie != nil {
		request.AddCookie(cookie)
	}
	return request
}

func assertSAMLBrowserCookieCleared(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == samlBrowserCookieName && cookie.Value == "" && cookie.MaxAge == -1 && cookie.Secure && cookie.HttpOnly && cookie.SameSite == http.SameSiteNoneMode {
			return
		}
	}
	t.Fatal("browser binding cookie not securely cleared")
}

func TestSAMLBrowserBindingRejectsBeforeAssertionParsing(t *testing.T) {
	for _, scenario := range []string{"unsolicited", "missing-cookie", "wrong-browser", "missing-relay", "query-only-relay", "duplicate-relay", "duplicate-cookie", "unknown-state", "expired", "oversized", "malformed-form", "artifact", "duplicate-assertion"} {
		t.Run(scenario, func(t *testing.T) {
			handler := samlBrowserTestHandler(t)
			cookie := startSAMLBrowserTestLogin(t, handler)
			request := samlBrowserTestACS(cookie, cookie.Value)
			want := http.StatusForbidden
			switch scenario {
			case "unsolicited":
				request = samlBrowserTestACS(nil, "")
			case "missing-cookie":
				request.Header.Del("Cookie")
			case "wrong-browser":
				other := startSAMLBrowserTestLogin(t, handler)
				if other.Value == cookie.Value {
					t.Fatal("nonce reused")
				}
				request = samlBrowserTestACS(cookie, other.Value)
			case "missing-relay":
				request = samlBrowserTestACS(cookie, "")
			case "query-only-relay":
				request = samlBrowserTestACS(cookie, "")
				request.URL.RawQuery = url.Values{"RelayState": {cookie.Value}}.Encode()
			case "duplicate-relay":
				request = httptest.NewRequest(http.MethodPost, request.URL.String(), strings.NewReader("SAMLResponse=secret-assertion&RelayState="+cookie.Value+"&RelayState="+cookie.Value))
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.AddCookie(cookie)
			case "duplicate-cookie":
				request.AddCookie(cookie)
			case "unknown-state":
				handler.samlBrowserBindings.discard(cookie.Value)
			case "expired":
				handler.samlBrowserBindings.mu.Lock()
				handler.samlBrowserBindings.pending[cookie.Value] = time.Now().Add(-time.Second)
				handler.samlBrowserBindings.mu.Unlock()
			case "oversized":
				request = httptest.NewRequest(http.MethodPost, request.URL.String(), strings.NewReader(strings.Repeat("x", samlACSBodyLimit+1)))
				request.ContentLength = -1
				request.AddCookie(cookie)
				want = http.StatusRequestEntityTooLarge
			case "malformed-form":
				request = httptest.NewRequest(http.MethodPost, request.URL.String(), strings.NewReader("RelayState=%zz&secret=password"))
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.AddCookie(cookie)
				want = http.StatusBadRequest
			case "artifact":
				request.URL.RawQuery = "SAMLart=secret-artifact"
				want = http.StatusBadRequest
			case "duplicate-assertion":
				request = httptest.NewRequest(http.MethodPost, request.URL.String(), strings.NewReader("RelayState="+cookie.Value+"&SAMLResponse=one&SAMLResponse=two"))
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.AddCookie(cookie)
				want = http.StatusBadRequest
			}
			handler.setSAMLParseFunc(func(*http.Request) (*auth.AssertionIdentity, error) {
				t.Fatal("unbound or malformed ACS reached assertion parser")
				return nil, errors.New("secret assertion")
			})
			response := httptest.NewRecorder()
			handler.SAMLACS(response, request)
			if response.Code != want {
				t.Fatalf("status = %d, want %d: %s", response.Code, want, response.Body.String())
			}
			assertSAMLBrowserCookieCleared(t, response)
			if strings.Contains(response.Body.String(), "secret") || strings.Contains(response.Body.String(), "password") {
				t.Fatal("error discloses submitted content")
			}
			if request.Header.Get("Cookie") != "" && handler.samlBrowserBindings.consume(cookie.Value, cookie.Value) {
				t.Fatal("failed request left cookie binding reusable")
			}
		})
	}
}

func TestSAMLBrowserBindingSingleUseAndRedactedParserError(t *testing.T) {
	handler := samlBrowserTestHandler(t)
	cookie := startSAMLBrowserTestLogin(t, handler)
	var calls atomic.Int32
	handler.setSAMLParseFunc(func(*http.Request) (*auth.AssertionIdentity, error) {
		calls.Add(1)
		return nil, errors.New("raw assertion secret=password https://user:password@idp.example.com")
	})
	var workers sync.WaitGroup
	for attempt := 0; attempt < 8; attempt++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			response := httptest.NewRecorder()
			handler.SAMLACS(response, samlBrowserTestACS(cookie, cookie.Value))
			if response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden {
				t.Errorf("unexpected status: %d", response.Code)
			}
			assertSAMLBrowserCookieCleared(t, response)
			if strings.Contains(response.Body.String(), "password") || strings.Contains(response.Body.String(), "assertion") {
				t.Error("raw parser error disclosed")
			}
		}()
	}
	workers.Wait()
	if calls.Load() != 1 {
		t.Fatalf("parser calls = %d, want 1", calls.Load())
	}
}

func TestSAMLBrowserBindingDoesNotBypassRealParser(t *testing.T) {
	handler := samlBrowserTestHandler(t)
	cookie := startSAMLBrowserTestLogin(t, handler)
	response := httptest.NewRecorder()
	handler.SAMLACS(response, samlBrowserTestACS(cookie, cookie.Value))
	if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "secret-assertion") {
		t.Fatalf("invalid assertion accepted or disclosed: %d %s", response.Code, response.Body.String())
	}
	assertSAMLBrowserCookieCleared(t, response)
}

func TestSAMLBrowserBindingSessionAndCLICompatibility(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	orgID, userID := uuid.New(), uuid.New()
	subject := "saml-binding-" + uuid.NewString() + "@example.com"
	if _, err := pool.Exec(context.Background(), `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'SAML binding')`, orgID, "saml-binding-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })
	if _, err := pool.Exec(context.Background(), `INSERT INTO users (id, org_id, email, display_name, oidc_issuer, oidc_subject) VALUES ($1, $2, $3, 'SAML binding', 'https://idp.example.com/sso', $3)`, userID, orgID, subject); err != nil {
		t.Fatal(err)
	}
	handler := samlBrowserTestHandler(t)
	handler.db, handler.signer, handler.auditLog = database, testAuthSigner(t), audit.New(pool)
	handler.setSAMLParseFunc(func(*http.Request) (*auth.AssertionIdentity, error) {
		return &auth.AssertionIdentity{Issuer: "https://idp.example.com/sso", Subject: subject, Email: subject}, nil
	})
	cookie := startSAMLBrowserTestLogin(t, handler)
	response := httptest.NewRecorder()
	request := samlBrowserTestACS(cookie, cookie.Value)
	request.Header.Del("Origin")
	handler.SAMLACS(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/clusters" || strings.Contains(response.Body.String(), `"token"`) {
		t.Fatalf("browser login = %d: %s", response.Code, response.Body.String())
	}
	assertSAMLBrowserCookieCleared(t, response)
	var accessCookie, refreshCookie bool
	for _, issued := range response.Result().Cookies() {
		if issued.Name == auth.AccessCookie {
			claims, err := handler.signer.Verify(issued.Value)
			if err != nil || claims.UserID != userID || claims.OrgID != orgID {
				t.Fatalf("browser access identity: %v / %v", claims, err)
			}
			accessCookie = true
		}
		if issued.Name == auth.RefreshCookie && issued.Value != "" {
			refreshCookie = true
		}
	}
	if !accessCookie || !refreshCookie {
		t.Fatal("browser session cookies missing")
	}
	response = httptest.NewRecorder()
	handler.SAMLACS(response, httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acs", nil))
	if response.Code != http.StatusOK || len(response.Result().Cookies()) != 0 {
		t.Fatalf("CLI ACS = %d: %s", response.Code, response.Body.String())
	}
	claims, err := handler.signer.Verify(decodeToken(t, response))
	if err != nil || claims.UserID != userID {
		t.Fatalf("CLI bearer identity: %v / %v", claims, err)
	}
	response = httptest.NewRecorder()
	handler.SAMLLogin(response, httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/login?relay_state=cli-state", nil))
	redirect, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != http.StatusFound || redirect.Query().Get("RelayState") != "cli-state" || len(response.Result().Cookies()) != 0 {
		t.Fatalf("CLI login changed: %d %v", response.Code, err)
	}
}
