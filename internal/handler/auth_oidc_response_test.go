//go:build integration

package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	authpkg "github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

const oidcCallbackResponseSentinel = "private-callback-response-sentinel"

type oidcCallbackFixture struct {
	handler  *Auth
	database *db.DB
	user     uuid.UUID
	actorIP  string
}

func newOIDCCallbackFixture(t *testing.T, mode string) oidcCallbackFixture {
	t.Helper()
	database := openTestDB(t)
	t.Cleanup(database.Close)
	org, user := uuid.New(), uuid.New()
	identity := "oidc-response-" + user.String()
	email := identity + "@example.test"
	server := oidcCallbackTestProvider(t, mode, identity, email)
	if _, err := database.Pool().Exec(t.Context(), `INSERT INTO orgs(id,name,display_name,jit_provisioning) VALUES($1,$2,'OIDC response fixture',false)`, org, "oidc-response-"+org.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := database.Pool().Exec(context.WithoutCancel(t.Context()), `DELETE FROM orgs WHERE id=$1`, org); err != nil {
			t.Error(err)
		}
	})
	if _, err := database.Pool().Exec(t.Context(), `INSERT INTO users(id,org_id,email,display_name,oidc_issuer,oidc_subject) VALUES($1,$2,$3,'OIDC response user',$4,$5)`, user, org, email, server.URL, identity); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool().Exec(t.Context(), `INSERT INTO role_assignments(user_id,role,scope_org_id) VALUES($1,'Auditor',$2)`, user, org); err != nil {
		t.Fatal(err)
	}
	provider, err := authpkg.NewOIDCClient(t.Context(), authpkg.OIDCConfig{IssuerURL: server.URL, ClientID: "response-client", RedirectURL: "https://console.example.test/callback"})
	if err != nil {
		t.Fatal(err)
	}
	actor := uuid.New()
	ip := append(net.IP{0x20, 0x01, 0x0d, 0xb8}, actor[:12]...)
	return oidcCallbackFixture{handler: NewAuth(database, testAuthSigner(t), provider, nil, nil, audit.New(database.Pool())), database: database, user: user, actorIP: ip.String()}
}

func oidcCallbackTestProvider(t *testing.T, mode, identity, email string) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	issuer := "http://" + server.Listener.Addr().String()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": issuer, "sub": identity, "email": email, "aud": "response-client", "nonce": "response-nonce", "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()})
	token.Header["kid"] = "response-key"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"id_token": signed, "access_token": "test-only-access"})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var value any
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			value = map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"}
		case "/jwks":
			value = map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "response-key", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}}
		case "/token":
			writeOIDCCallbackToken(w, mode, string(body))
			return
		default:
			http.NotFound(w, r)
			return
		}
		if err := json.NewEncoder(w).Encode(value); err != nil {
			t.Error(err)
		}
	})
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func writeOIDCCallbackToken(w http.ResponseWriter, mode, body string) {
	switch mode {
	case "truncated":
		w.Header().Set("Content-Length", strconv.Itoa(len(body)+7))
	case "oversized":
		body += strings.Repeat(" ", (1<<20)-len(body)+1)
	case "malformed":
		body = `{"id_token":`
	case "provider error":
		w.WriteHeader(http.StatusBadRequest)
		body = oidcCallbackResponseSentinel
	}
	// A failing client may deliberately close after the bound. Its rejection is
	// asserted by the caller; a provider-side broken pipe is not a test failure.
	_, _ = io.WriteString(w, body)
}

func (f oidcCallbackFixture) callback(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/auth/oidc/callback?state=response-state&code=test-code", nil)
	request.RemoteAddr = net.JoinHostPort(f.actorIP, "1234")
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	for name, value := range map[string]string{"oidc_state": "response-state", "oidc_verifier": "response-verifier", "oidc_nonce": "response-nonce"} {
		request.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	response := httptest.NewRecorder()
	f.handler.OIDCCallback(response, request)
	return response
}

func TestOIDCCallbackFailedResponsesIssueNoSession(t *testing.T) {
	for _, mode := range []string{"truncated", "oversized", "malformed", "provider error"} {
		t.Run(mode, func(t *testing.T) { assertOIDCCallbackHasNoSession(t, mode) })
	}
}

func assertOIDCCallbackHasNoSession(t *testing.T, mode string) {
	t.Helper()
	fixture := newOIDCCallbackFixture(t, mode)
	response := fixture.callback(t)
	var sessions int
	if err := fixture.database.Pool().QueryRow(t.Context(), `SELECT count(*) FROM user_sessions WHERE user_id=$1`, fixture.user).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusUnauthorized || sessions != 0 || len(response.Result().Cookies()) != 0 {
		t.Fatalf("failed token response issued identity: status=%d sessions=%d cookies=%d", response.Code, sessions, len(response.Result().Cookies()))
	}
	var result apiutil.Body
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Error.Message != "oidc authentication failed" || strings.Contains(response.Body.String(), oidcCallbackResponseSentinel) {
		t.Fatal("callback exposed upstream diagnostic")
	}
	var failures int
	if err := fixture.database.Pool().QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='auth.login.failed' AND actor_ip=$1::inet AND after->>'reason'='oidc_exchange_failed'`, fixture.actorIP).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if failures != 1 {
		t.Fatalf("failure audit count=%d", failures)
	}
}

func TestOIDCCallbackCompleteResponseStillIssuesSession(t *testing.T) {
	fixture := newOIDCCallbackFixture(t, "valid")
	response := fixture.callback(t)
	var sessions int
	if err := fixture.database.Pool().QueryRow(t.Context(), `SELECT count(*) FROM user_sessions WHERE user_id=$1`, fixture.user).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusSeeOther || sessions != 1 || len(response.Result().Cookies()) < 2 {
		t.Fatalf("valid response rejected: status=%d sessions=%d cookies=%d", response.Code, sessions, len(response.Result().Cookies()))
	}
}
