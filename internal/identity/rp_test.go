package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestTokenEndpointClientAuthentication(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"client_secret_basic", "client_secret_post"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				user, password, basic := r.BasicAuth()
				if method == "client_secret_basic" {
					if !basic || user != url.QueryEscape("client:one") || password != url.QueryEscape("secret+two") || r.Form.Get("client_secret") != "" {
						t.Error("confidential client did not use discovered Basic authentication")
					}
				} else if basic || r.Form.Get("client_secret") != "secret+two" {
					t.Error("external provider's client_secret_post was not preserved")
				}
				if r.Form.Get("code_verifier") != "pkce-verifier" {
					t.Error("PKCE missing")
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "signed-token"})
			}))
			defer server.Close()
			rp := RP{cfg: OIDCConfig{ClientID: "client:one", ClientSecret: "secret+two"}, meta: metadata{Token: server.URL, TokenAuthMethods: []string{method}}, client: server.Client()}
			var response map[string]string
			if err := rp.request(t.Context(), http.MethodPost, server.URL, url.Values{"client_id": {"client:one"}, "client_secret": {"secret+two"}, "code_verifier": {"pkce-verifier"}}, &response); err != nil {
				t.Fatal(err)
			}
			if response["id_token"] != "signed-token" {
				t.Fatal("token response lost")
			}
		})
	}
}
