package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alphabravocompany/constellation/internal/db"
)

func TestRemoteJoinConfigBindsImplicitCredentialToConfiguredDestination(t *testing.T) {
	const configured = "https://Master.example/federation/"
	tests := []struct {
		name            string
		request         fedJoinRemoteRequest
		configuredURL   string
		configuredToken string
		wantURL         string
		wantToken       string
		reject          bool
	}{
		{name: "environment pair", configuredURL: configured, configuredToken: "deployment-token", wantURL: "https://master.example/federation", wantToken: "deployment-token"},
		{name: "same configured destination", request: fedJoinRemoteRequest{MasterURL: "https://master.example/federation"}, configuredURL: configured, configuredToken: "deployment-token", wantURL: "https://master.example/federation", wantToken: "deployment-token"},
		{name: "explicit override pair", request: fedJoinRemoteRequest{MasterURL: "https://other.example", Token: "caller-token"}, configuredURL: configured, configuredToken: "deployment-token", wantURL: "https://other.example", wantToken: "caller-token"},
		{name: "explicit token configured URL", request: fedJoinRemoteRequest{Token: "caller-token"}, configuredURL: configured, configuredToken: "deployment-token", wantURL: "https://master.example/federation", wantToken: "caller-token"},
		{name: "different host cannot borrow token", request: fedJoinRemoteRequest{MasterURL: "https://other.example"}, configuredURL: configured, configuredToken: "deployment-token", reject: true},
		{name: "different path cannot borrow token", request: fedJoinRemoteRequest{MasterURL: "https://master.example/elsewhere"}, configuredURL: configured, configuredToken: "deployment-token", reject: true},
		{name: "different port cannot borrow token", request: fedJoinRemoteRequest{MasterURL: "https://master.example:8443/federation"}, configuredURL: configured, configuredToken: "deployment-token", reject: true},
		{name: "no configured destination cannot borrow token", request: fedJoinRemoteRequest{MasterURL: "https://other.example"}, configuredToken: "deployment-token", reject: true},
		{name: "missing token", configuredURL: configured, reject: true},
		{name: "query rejected", request: fedJoinRemoteRequest{MasterURL: "https://master.example/federation?", Token: "caller-token"}, reject: true},
		{name: "userinfo rejected", request: fedJoinRemoteRequest{MasterURL: "https://user@master.example", Token: "caller-token"}, reject: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, token, err := resolveRemoteJoinConfig(test.request, test.configuredURL, test.configuredToken)
			if test.reject {
				if err == nil || target != "" || token != "" {
					t.Fatal("unsafe configuration returned a credential")
				}
				if strings.Contains(err.Error(), "deployment-token") || strings.Contains(err.Error(), "caller-token") {
					t.Fatal("error revealed credential")
				}
				return
			}
			if err != nil || target != test.wantURL || token != test.wantToken {
				t.Fatal("valid caller/configured pair not preserved")
			}
		})
	}
}

func TestJoinRemoteNeverSendsImplicitTokenToHostileEndpoint(t *testing.T) {
	var calls atomic.Int32
	var leaked atomic.Bool
	hostile := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body fedJoinRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.JoinToken == "deployment-only-test-token" {
			leaked.Store(true)
		}
		if body.JoinToken != "explicit-caller-test-token" {
			t.Error("unexpected token at hostile receiver")
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(hostile.Close)
	// Exercise the actual handler/client with this owned TLS server, not a fake
	// transport that would overlook a request or fail at certificate validation.
	previous := http.DefaultTransport
	http.DefaultTransport = hostile.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previous })
	t.Setenv("CONSTELLATION_FED_MASTER_URL", "https://configured-master.invalid")
	t.Setenv("CONSTELLATION_FED_MASTER_TOKEN", "deployment-only-test-token")
	handler := NewFederation(&db.DB{}, nil)
	call := func(token string) *httptest.ResponseRecorder {
		body := `{"master_url":"` + hostile.URL + `","cluster_id":"owned-test-cluster","cluster_name":"owned-test-cluster"`
		if token != "" {
			body += `,"token":"` + token + `"`
		}
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/federation/join-remote", strings.NewReader(body+"}"))
		response := httptest.NewRecorder()
		handler.JoinRemote(response, request)
		return response
	}
	rejected := call("")
	if rejected.Code != http.StatusBadRequest || calls.Load() != 0 || leaked.Load() {
		t.Fatal("implicit deployment credential reached a caller-selected destination")
	}
	explicit := call("explicit-caller-test-token")
	if explicit.Code != http.StatusBadGateway || calls.Load() != 1 || leaked.Load() {
		t.Fatal("explicit caller-supplied token/destination behavior changed")
	}
}
