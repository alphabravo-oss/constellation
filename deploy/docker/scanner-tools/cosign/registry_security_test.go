package options

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/osscontainertools/docker-credential-acr/pkg/credhelper"
)

type rejectCredentialTransport struct{ calls *int }

func (r rejectCredentialTransport) RoundTrip(*http.Request) (*http.Response, error) {
	*r.calls++
	return nil, errors.New("network forbidden in credential validation proof")
}

func TestConstellationAzureLookalikesRejectedBeforeCredentialRequest(t *testing.T) {
	t.Parallel()
	calls := 0
	old := http.DefaultTransport
	http.DefaultTransport = rejectCredentialTransport{calls: &calls}
	t.Cleanup(func() { http.DefaultTransport = old })
	for _, host := range []string{"evil.azurecr.io.attacker.invalid", "registry.azurecr.cn.attacker.invalid", "registry.azurecr.de.attacker.invalid", "registry.azurecr.us.attacker.invalid", "registry.azurecr.io@attacker.invalid", "azurecr.io", "example.invalid"} {
		t.Run(host, func(t *testing.T) {
			username, password, err := credhelper.NewACRCredentialsHelper().Get(host)
			if err == nil || !strings.Contains(err.Error(), "does not refer to Azure Container Registry") || username != "" || password != "" {
				t.Fatalf("lookalike was not rejected before authentication: %v", err)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("made %d credential network requests for rejected hosts", calls)
	}
}
