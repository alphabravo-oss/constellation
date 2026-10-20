package registry

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func catalogRedactionCases() []primaryReadCase {
	var cases []primaryReadCase
	for _, test := range primaryReadCases() {
		switch test.name {
		case "docker-hub", "ghcr", "generic-v2", "nexus", "openshift", "quay", "jfrog":
			cases = append(cases, test)
		}
	}
	return append(cases,
		primaryReadCase{"harbor", `[]`, 8 << 20, func(c Config) Connector { return NewHarbor(c) }},
		primaryReadCase{"gitlab", `[]`, 8 << 20, func(c Config) Connector { return NewGitLab(c) }},
	)
}

func checkCatalogResponseRedaction(t *testing.T, test primaryReadCase, fault string) {
	t.Helper()
	payload := test.payload
	if fault == "json" {
		payload = responseSecretCanary
	}
	fixture := &redactionFixture{fault: fault, payload: payload, failure: errors.New("owned catalog error " + responseSecretCanary)}
	cfg := Config{Endpoint: "https://owned.registry.example", Username: "owned-user", Password: "owned-password", Token: "owned-token", HTTPClient: fixture.client()}
	if test.name == "quay" {
		cfg.Endpoint = "owned.registry.example"
	}
	rows, err := test.build(cfg).ListImages(t.Context())
	assertCategoricalResponseError(t, err, fixture)
	if len(rows) != 0 {
		t.Fatal("failed primary catalog returned inventory rows")
	}
}

func TestPrimaryCatalogErrorsDoNotDiscloseRemoteValues(t *testing.T) {
	for _, test := range catalogRedactionCases() {
		for _, fault := range []string{"status", "transport", "read", "close", "json"} {
			t.Run(test.name+"/"+fault, func(t *testing.T) { checkCatalogResponseRedaction(t, test, fault) })
		}
	}
}

func TestDockerHubRetainsEarlierPageOnCategoricalFailure(t *testing.T) {
	for _, fault := range []string{"status", "transport", "read", "close", "json"} {
		t.Run(fault, func(t *testing.T) {
			payload := `{"results":[],"next":""}`
			if fault == "json" {
				payload = responseSecretCanary
			}
			fixture := &redactionFixture{fault: fault, payload: payload, failure: errors.New("owned catalog error " + responseSecretCanary)}
			calls := 0
			client := &http.Client{Transport: registryPageTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					body := &trackedResponseBody{reader: strings.NewReader(`{"results":[{"namespace":"owned","name":"first"}],"next":"https://hub.docker.com/owned-next"}`)}
					fixture.bodies = append(fixture.bodies, body)
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: request}, nil
				}
				return fixture.response(request)
			})}
			rows, err := NewDockerHub(Config{Username: "owned-user", Token: "owned-token", HTTPClient: client}).ListImages(t.Context())
			assertCategoricalResponseError(t, err, fixture)
			if calls != 2 || len(rows) != 1 || rows[0].Repository != "docker.io/owned/first" {
				t.Fatal("categorical failure changed prior page or continued enumeration")
			}
		})
	}
}
