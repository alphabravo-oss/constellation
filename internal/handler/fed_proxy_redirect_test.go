//go:build integration

package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestFedProxyRejectsRedirects(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := t.Context()
	orgID, _ := fedGroupTestOrg(t, d.Pool())
	userID := uuid.New()
	signer := fedTestSigner(t, ctx, d.Pool())
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, destination := range []string{"other-host", "same-host-forbidden-path"} {
			t.Run(fmt.Sprintf("%d/%s", status, destination), func(t *testing.T) {
				var escaped, receivedCredential atomic.Int32
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					escaped.Add(1)
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(target.Close)
				location := target.URL + "/private"
				if destination == "same-host-forbidden-path" {
					location = "/api/v1/users"
				}
				joint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/api/v1/findings" {
						escaped.Add(1)
						w.WriteHeader(http.StatusOK)
						return
					}
					if claims, err := signer.VerifySyncTicket(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); err == nil && claims.OrgID == orgID {
						receivedCredential.Add(1)
					}
					w.Header().Set("Location", location)
					w.Header().Set("Set-Cookie", "untrusted=1")
					w.WriteHeader(status)
				}))
				t.Cleanup(joint.Close)
				clusterID := insertMember(t, t.Context(), d, orgID, joint.URL)
				client := &http.Client{}
				h := NewFedProxy(d, audit.New(d.Pool())).WithFedCredentials(signer, nil).WithClient(client)
				w := forwardReq(t, h, readerSubject(orgID, userID), http.MethodGet, clusterID, "findings", "", "")
				if w.Code != http.StatusBadGateway {
					t.Fatalf("redirect status=%d body=%s", w.Code, w.Body.String())
				}
				if escaped.Load() != 0 || receivedCredential.Load() != 1 {
					t.Fatalf("redirect followed or credential not tested: escaped=%d credential=%d", escaped.Load(), receivedCredential.Load())
				}
				if w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" {
					t.Fatal("redirect response headers reached the browser")
				}
				if client.CheckRedirect != nil {
					t.Fatal("proxy mutated the shared HTTP client")
				}
				var loggedStatus, upstreamStatus int
				if err := d.Pool().QueryRow(t.Context(), `SELECT (after->>'status')::int, (after->>'upstream_status')::int FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action='federation.proxy'`, orgID, clusterID).Scan(&loggedStatus, &upstreamStatus); err != nil || loggedStatus != 502 || upstreamStatus != status {
					t.Fatalf("redirect audit missing or incorrect: status=%d upstream=%d err=%v", loggedStatus, upstreamStatus, err)
				}
			})
		}
	}
}

func TestFedProxyEndpointRejectsEmbeddedCredentialsAndFragments(t *testing.T) {
	for _, endpoint := range []string{"https://user:password@joint.example", "https://joint.example/#fragment"} {
		if _, err := fedProxyTargetURL(endpoint, "findings", ""); err == nil {
			t.Errorf("accepted ambiguous endpoint %q", endpoint)
		}
	}
	if target, err := fedProxyTargetURL("https://joint.example/prefix", "findings", "limit=10"); err != nil || target != "https://joint.example/prefix/api/v1/findings?limit=10" {
		t.Fatalf("valid endpoint: target=%q err=%v", target, err)
	}
}
