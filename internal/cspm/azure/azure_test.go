package azure

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type fakeHTTP struct{ responses map[string]string }

func (f *fakeHTTP) Do(req *http.Request) (*http.Response, error) {
	for needle, body := range f.responses {
		if strings.Contains(req.URL.String(), needle) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader([]byte(body)))}, nil
		}
	}
	return &http.Response{StatusCode: 404, Body: io.NopCloser(bytes.NewReader(nil))}, nil
}

func TestScanRoleAssignments_FlagsOwnerToUser(t *testing.T) {
	c := &Connector{Token: "t", SubscriptionID: "sub-1", HTTP: &fakeHTTP{responses: map[string]string{
		"roleAssignments": `{"value":[
			{"name":"a1","properties":{"roleDefinitionId":"/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635","principalId":"u1","principalType":"User","scope":"/subscriptions/sub-1"}},
			{"name":"a2","properties":{"roleDefinitionId":"/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635","principalId":"sp1","principalType":"ServicePrincipal","scope":"/subscriptions/sub-1"}},
			{"name":"a3","properties":{"roleDefinitionId":"/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7","principalId":"u2","principalType":"User","scope":"/subscriptions/sub-1"}}
		]}`,
	}}}
	out, err := c.ScanRoleAssignments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Only a1 should fire: Owner + User. a2 is ServicePrincipal (skipped); a3 is Reader role (skipped).
	if len(out) != 1 {
		t.Fatalf("got %d findings: %+v", len(out), out)
	}
	if out[0].ExternalID != "azure-rbac-overprivilege-a1" {
		t.Fatalf("wrong finding: %+v", out[0])
	}
}

func TestScanStorage_FlagsAllowBlobPublicAccess(t *testing.T) {
	c := &Connector{Token: "t", SubscriptionID: "sub-1", HTTP: &fakeHTTP{responses: map[string]string{
		"storageAccounts": `{"value":[
			{"id":"/sub/x/sa1","name":"sa1","properties":{"allowBlobPublicAccess":true}},
			{"id":"/sub/x/sa2","name":"sa2","properties":{"allowBlobPublicAccess":false}}
		]}`,
	}}}
	out, err := c.ScanStorage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Resource != "/sub/x/sa1" {
		t.Fatalf("expected only sa1 flagged: %+v", out)
	}
}
