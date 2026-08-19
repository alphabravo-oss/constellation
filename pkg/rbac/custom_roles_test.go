package rbac

import (
	"testing"

	"github.com/google/uuid"
)

func TestAuthorizeWithCustom(t *testing.T) {
	org := uuid.New()
	asg := []RoleAssignment{{Role: "vuln-viewer", Scope: Scope{OrgID: org}}}
	res := Resource{OrgID: org}
	// A custom role with a user-grantable verb AND a smuggled-in service verb.
	custom := map[string][]Verb{"vuln-viewer": {VerbReadFindings, VerbRuntimeIngest}}

	if err := AuthorizeWithCustom(asg, VerbReadFindings, res, custom); err != nil {
		t.Fatalf("custom role should grant read-findings: %v", err)
	}
	// Defense-in-depth: a custom role must NEVER grant a service-only verb,
	// even when the row lists it.
	if err := AuthorizeWithCustom(asg, VerbRuntimeIngest, res, custom); err == nil {
		t.Fatal("custom role must NOT grant service-only runtime-ingest")
	}
	// A verb not in the custom set is not granted.
	if err := AuthorizeWithCustom(asg, VerbManageOrg, res, custom); err == nil {
		t.Fatal("custom role without manage-org should not grant it")
	}
	// nil custom map behaves exactly like Authorize.
	if err := AuthorizeWithCustom(asg, VerbReadFindings, res, nil); err == nil {
		t.Fatal("unknown role with nil custom map should be forbidden")
	}
}
