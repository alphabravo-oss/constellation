package auth

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// cannedEntry is a user entry as an AD/LDAP search would return it: a DN, a mail attribute, and
// a multi-valued memberOf carrying full group DNs.
func cannedEntry() *ldap.Entry {
	return ldap.NewEntry("uid=alice,ou=people,dc=example,dc=com", map[string][]string{
		"mail": {"alice@example.com"},
		"memberOf": {
			"cn=Auditors,ou=groups,dc=example,dc=com",
			"cn=Everyone,ou=groups,dc=example,dc=com",
			"cn=SecAdmins,ou=groups,dc=example,dc=com",
		},
	})
}

func testLDAPProvider() *LDAPProvider {
	return &LDAPProvider{cfg: LDAPConfig{
		GroupAttribute: "memberOf",
		EmailAttribute: "mail",
		RoleMapping: RoleMapping{
			Rules: map[string]string{
				"auditors":  "Auditor",
				"secadmins": "SecurityAdmin",
			},
		},
	}}
}

func TestLDAP_EntryGroupMap(t *testing.T) {
	p := testLDAPProvider()
	id := p.identityFromEntry(cannedEntry())

	if id.DN != "uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("dn: %q", id.DN)
	}
	if id.Email != "alice@example.com" {
		t.Fatalf("email: %q", id.Email)
	}
	// memberOf DNs are reduced to CNs.
	wantGroups := []string{"Auditors", "Everyone", "SecAdmins"}
	if len(id.Groups) != len(wantGroups) {
		t.Fatalf("groups: %v", id.Groups)
	}
	for i := range wantGroups {
		if id.Groups[i] != wantGroups[i] {
			t.Fatalf("groups[%d]=%q want %q", i, id.Groups[i], wantGroups[i])
		}
	}
	// "Everyone" has no rule; case-insensitive match on the other two.
	want := []string{"Auditor", "SecurityAdmin"}
	if len(id.Roles) != len(want) {
		t.Fatalf("roles: %v", id.Roles)
	}
	for i := range want {
		if id.Roles[i] != want[i] {
			t.Fatalf("roles[%d]=%q want %q (%v)", i, id.Roles[i], want[i], id.Roles)
		}
	}
}

func TestLDAP_EmailFallsBackToDN(t *testing.T) {
	p := &LDAPProvider{cfg: LDAPConfig{GroupAttribute: "memberOf"}} // no EmailAttribute
	id := p.identityFromEntry(cannedEntry())
	if id.Email != id.DN {
		t.Fatalf("email %q should fall back to DN %q", id.Email, id.DN)
	}
}

func TestLDAP_BareGroupName(t *testing.T) {
	// Some directories store memberOf as a bare CN rather than a DN.
	e := ldap.NewEntry("uid=bob,dc=x", map[string][]string{"memberOf": {"SecAdmins"}})
	p := testLDAPProvider()
	id := p.identityFromEntry(e)
	if len(id.Roles) != 1 || id.Roles[0] != "SecurityAdmin" {
		t.Fatalf("expected SecurityAdmin from bare name, got %v (groups %v)", id.Roles, id.Groups)
	}
}

func TestNewLDAPProvider_Validation(t *testing.T) {
	if _, err := NewLDAPProvider(LDAPConfig{URL: "ldap://x", BaseDN: "dc=x", UserFilter: "(uid=alice)"}); err == nil {
		t.Fatal("expected error: UserFilter without percent-s placeholder")
	}
	if _, err := NewLDAPProvider(LDAPConfig{URL: "ldap://x", BaseDN: "dc=x", UserFilter: "(uid=%s)"}); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}
