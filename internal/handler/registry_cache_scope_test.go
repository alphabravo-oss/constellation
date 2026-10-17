package handler

import (
	"testing"

	"github.com/google/uuid"
)

func TestRegistryCredentialCacheScopeRequiresExactOwnedIdentity(t *testing.T) {
	org, siblingOrg := uuid.New(), uuid.New()
	registryID, siblingRegistry := uuid.New(), uuid.New()
	scope := registryCredentialCacheScope(org, registryID)
	if scope == "" || scope != registryCredentialCacheScope(org, registryID) {
		t.Fatal("same trusted owned identity did not retain its cache scope")
	}
	if scope == registryCredentialCacheScope(siblingOrg, registryID) || scope == registryCredentialCacheScope(org, siblingRegistry) {
		t.Fatal("sibling tenant or registry shared an owner cache scope")
	}
	for _, ids := range [][2]uuid.UUID{{uuid.Nil, registryID}, {org, uuid.Nil}, {uuid.Nil, uuid.Nil}} {
		if registryCredentialCacheScope(ids[0], ids[1]) != "" {
			t.Fatal("unknown owner established a shared credential scope")
		}
	}
}
