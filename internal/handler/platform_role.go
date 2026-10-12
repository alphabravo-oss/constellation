package handler

import (
	"encoding/json"
	"github.com/alphabravocompany/constellation/internal/handler/platformrole"
)

func PlatformRole(namespace string, labels map[string]string) string {
	return platformrole.PlatformRole(namespace, labels)
}
func PlatformRoleJSON(namespace string, labels json.RawMessage) string {
	return platformrole.PlatformRoleJSON(namespace, labels)
}
func platformRoleSQL(namespace, labels string) string { return platformrole.SQL(namespace, labels) }

// Preserve the package-local policy inventory used by classification parity tests.
var platformNamespaces = platformrole.Namespaces()
