package server

import (
	_ "embed"
	"encoding/json"
	"sync"
)

//go:embed routepolicy.json
var routePolicyJSON []byte

var (
	routePolicyOnce sync.Once
	routePolicy     map[string]string
)

// RoutePolicy is the static "METHOD /route/pattern" -> rbac verb table
// extracted from the router (routepolicy.json, kept current by
// TestRoutePolicyTableIsCurrent). Routes mapped to "public" carry no verb gate
// (health, auth bootstrap, webhooks with their own token middleware). The Phase 2
// Connect authz interceptor reuses this table keyed by RPC procedure.
func RoutePolicy() map[string]string {
	routePolicyOnce.Do(func() {
		routePolicy = map[string]string{}
		_ = json.Unmarshal(routePolicyJSON, &routePolicy)
	})
	return routePolicy
}
