package netpolicy

import (
	"context"
	"net/http"
	"strings"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"
)

// jsonError writes the apiutil error body ({"error":{"code","message"}}) with the given status. It mirrors
// the package-internal handler.jsonError helper; each handler sub-package owns
// its own small response helpers (see docs/handler-split-plan.md).
func jsonError(w http.ResponseWriter, status int, msg string) {
	apiutil.WriteStatus(context.Background(), w, status, msg)
}

// namespaceOf returns the namespace segment of a "<namespace>/<name>" workload
// identity, or "" when the identity is not namespaced (eg. "external"). Mirrors
// the same namespace/name convention used by the shared IP resolver.
func namespaceOf(workload string) string {
	if i := strings.IndexByte(workload, '/'); i > 0 {
		return workload[:i]
	}
	return ""
}
