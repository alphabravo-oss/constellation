package netpolicy

import (
	"net/http"
	"strings"

	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// jsonError writes a {"error": msg} JSON body with the given status. It mirrors
// the package-internal handler.jsonError helper; each handler sub-package owns
// its own small response helpers (see docs/handler-split-plan.md).
func jsonError(w http.ResponseWriter, status int, msg string) {
	httpx.WriteJSON(w, status, map[string]string{"error": msg})
}

// namespaceOf returns the namespace segment of a "<namespace>/<name>" workload
// identity, or "" when the identity is not namespaced (eg. "external"). Mirrors
// the parent handler's splitNamespacedName without exporting it.
func namespaceOf(workload string) string {
	if i := strings.IndexByte(workload, '/'); i > 0 {
		return workload[:i]
	}
	return ""
}
