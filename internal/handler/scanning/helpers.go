package scanning

import (
	"net/http"

	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// jsonError writes a {"error": msg} JSON body with the given status. It mirrors
// the package-internal handler.jsonError helper; each handler sub-package owns
// its own small response helpers (see docs/handler-split-plan.md).
func jsonError(w http.ResponseWriter, status int, msg string) {
	httpx.WriteJSON(w, status, map[string]string{"error": msg})
}
