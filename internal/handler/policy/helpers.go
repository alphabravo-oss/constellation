package policy

import (
	"net/http"

	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// jsonError writes a {"error": msg} JSON body with the given status. It mirrors
// the package-private handler.jsonError helper the policy handlers used before
// the ARC-1 split; kept domain-local so the sub-package stays self-contained.
func jsonError(w http.ResponseWriter, status int, msg string) {
	httpx.WriteJSON(w, status, map[string]string{"error": msg})
}

// firstNonEmpty returns the first non-empty string. It is a pure-stdlib helper
// duplicated from the parent package (where several other domains still use it)
// so the policy sub-package stays self-contained without a cross-domain seam.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
