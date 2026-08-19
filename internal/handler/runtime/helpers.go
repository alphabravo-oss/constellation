package runtime

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// jsonError writes a {"error": msg} JSON body with the given status. It mirrors
// the package-internal handler.jsonError helper; each handler sub-package owns
// its own small response helpers (see docs/handler-split-plan.md).
func jsonError(w http.ResponseWriter, status int, msg string) {
	httpx.WriteJSON(w, status, map[string]string{"error": msg})
}

// rowScanner is satisfied by both pgx.Row and pgx.Rows. Copied from the parent
// handler package (api_tokens.go) so the runtime sub-package's scanXxx helpers
// stay self-contained.
type rowScanner interface {
	Scan(dest ...any) error
}

// normalizeIP canonicalizes an IP string (unmaps 4-in-6, strips zone). Copied
// from the parent handler package (network_flow_resolve.go) so the runtime
// sub-package stays self-contained without a cross-domain seam.
func normalizeIP(s string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	return a.WithZone("").String(), true
}

// splitNamespacedName splits "ns/name" into its parts. Copied from the parent
// handler package (network_flow_resolve.go) to keep this sub-package self-contained.
func splitNamespacedName(workload string) (ns, name string, ok bool) {
	i := strings.IndexByte(workload, '/')
	if i <= 0 || i == len(workload)-1 {
		return "", "", false
	}
	return workload[:i], workload[i+1:], true
}

// nonNilStrings returns a non-nil empty slice for nil input. Copied from the
// parent handler package (deployments.go) to keep this sub-package self-contained.
func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// deploymentWorkloadID joins namespace and name into a workload id. Copied from
// the parent handler package (deployments.go) to keep this sub-package self-contained.
func deploymentWorkloadID(namespace, name string) string {
	namespace = strings.TrimSpace(namespace)
	name = strings.TrimSpace(name)
	if namespace == "" {
		return name
	}
	if name == "" {
		return namespace
	}
	return namespace + "/" + name
}
