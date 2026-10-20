package compliance

import (
	"context"
	"net/http"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"
)

// jsonError writes the apiutil error body ({"error":{"code","message"}}) with the given status. It mirrors
// the package-internal handler.jsonError helper; each handler sub-package owns
// its own small response helpers (see docs/handler-split-plan.md).
func jsonError(w http.ResponseWriter, status int, msg string) {
	apiutil.WriteStatus(context.Background(), w, status, msg)
}

// rowScanner is the common subset of pgx.Row / pgx.Rows used by the schedule/run
// scanners. It mirrors the package-internal handler.rowScanner; each sub-package
// owns its own copy so it has no cross-package dependency on the interface.
type rowScanner interface {
	Scan(dest ...any) error
}
