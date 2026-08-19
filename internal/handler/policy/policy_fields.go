package policy

import (
	"net/http"

	"github.com/alphabravocompany/constellation/internal/handler/httpx"

	"github.com/alphabravocompany/constellation/pkg/policy/fields"
)

// PolicyFields serves the policy criteria fields registry, used by the policy
// wizard UI to render a guided picker for each criterion.
type PolicyFields struct{}

func NewPolicyFields() *PolicyFields { return &PolicyFields{} }

// List returns the curated catalogue. The response is intentionally cacheable
// for short periods (the catalogue is process-static), so the UI can pre-fetch.
func (p *PolicyFields) List(w http.ResponseWriter, _ *http.Request) {
	all := fields.All()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"fields": all})
}
