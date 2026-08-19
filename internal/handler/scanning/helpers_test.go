package scanning

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// withRouteParam mirrors the package-internal test helper in internal/handler;
// copied here so the moved scanning tests are self-contained.
func withRouteParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.RouteContext(r.Context())
	if rctx == nil {
		rctx = chi.NewRouteContext()
	}
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
