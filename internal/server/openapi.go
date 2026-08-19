package server

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/syscfg"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/observability"
)

// RouteList walks the live chi router and returns every registered (method,
// path) pair, sorted and de-duplicated. This is the single source of truth the
// OpenAPI generator and the completeness gate introspect, so the documented
// surface is mechanically derived from the routes the server actually serves
// and cannot drift.
//
// chi.Walk visits nested Routes/Groups/Mounts transparently, so sub-routers
// (the scanner-token, runtime-agent-token, and Astronomer groups) are included.
func (s *Server) RouteList() ([]handler.Route, error) {
	seen := map[string]handler.Route{}
	err := chi.Walk(s.router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		method = strings.ToUpper(method)
		// chi emits a synthetic "*" method for catch-all NotFound/MethodNotAllowed
		// nodes; those are not real operations.
		if method == "" || method == "*" {
			return nil
		}
		// Normalize trailing-slash noise chi can introduce on Mount points.
		route = strings.TrimSuffix(route, "/*")
		if route == "" {
			route = "/"
		}
		seen[method+" "+route] = handler.Route{Method: method, Path: route}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]handler.Route, 0, len(seen))
	for _, rt := range seen {
		out = append(out, rt)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out, nil
}

// newSpecServer builds a Server whose router carries every route buildRouter
// registers, WITHOUT connecting to a database. It is used by the OpenAPI
// generator and the completeness gate so they run in plain `go test` / `go run`
// with no DATABASE_URL and no live Postgres.
//
// buildRouter only stores handler dependencies (it never issues a query at
// registration time), so a lazily-constructed pgxpool — which does not dial
// until first use — is sufficient to assemble the full route tree. The
// Astronomer JWKS URL is set so the conditional /security/* mount is included.
func newSpecServer() (*Server, error) {
	ctx := context.Background()
	// pgxpool.New does not dial; the pool connects lazily on first query, which
	// never happens here because we only assemble the router.
	pool, err := pgxpool.New(ctx, "postgres://introspect:introspect@127.0.0.1:1/introspect")
	if err != nil {
		return nil, err
	}
	tel, err := observability.Init(ctx, "openapi-introspect")
	if err != nil {
		return nil, err
	}
	dbHandle := db.NewFromPool(pool)
	s := &Server{
		cfg: Config{
			ListenAddr:        ":0",
			CORSOrigins:       []string{"http://localhost:5173"},
			AstronomerJWKSURL: "https://astronomer.example.com/.well-known/jwks.json",
		},
		tel:         tel,
		db:          dbHandle,
		auditLog:    audit.New(pool),
		syscfg:      syscfg.NewProvider(pool),
		customRoles: handler.NewCustomRoles(pool),
	}
	s.router = s.buildRouter()
	return s, nil
}
