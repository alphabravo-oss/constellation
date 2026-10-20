package apiutil

import (
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Recoverer is the first middleware in the chain (guide ch.03): a panic
// anywhere below becomes a CodeInternal response in the standard shape, with
// the panic value and stack logged under the request's correlation id. The
// panic value itself never reaches the client.
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		defer func() {
			if rec := recover(); rec != nil {
				if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(rec) // let the server abort the connection as net/http expects
				}
				slog.ErrorContext(ctx, "panic recovered",
					slog.Any("panic", rec), slog.String("stack", string(debug.Stack())))
				write(w, http.StatusInternalServerError, CodeInternal, InternalMessage)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
