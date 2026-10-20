package server

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/alphabravocompany/constellation/internal/identity"
)

func (s *Server) browserCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet || request.Method == http.MethodHead || request.Method == http.MethodOptions {
			next.ServeHTTP(writer, request)
			return
		}
		_, accessErr := request.Cookie(identity.AccessCookie)
		cookieAuth := request.Header.Get("Authorization") == "" && accessErr == nil
		browserLogin := request.URL.Path == "/api/v1/auth/break-glass"
		if cookieAuth || browserLogin {
			if request.Header.Get(identity.BrowserHeader) != "browser" || !s.browserOriginAllowed(request) {
				writeError(writer, http.StatusForbidden, "browser request origin rejected")
				return
			}
		}
		next.ServeHTTP(writer, request)
	})
}

func (s *Server) browserOriginAllowed(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	if origin == "" {
		return request.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if strings.EqualFold(parsed.Host, request.Host) && (request.TLS == nil || parsed.Scheme == "https") {
		return true
	}
	for _, allowed := range corsAllowedOrigins(s.cfg.CORSOrigins) {
		if origin == allowed {
			return true
		}
	}
	return false
}
