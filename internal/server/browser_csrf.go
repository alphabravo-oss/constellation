package server

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/alphabravocompany/constellation/internal/auth"
)

func (s *Server) browserCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet || request.Method == http.MethodHead || request.Method == http.MethodOptions || request.URL.Path == "/api/v1/auth/saml/acs" {
			next.ServeHTTP(writer, request)
			return
		}
		_, accessErr := request.Cookie(auth.AccessCookie)
		_, refreshErr := request.Cookie(auth.RefreshCookie)
		cookieAuth := request.Header.Get("Authorization") == "" && (accessErr == nil || refreshErr == nil)
		browserLogin := auth.BrowserRequest(request) && (request.URL.Path == "/api/v1/auth/login" || request.URL.Path == "/api/v1/auth/ldap/login")
		if cookieAuth || browserLogin || request.URL.Path == "/api/v1/auth/refresh" {
			if request.Header.Get(auth.BrowserHeader) != "browser" || !s.browserOriginAllowed(request) {
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
