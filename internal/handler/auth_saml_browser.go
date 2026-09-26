package handler

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/alphabravocompany/constellation/internal/auth"
)

const (
	samlBrowserCookieName = "__Host-constellation-saml-state"
	samlBrowserBindingTTL = 5 * time.Minute
	samlBrowserBindingCap = 4096
	samlACSBodyLimit      = 1 << 20
)

type samlBrowserBindingStore struct {
	mu      sync.Mutex
	pending map[string]time.Time
}

func (store *samlBrowserBindingStore) mint() (string, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(random[:])
	store.mu.Lock()
	defer store.mu.Unlock()
	now := time.Now()
	for pending, expires := range store.pending {
		if !now.Before(expires) {
			delete(store.pending, pending)
		}
	}
	if len(store.pending) >= samlBrowserBindingCap {
		return "", errors.New("SAML browser binding capacity reached")
	}
	if store.pending == nil {
		store.pending = make(map[string]time.Time)
	}
	store.pending[nonce] = now.Add(samlBrowserBindingTTL)
	return nonce, nil
}

func (store *samlBrowserBindingStore) consume(nonce, relayState string) bool {
	if len(nonce) != 43 || subtle.ConstantTimeCompare([]byte(nonce), []byte(relayState)) != 1 {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	expires, found := store.pending[nonce]
	delete(store.pending, nonce)
	return found && time.Now().Before(expires)
}

func (store *samlBrowserBindingStore) discard(nonce string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.pending, nonce)
}

func (store *samlBrowserBindingStore) discardRequest(r *http.Request) {
	for _, cookie := range r.Cookies() {
		if cookie.Name == samlBrowserCookieName {
			store.discard(cookie.Value)
		}
	}
}

func samlBrowserRequest(r *http.Request) bool {
	if auth.BrowserRequest(r) {
		return true
	}
	_, err := r.Cookie(samlBrowserCookieName)
	return err == nil
}

func setSAMLBrowserCookie(w http.ResponseWriter, nonce string) {
	http.SetCookie(w, &http.Cookie{
		Name: samlBrowserCookieName, Value: nonce, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode,
		MaxAge: int(samlBrowserBindingTTL.Seconds()), Expires: time.Now().Add(samlBrowserBindingTTL),
	})
}

func clearSAMLBrowserCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: samlBrowserCookieName, Value: "", Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode,
		MaxAge: -1, Expires: time.Unix(1, 0),
	})
}

func (a *Auth) prepareSAMLACS(w http.ResponseWriter, r *http.Request, browser bool) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, samlACSBodyLimit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "SAML response too large"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid SAML form"})
		}
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid SAML form"})
		return false
	}
	if !browser {
		return true
	}
	assertions := r.PostForm["SAMLResponse"]
	if r.Method != http.MethodPost || len(assertions) != 1 || assertions[0] == "" || r.Form.Has("SAMLart") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid SAML form"})
		return false
	}
	var nonce string
	var cookieCount int
	for _, cookie := range r.Cookies() {
		if cookie.Name == samlBrowserCookieName {
			cookieCount++
			nonce = cookie.Value
		}
	}
	relayStates := r.PostForm["RelayState"]
	if cookieCount != 1 || len(relayStates) != 1 || !a.samlBrowserBindings.consume(nonce, relayStates[0]) {
		if a.auditLog != nil {
			a.auditLoginFailure(r.Context(), r, nil, nil, "", "saml_browser_binding_failed")
		}
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid SAML browser state; restart login"})
		return false
	}
	r.Header.Set(auth.BrowserHeader, "browser")
	return true
}
