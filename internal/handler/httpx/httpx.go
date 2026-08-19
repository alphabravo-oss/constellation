// Package httpx holds the small, dependency-free HTTP response helpers shared
// across the handler sub-packages. It is the first shared-helper seam extracted
// as part of the D2 god-package split (see docs/handler-split-plan.md): every
// domain sub-package (handler/network, handler/scanning, ...) imports this
// instead of relying on the package-level helpers that used to live in
// internal/handler.
package httpx

import (
	"encoding/json"
	"net/http"
)

// WriteJSON writes a JSON response with the given status code. It mirrors the
// behaviour of the original handler.writeJSON helper.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// WriteRawSBOM writes a pre-rendered JSON document as a downloadable attachment.
// It mirrors the original handler.writeRawSBOM helper and is shared by the
// findings (SBOM) handlers and the image-scan-results handler.
func WriteRawSBOM(w http.ResponseWriter, raw []byte, fname string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
	_, _ = w.Write(raw)
}
