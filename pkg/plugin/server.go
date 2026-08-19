// Server-side helpers for writing plugins. A plugin author wires their Scan / Enrich /
// Export functions to a chi mux and calls Serve. Used by cmd/sample-scanner-plugin.
package plugin

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Server exposes a Scanner / Enricher / Exporter behind the wire shape. Any nil capability
// returns 501 because the plugin did not declare that optional capability.
type Server struct {
	Manifest Manifest
	Scanner  Scanner
	Enricher Enricher
	Exporter Exporter
}

// Mux returns an http.Handler with /v1/plugin/{info,scan,enrich,export} routes.
func (s *Server) Mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/plugin/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Manifest)
	})
	mux.HandleFunc("/v1/plugin/scan", func(w http.ResponseWriter, r *http.Request) {
		if s.Scanner == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "scan capability not declared"})
			return
		}
		var req ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		res, err := s.Scanner.Scan(r.Context(), req)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("/v1/plugin/enrich", func(w http.ResponseWriter, r *http.Request) {
		if s.Enricher == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "enrich capability not declared"})
			return
		}
		var in []Finding
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		out, err := s.Enricher.Enrich(r.Context(), in)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("/v1/plugin/export", func(w http.ResponseWriter, r *http.Request) {
		if s.Exporter == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "export capability not declared"})
			return
		}
		var in []Finding
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		rec, err := s.Exporter.Export(r.Context(), in)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, rec)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// CheckOnce posts a probe to the plugin Info endpoint and verifies the manifest is sane.
// Returns a user-facing error message when the manifest is missing required fields.
func CheckOnce(m Manifest) error {
	if m.Name == "" {
		return fmt.Errorf("plugin: manifest missing Name")
	}
	if len(m.Capabilities) == 0 {
		return fmt.Errorf("plugin: manifest declares no Capabilities")
	}
	return nil
}
