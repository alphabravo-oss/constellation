package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
)

const maxBackupRequestBytes = 64 << 10

// decodeBackupRequest rejects ambiguous signing requests before a job, audit or
// artifact can be created. Empty bodies are optional only for one-off backups.
func decodeBackupRequest(w http.ResponseWriter, r *http.Request, destination any, optional bool, allowed ...string) bool {
	var body []byte
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxBackupRequestBytes)
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			var limit *http.MaxBytesError
			if errors.As(err, &limit) {
				jsonError(w, http.StatusRequestEntityTooLarge, "backup request too large")
			} else {
				jsonError(w, http.StatusBadRequest, "invalid backup request")
			}
			return false
		}
	}
	if len(bytes.Trim(body, " \t\r\n")) == 0 && optional {
		return true
	}
	if !validBackupRequestObject(body, allowed) || json.Unmarshal(body, destination) != nil {
		jsonError(w, http.StatusBadRequest, "invalid backup request")
		return false
	}
	return true
}

func validBackupRequestObject(body []byte, allowed []string) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok || seen[key] || !slices.Contains(allowed, key) {
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false
		}
		if key == "sign_mode" {
			value = bytes.TrimSpace(value)
			if len(value) == 0 || value[0] != '"' {
				return false
			}
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}
