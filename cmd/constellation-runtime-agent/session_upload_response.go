package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const sessionResponseLimit = 65536

func weakTLSSettingChanged(current, requested *bool) bool {
	return requested != nil && (current == nil || *current != *requested)
}

func parseSessionResponse(body []byte) (*sessionUploadResp, error) {
	var parsed *sessionUploadResp
	if err := json.Unmarshal(body, &parsed); err != nil || parsed == nil {
		return nil, errors.New("invalid session upload response")
	}
	return parsed, nil
}

// The response contains native control commands. A transport failure or a
// truncated document must never be interpreted as a successful default command.
func readSessionResponse(response *http.Response) ([]byte, error) {
	body, readErr := io.ReadAll(io.LimitReader(response.Body, sessionResponseLimit+1))
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		return nil, fmt.Errorf("read session upload response: %w", err)
	}
	if len(body) > sessionResponseLimit {
		return nil, errors.New("session upload response exceeds byte limit")
	}
	return body, nil
}
