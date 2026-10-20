package registry

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Close every page before the next request and never return a successful page
// when its transport reports a read/close error, even if the bytes form JSON.
func readRegistryPage(resp *http.Response, limit int64) ([]byte, error) {
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err := errors.Join(readErr, resp.Body.Close()); err != nil {
		return nil, fmt.Errorf("read registry response: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, errors.New("registry response exceeds page byte limit")
	}
	return body, nil
}
