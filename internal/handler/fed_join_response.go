package handler

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

const remoteJoinResponseLimit = 1 << 20

// remoteJoinError keeps untrusted diagnostics available to error inspection but
// excludes them from the public error text returned by JoinRemote.
type remoteJoinError struct {
	stage    string
	category string
	status   int
	cause    error
}

func (e *remoteJoinError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("federation: join %s: %s (HTTP %d)", e.stage, e.category, e.status)
	}
	return fmt.Sprintf("federation: join %s: %s", e.stage, e.category)
}

func (e *remoteJoinError) Unwrap() error { return e.cause }

func remoteJoinFailure(stage, category string, status int, cause error) error {
	return &remoteJoinError{stage: stage, category: category, status: status, cause: cause}
}

// readRemoteJoinResponse owns the body. A successful bounded read must observe
// actual EOF and a successful close before any returned credential is persisted.
func readRemoteJoinResponse(response *http.Response) ([]byte, error) {
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, remoteJoinResponseLimit+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return nil, remoteJoinFailure("response", "read failed", response.StatusCode, errors.Join(readErr, closeErr))
	}
	if closeErr != nil {
		return nil, remoteJoinFailure("response", "close failed", response.StatusCode, closeErr)
	}
	if len(raw) > remoteJoinResponseLimit {
		return nil, remoteJoinFailure("response", "size limit exceeded", response.StatusCode, nil)
	}
	return raw, nil
}
