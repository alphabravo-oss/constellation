package registry

import "strconv"

// providerResponseError keeps untrusted diagnostic values out of operator-facing
// errors while retaining the original cause for explicit errors.Is/As handling.
// Stage/category arguments must be constant descriptions, never remote values.
type providerResponseError struct {
	stage    string
	category string
	status   int
	cause    error
}

func (e *providerResponseError) Error() string {
	message := e.stage + ": " + e.category
	if e.status > 0 {
		message += " (HTTP " + strconv.Itoa(e.status) + ")"
	}
	return message
}

func (e *providerResponseError) Unwrap() error { return e.cause }

func responseFailure(stage, category string, status int, cause error) error {
	return &providerResponseError{stage: stage, category: category, status: status, cause: cause}
}
