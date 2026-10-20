// Package apiutil is the single seam between domain errors and the wire
// (guide ch.03): handlers return or map typed errors, this package picks the
// status/code, scrubs internal messages, and writes one body shape:
//
//	{"error": {"code": "<code>", "message": "<message>"}}
//
// ToConnect holds the same mapping for the Phase 2 Connect-RPC interceptors.
package apiutil

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"
)

// Sentinel errors domain code returns (wrap with %w; errors.Is matches).
var (
	ErrInvalid            = errors.New("invalid argument")
	ErrNotFound           = errors.New("not found")
	ErrConflict           = errors.New("conflict")
	ErrForbidden          = errors.New("forbidden")
	ErrUnauthenticated    = errors.New("unauthenticated")
	ErrFailedPrecondition = errors.New("failed precondition")
	ErrResourceExhausted  = errors.New("resource exhausted")
	ErrUnavailable        = errors.New("unavailable")
	ErrUnimplemented      = errors.New("unimplemented")
	ErrDeadline           = errors.New("deadline exceeded")
	ErrCanceled           = errors.New("canceled")
)

// Code is the wire error code. Names follow connect.Code / gRPC so the Phase 2
// RPC surface and this REST surface share one vocabulary.
type Code string

const (
	CodeCanceled           Code = "canceled"
	CodeUnknown            Code = "unknown"
	CodeInvalidArgument    Code = "invalid_argument"
	CodeDeadlineExceeded   Code = "deadline_exceeded"
	CodeNotFound           Code = "not_found"
	CodeAlreadyExists      Code = "already_exists"
	CodePermissionDenied   Code = "permission_denied"
	CodeResourceExhausted  Code = "resource_exhausted"
	CodeFailedPrecondition Code = "failed_precondition"
	CodeAborted            Code = "aborted"
	CodeOutOfRange         Code = "out_of_range"
	CodeUnimplemented      Code = "unimplemented"
	CodeInternal           Code = "internal"
	CodeUnavailable        Code = "unavailable"
	CodeDataLoss           Code = "data_loss"
	CodeUnauthenticated    Code = "unauthenticated"
)

// InternalMessage is the only message a CodeInternal response carries; the
// original error is logged with the request's correlation id instead.
const InternalMessage = "internal error"

// Error is a typed error carrying its wire code and client-safe message.
type Error struct {
	Code    Code
	Message string
	Err     error // wrapped cause, never sent to the client
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Err }

// E builds a typed error with a client-safe message.
func E(code Code, message string) *Error { return &Error{Code: code, Message: message} }

// Ef is E with formatting.
func Ef(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Wrap attaches a code and client-safe message to a cause.
func Wrap(err error, code Code, message string) *Error {
	return &Error{Code: code, Message: message, Err: err}
}

// Convenience constructors for the common cases.
func NotFound(what string) *Error   { return E(CodeNotFound, what+" not found") }
func Invalid(message string) *Error { return E(CodeInvalidArgument, message) }
func Conflict(message string) *Error {
	return E(CodeAlreadyExists, message)
}
func Forbidden(message string) *Error { return E(CodePermissionDenied, message) }

// CodeOf maps any error to a Code: typed *Error first, then sentinels, then
// pgx/context errors; everything else is CodeInternal.
func CodeOf(err error) Code {
	var e *Error
	switch {
	case err == nil:
		return CodeUnknown
	case errors.As(err, &e):
		return e.Code
	case errors.Is(err, ErrInvalid):
		return CodeInvalidArgument
	case errors.Is(err, ErrNotFound), errors.Is(err, pgx.ErrNoRows):
		return CodeNotFound
	case errors.Is(err, ErrConflict):
		return CodeAlreadyExists
	case errors.Is(err, ErrForbidden):
		return CodePermissionDenied
	case errors.Is(err, ErrUnauthenticated):
		return CodeUnauthenticated
	case errors.Is(err, ErrFailedPrecondition):
		return CodeFailedPrecondition
	case errors.Is(err, ErrResourceExhausted):
		return CodeResourceExhausted
	case errors.Is(err, ErrUnavailable):
		return CodeUnavailable
	case errors.Is(err, ErrUnimplemented):
		return CodeUnimplemented
	case errors.Is(err, ErrDeadline), errors.Is(err, context.DeadlineExceeded):
		return CodeDeadlineExceeded
	case errors.Is(err, ErrCanceled), errors.Is(err, context.Canceled):
		return CodeCanceled
	default:
		return CodeInternal
	}
}

// HTTPStatus is the REST status for a code.
func HTTPStatus(code Code) int {
	switch code {
	case CodeInvalidArgument, CodeOutOfRange:
		return http.StatusBadRequest
	case CodeUnauthenticated:
		return http.StatusUnauthorized
	case CodePermissionDenied:
		return http.StatusForbidden
	case CodeNotFound:
		return http.StatusNotFound
	case CodeAlreadyExists, CodeAborted:
		return http.StatusConflict
	case CodeFailedPrecondition:
		return http.StatusPreconditionFailed
	case CodeResourceExhausted:
		return http.StatusTooManyRequests
	case CodeCanceled:
		return 499 // client closed request
	case CodeDeadlineExceeded:
		return http.StatusGatewayTimeout
	case CodeUnimplemented:
		return http.StatusNotImplemented
	case CodeUnavailable:
		return http.StatusServiceUnavailable
	case CodeInternal, CodeUnknown, CodeDataLoss:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// CodeForStatus is the inverse table for call sites that still think in HTTP
// statuses (the legacy REST handlers).
func CodeForStatus(status int) Code {
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusUnsupportedMediaType, http.StatusRequestEntityTooLarge:
		return CodeInvalidArgument
	case http.StatusUnauthorized:
		return CodeUnauthenticated
	case http.StatusForbidden:
		return CodePermissionDenied
	case http.StatusNotFound, http.StatusGone:
		return CodeNotFound
	case http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return CodeUnimplemented
	case http.StatusConflict:
		return CodeAlreadyExists
	case http.StatusPreconditionFailed, http.StatusPreconditionRequired, http.StatusLocked:
		return CodeFailedPrecondition
	case http.StatusTooManyRequests, http.StatusInsufficientStorage:
		return CodeResourceExhausted
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return CodeDeadlineExceeded
	case http.StatusServiceUnavailable, http.StatusBadGateway:
		return CodeUnavailable
	case 499:
		return CodeCanceled
	default:
		if status >= 500 {
			return CodeInternal
		}
		if status >= 400 {
			return CodeInvalidArgument
		}
		return CodeUnknown
	}
}

// Body is the wire shape of every error response.
type Body struct {
	Error Detail `json:"error"`
}

// Detail is the error object inside Body. Details carries structured,
// client-safe context (validation field errors, blocking references) and is
// omitted when nil.
type Detail struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// WriteError maps err to its code and status and writes the error body.
// CodeInternal messages are scrubbed; the cause is logged with the request's
// correlation id (ctx) so operators can join it to the request-summary line.
func WriteError(ctx context.Context, w http.ResponseWriter, err error) {
	code := CodeOf(err)
	message := clientMessage(err, code)
	if code == CodeInternal || code == CodeUnknown || code == CodeDataLoss {
		slog.ErrorContext(ctx, "request failed", slog.String("code", string(code)), slog.String("err", err.Error()))
		message = InternalMessage
	}
	write(w, HTTPStatus(code), code, message)
}

// WriteStatus is the bridge for call sites that still pick an HTTP status by
// hand: the status is kept, the code is derived from it, and a message whose
// code is internal (500 and unmapped 5xx) is scrubbed and logged instead of
// sent. 502/503/504 are upstream/unavailable conditions whose messages are
// categorical, not internal detail, and pass through.
func WriteStatus(ctx context.Context, w http.ResponseWriter, status int, message string) {
	code := CodeForStatus(status)
	if code == CodeInternal {
		slog.ErrorContext(ctx, "request failed", slog.Int("status", status), slog.String("err", message))
		message = InternalMessage
	}
	write(w, status, code, message)
}

// WriteStatusCode is WriteStatus with a domain-specific code string (for
// example "protected_namespace"); internal messages are still scrubbed.
func WriteStatusCode(ctx context.Context, w http.ResponseWriter, status int, code, message string) {
	if CodeForStatus(status) == CodeInternal {
		slog.ErrorContext(ctx, "request failed", slog.Int("status", status), slog.String("code", code), slog.String("err", message))
		message = InternalMessage
	}
	write(w, status, Code(code), message)
}

// WriteCode writes a non-internal error with an explicit code and message.
func WriteCode(w http.ResponseWriter, code Code, message string) {
	if code == CodeInternal {
		message = InternalMessage
	}
	write(w, HTTPStatus(code), code, message)
}

// WriteDetailed writes a non-internal error with structured details (for
// example validation field errors). Internal statuses are still scrubbed and
// their details dropped.
func WriteDetailed(ctx context.Context, w http.ResponseWriter, status int, code, message string, details any) {
	if CodeForStatus(status) == CodeInternal {
		slog.ErrorContext(ctx, "request failed", slog.Int("status", status), slog.String("code", code), slog.String("err", message))
		write(w, status, CodeInternal, InternalMessage)
		return
	}
	if code == "" {
		code = string(CodeForStatus(status))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Body{Error: Detail{Code: Code(code), Message: message, Details: details}})
}

func write(w http.ResponseWriter, status int, code Code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Body{Error: Detail{Code: code, Message: message}})
}

func clientMessage(err error, code Code) string {
	var e *Error
	if errors.As(err, &e) && e.Message != "" {
		return e.Message
	}
	switch code {
	case CodeNotFound:
		return "not found"
	case CodeInvalidArgument:
		return err.Error()
	case CodePermissionDenied:
		return "forbidden"
	case CodeUnauthenticated:
		return "unauthenticated"
	case CodeAlreadyExists:
		return "conflict"
	case CodeFailedPrecondition, CodeResourceExhausted, CodeUnavailable, CodeUnimplemented, CodeDeadlineExceeded, CodeCanceled, CodeAborted, CodeOutOfRange:
		return err.Error()
	case CodeInternal, CodeUnknown, CodeDataLoss:
		return InternalMessage
	default:
		return InternalMessage
	}
}

// NotFoundHandler / MethodNotAllowedHandler give the router's own 404/405 the same shape.
func NotFoundHandler(w http.ResponseWriter, _ *http.Request) {
	write(w, http.StatusNotFound, CodeNotFound, "route not found")
}

func MethodNotAllowedHandler(w http.ResponseWriter, _ *http.Request) {
	write(w, http.StatusMethodNotAllowed, CodeUnimplemented, "method not allowed")
}
