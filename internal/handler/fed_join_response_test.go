package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
)

const remoteJoinDiagnosticCanary = "owned-join-diagnostic-938475621"

type remoteJoinTestTransport func(*http.Request) (*http.Response, error)

func (f remoteJoinTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type remoteJoinTestBody struct {
	reader   io.Reader
	tailErr  error
	closeErr error
	closed   int
	read     int
	sawEOF   bool
}

func (b *remoteJoinTestBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read += n
	if errors.Is(err, io.EOF) {
		b.sawEOF = true
		if b.tailErr != nil {
			return n, b.tailErr
		}
	}
	return n, err
}

func (b *remoteJoinTestBody) Close() error {
	b.closed++
	return b.closeErr
}

func remoteJoinPaddedJSON() string {
	const payload = `{"secret":"owned-new-ticket","cluster_id":"owned-new-cluster"}`
	return payload + strings.Repeat(" ", remoteJoinResponseLimit-len(payload))
}

func assertRemoteJoinFailure(t *testing.T, err error, category string) {
	t.Helper()
	if err == nil || strings.Contains(err.Error(), remoteJoinDiagnosticCanary) {
		t.Fatal("join error disclosed raw diagnostics or accepted a failed operation")
	}
	var safe *remoteJoinError
	if !errors.As(err, &safe) || safe.category != category {
		t.Fatal("join error lost its categorical boundary")
	}
}

type remoteJoinReadCase struct {
	name     string
	payload  string
	tailErr  error
	closeErr error
	category string
}

func checkRemoteJoinReadCase(t *testing.T, test remoteJoinReadCase) {
	t.Helper()
	body := &remoteJoinTestBody{reader: strings.NewReader(test.payload), tailErr: test.tailErr, closeErr: test.closeErr}
	raw, err := readRemoteJoinResponse(&http.Response{StatusCode: http.StatusOK, Body: body})
	if body.closed != 1 || body.read > remoteJoinResponseLimit+1 {
		t.Fatal("response did not close exactly once within the sentinel-byte bound")
	}
	if test.category == "" {
		if err != nil || string(raw) != test.payload || !body.sawEOF {
			t.Fatal("complete bounded response rejected or accepted without EOF")
		}
		return
	}
	if raw != nil {
		t.Fatal("failed response retained accepted credential bytes")
	}
	assertRemoteJoinFailure(t, err, test.category)
	for _, cause := range []error{test.tailErr, test.closeErr} {
		if cause != nil && !errors.Is(err, cause) {
			t.Fatal("read/close cause identity was not preserved")
		}
	}
}

func TestRemoteJoinResponseRequiresCompleteReadAndClose(t *testing.T) {
	readFailure := errors.New("read " + remoteJoinDiagnosticCanary)
	closeFailure := errors.New("close " + remoteJoinDiagnosticCanary)
	for _, test := range []remoteJoinReadCase{
		{name: "small complete", payload: `{"secret":"owned-ticket"}`},
		{name: "exact bound complete", payload: remoteJoinPaddedJSON()},
		{name: "overflow whitespace", payload: remoteJoinPaddedJSON() + " ", category: "size limit exceeded"},
		{name: "overflow trailing data", payload: remoteJoinPaddedJSON() + "x", category: "size limit exceeded"},
		{name: "tail error at old bound", payload: remoteJoinPaddedJSON(), tailErr: readFailure, category: "read failed"},
		{name: "prefix read failure", payload: `{"secret":"owned-ticket"}`, tailErr: readFailure, category: "read failed"},
		{name: "close failure", payload: `{"secret":"owned-ticket"}`, closeErr: closeFailure, category: "close failed"},
		{name: "read and close failure", payload: `{"secret":"owned-ticket"}`, tailErr: readFailure, closeErr: closeFailure, category: "read failed"},
	} {
		t.Run(test.name, func(t *testing.T) { checkRemoteJoinReadCase(t, test) })
	}
}

func remoteJoinFailureTransport(fault string, cause error) remoteJoinTestTransport {
	return func(request *http.Request) (*http.Response, error) {
		if fault == "transport" {
			return nil, cause
		}
		body := &remoteJoinTestBody{reader: strings.NewReader(`{"secret":false}`)}
		status := http.StatusOK
		switch fault {
		case "read":
			body.tailErr = cause
		case "close":
			body.closeErr = cause
		case "status":
			status = http.StatusForbidden
			body.reader = strings.NewReader(remoteJoinDiagnosticCanary)
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: body, Request: request}, nil
	}
}

func TestPerformRemoteJoinErrorsKeepCausesPrivate(t *testing.T) {
	for fault, category := range map[string]string{"transport": "transport failed", "read": "read failed", "close": "close failed", "decode": "decode failed", "status": "unexpected status"} {
		t.Run(fault, func(t *testing.T) {
			cause := errors.New("owned failure " + remoteJoinDiagnosticCanary)
			client := &http.Client{Transport: remoteJoinFailureTransport(fault, cause)}
			_, err := performRemoteJoin(t.Context(), nil, nil, client, uuid.New(), "https://127.0.0.1:8443/owned/"+remoteJoinDiagnosticCanary, "owned-token", "owned-cluster", "owned-cluster")
			assertRemoteJoinFailure(t, err, category)
			if fault == "transport" || fault == "read" || fault == "close" {
				if !errors.Is(err, cause) {
					t.Fatal("remote cause was lost")
				}
			}
			if fault == "decode" {
				var typed *json.UnmarshalTypeError
				if !errors.As(err, &typed) {
					t.Fatal("typed decode cause was lost")
				}
			}
			if client.CheckRedirect != nil {
				t.Fatal("join modified the caller HTTP client")
			}
		})
	}
}

func TestJoinRemoteReturnsCategoricalFailureJSON(t *testing.T) {
	// Use the existing owned DefaultTransport seam. This exercises the real HTTP
	// handler and http.Client; the fixture does not claim a live TLS handshake.
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	for fault, category := range map[string]string{"transport": "transport failed", "read": "read failed", "decode": "decode failed", "status": "unexpected status"} {
		t.Run(fault, func(t *testing.T) {
			cause := errors.New("owned failure " + remoteJoinDiagnosticCanary)
			http.DefaultTransport = remoteJoinFailureTransport(fault, cause)
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/federation/join-remote", strings.NewReader(`{"master_url":"https://127.0.0.1:8443/owned/`+remoteJoinDiagnosticCanary+`","token":"owned-token","cluster_id":"owned-cluster"}`))
			response := httptest.NewRecorder()
			NewFederation(&db.DB{}, nil).JoinRemote(response, request)
			var value apiutil.Body
			if response.Code != http.StatusBadGateway || json.Unmarshal(response.Body.Bytes(), &value) != nil || value.Error.Code == "" {
				t.Fatal("join error did not return structured 502")
			}
			if strings.Contains(value.Error.Message, remoteJoinDiagnosticCanary) || !strings.Contains(value.Error.Message, category) {
				t.Fatal("join API error disclosed diagnostics or lost its categorical operation")
			}
		})
	}
}
