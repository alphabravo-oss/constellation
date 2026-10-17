package main

import (
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

type sessionResponseTransport func(*http.Request) (*http.Response, error)

func (transport sessionResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

type sessionFaultBody struct {
	io.Reader
	readErr, closeErr error
	closed            *int
}

func (body *sessionFaultBody) Read(buffer []byte) (int, error) {
	n, err := body.Reader.Read(buffer)
	if errors.Is(err, io.EOF) && body.readErr != nil {
		return n, body.readErr
	}
	return n, err
}

func (body *sessionFaultBody) Close() error {
	*body.closed++
	return body.closeErr
}

func TestSessionUploadRejectsIncompleteControlResponses(t *testing.T) {
	for _, fault := range []string{"read", "close", "overflow", "malformed", "empty", "null", "invalid-toggle"} {
		t.Run(fault, func(t *testing.T) {
			checkSessionResponseFailure(t, fault)
		})
	}
}

func checkSessionResponseFailure(t *testing.T, fault string) {
	t.Helper()
	calls, closed := 0, 0
	client := &http.Client{Transport: sessionResponseTransport(func(request *http.Request) (*http.Response, error) {
		calls++
		payload := `{"accepted":1,"kill":[7],"weak_tls":false}`
		body := &sessionFaultBody{closed: &closed}
		switch fault {
		case "read":
			body.readErr = io.ErrUnexpectedEOF
		case "close":
			body.closeErr = io.ErrClosedPipe
		case "overflow":
			payload += strings.Repeat(" ", 65537)
		case "malformed":
			payload = `{"kill":[7],"weak_tls":`
		case "empty":
			payload = ""
		case "null":
			payload = "null"
		case "invalid-toggle":
			payload = `{"kill":[7],"weak_tls":"false"}`
		}
		body.Reader = strings.NewReader(payload)
		return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header), Request: request}, nil
	})}
	response, err := postSessionBatch(t.Context(), client, "https://control.example/sessions", "fixture-token", []sessionUploadRow{{ID: 1}})
	if err == nil || response != nil {
		t.Fatal("incomplete control response returned commands or acknowledged upload")
	}
	if calls == 0 || calls > 3 || closed != calls {
		t.Fatalf("unbounded retries or unclosed responses: calls=%d closed=%d", calls, closed)
	}
}

func TestSessionUploadPreservesExplicitAndAbsentControl(t *testing.T) {
	enabled, disabled := true, false
	cases := []struct {
		payload string
		want    sessionUploadResp
	}{
		{`{}`, sessionUploadResp{}},
		{`{"weak_tls":null}`, sessionUploadResp{}},
		{`{"accepted":1,"kill":[7],"weak_tls":false}`, sessionUploadResp{Accepted: 1, Kill: []uint32{7}, WeakTLS: &disabled}},
		{`{"weak_tls":true}`, sessionUploadResp{WeakTLS: &enabled}},
	}
	for _, test := range cases {
		t.Run(test.payload, func(t *testing.T) {
			client := &http.Client{Transport: sessionResponseTransport(func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(test.payload)), Header: make(http.Header), Request: request}, nil
			})}
			response, err := postSessionBatch(t.Context(), client, "https://control.example/sessions", "fixture-token", nil)
			if err != nil || response == nil {
				t.Fatalf("valid response rejected: %v", err)
			}
			if !reflect.DeepEqual(*response, test.want) {
				t.Fatal("explicit command changed or absent setting became a disable command")
			}
		})
	}
}
