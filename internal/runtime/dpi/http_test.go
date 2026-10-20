package dpi

import (
	"fmt"
	"strings"
	"testing"
)

func TestHTTPBodyFramingForInspection(t *testing.T) {
	for _, tc := range []struct {
		name          string
		direction     Direction
		payload, body string
		truncated     bool
	}{
		{"chunked request", DirRequest, "POST / HTTP/1.1\r\nHost: app\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nsec\r\n3\r\nret\r\n0\r\n\r\n", "secret", false},
		{"chunked response", DirResponse, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nsec\r\n3\r\nret\r\n0\r\n\r\n", "secret", false},
		{"pipelined request", DirRequest, "POST / HTTP/1.1\r\nHost: app\r\nContent-Length: 3\r\n\r\noneGET /next HTTP/1.1\r\nHost: app\r\n\r\n", "one", false},
		{"pipelined response", DirResponse, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\noneHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo", "one", false},
		{"partial body", DirRequest, "POST / HTTP/1.1\r\nHost: app\r\nContent-Length: 10\r\n\r\nshort", "short", true},
		{"partial chunk", DirResponse, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nshort", "short", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := parseHTTP1(Flow{}, tc.direction, []byte(tc.payload))
			if event == nil || event.HTTP == nil {
				t.Fatal("HTTP message not recognized")
			}
			if string(event.HTTP.Body) != tc.body || event.HTTP.Truncated != tc.truncated {
				t.Fatalf("body=%q truncated=%v, want body=%q truncated=%v", event.HTTP.Body, event.HTTP.Truncated, tc.body, tc.truncated)
			}
		})
	}
}

func TestHTTPDecodedBodyRemainsBounded(t *testing.T) {
	t.Parallel()
	const limit = 64 << 10
	body := strings.Repeat("x", limit+1)
	payload := fmt.Sprintf("POST / HTTP/1.1\r\nHost: app\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body)
	event := parseHTTP1(Flow{}, DirRequest, []byte(payload))
	if event == nil || len(event.HTTP.Body) != limit || !event.HTTP.Truncated {
		t.Fatal("decoded body exceeded its inspection budget or hid truncation")
	}
}
