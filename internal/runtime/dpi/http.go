package dpi

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// parseHTTP1 attempts HTTP/1.1 request line + headers parsing. Body is taken raw
// up to a 64 KiB cap. Pipelined responses get parsed if dir = response.
func parseHTTP1(flow Flow, dir Direction, payload []byte) *L7Event {
	br := bufio.NewReader(bytes.NewReader(payload))
	// Cheap pre-flight: first byte should be a printable ASCII method/ HTTP token.
	if !startsLikeHTTP1(payload) {
		return nil
	}
	if dir == DirRequest {
		req, err := http.ReadRequest(br)
		if err != nil {
			return nil
		}
		body := readBounded(br, 64<<10)
		evt := &L7Event{
			Flow: flow, Protocol: "http", Dir: dir,
			HTTP: &HTTPEvent{
				Method:    req.Method,
				Path:      req.URL.Path,
				Host:      req.Host,
				Query:     req.URL.RawQuery,
				Version:   req.Proto,
				Headers:   normalizeHeaders(req.Header),
				Body:      body.bytes,
				Truncated: body.truncated,
			},
		}
		return evt
	}
	// response
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil
	}
	body := readBounded(br, 64<<10)
	return &L7Event{
		Flow: flow, Protocol: "http", Dir: dir,
		HTTP: &HTTPEvent{
			Version:    resp.Proto,
			StatusCode: resp.StatusCode,
			Headers:    normalizeHeaders(resp.Header),
			Body:       body.bytes,
			Truncated:  body.truncated,
		},
	}
}

// startsLikeHTTP1 sniffs methods (and HTTP/ for responses) without allocating.
func startsLikeHTTP1(b []byte) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "HTTP/"}
	for _, m := range methods {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

type boundedBody struct {
	bytes     []byte
	truncated bool
}

func readBounded(r *bufio.Reader, cap int) boundedBody {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			if len(buf)+n > cap {
				buf = append(buf, tmp[:cap-len(buf)]...)
				return boundedBody{bytes: buf, truncated: true}
			}
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			return boundedBody{bytes: buf}
		}
	}
}

func normalizeHeaders(in http.Header) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, vs := range in {
		out[canonicalHeader(k)] = vs
	}
	return out
}

// HTTP/2 preface — first 24 bytes of any client h2 connection.
var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// parseHTTP2 looks for the h2 connection preface followed by HEADERS frames. It
// decodes one HEADERS frame using a fresh HPACK decoder. This is good enough for
// the WAF/DLP path which examines pseudo-headers + selected headers; it does NOT
// reassemble continuations or maintain cross-frame state.
func parseHTTP2(flow Flow, dir Direction, payload []byte) *L7Event {
	rest := payload
	if bytes.HasPrefix(rest, http2Preface) {
		rest = rest[len(http2Preface):]
	}
	if len(rest) < 9 {
		return nil
	}
	// Frame header: length(3) type(1) flags(1) reserved+streamID(4)
	length := int(rest[0])<<16 | int(rest[1])<<8 | int(rest[2])
	ftype := http2.FrameType(rest[3])
	if ftype != http2.FrameHeaders {
		// Skip non-HEADERS frames; for the WAF path we only care about HEADERS.
		return nil
	}
	if 9+length > len(rest) {
		return nil
	}
	block := rest[9 : 9+length]

	dec := hpack.NewDecoder(4096, nil)
	hf, err := dec.DecodeFull(block)
	if err != nil || len(hf) == 0 {
		return nil
	}
	hdrs := map[string][]string{}
	var method, path, scheme, authority string
	for _, h := range hf {
		switch h.Name {
		case ":method":
			method = h.Value
		case ":path":
			path = h.Value
		case ":scheme":
			scheme = h.Value
		case ":authority":
			authority = h.Value
		default:
			hdrs[h.Name] = append(hdrs[h.Name], h.Value)
		}
	}
	_ = scheme
	query := ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		query = path[i+1:]
		path = path[:i]
	}
	proto := "http2"
	var service, rpc string
	if ct := hdrs["content-type"]; len(ct) > 0 && strings.HasPrefix(ct[0], "application/grpc") {
		proto = "grpc"
		service, rpc = splitGRPCPath(path)
	}
	return &L7Event{
		Flow: flow, Protocol: proto, Dir: dir,
		HTTP: &HTTPEvent{
			Method:  method,
			Path:    path,
			Host:    authority,
			Query:   query,
			Version: proto,
			Headers: hdrs,
			Service: service,
			RPC:     rpc,
		},
	}
}

func splitGRPCPath(p string) (svc, rpc string) {
	p = strings.TrimPrefix(p, "/")
	if i := strings.Index(p, "/"); i > 0 {
		return p[:i], p[i+1:]
	}
	return p, ""
}
