package dpi

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestHTTP1Request(t *testing.T) {
	raw := []byte("GET /v1/users?id=1 HTTP/1.1\r\nHost: api\r\nUser-Agent: curl\r\n\r\n")
	e := NewEngine(nil)
	evt := e.Process(Flow{}, DirRequest, raw)
	if evt == nil || evt.HTTP == nil {
		t.Fatalf("nil HTTP event")
	}
	if evt.HTTP.Method != "GET" || evt.HTTP.Path != "/v1/users" || evt.HTTP.Query != "id=1" {
		t.Fatalf("bad parse: %+v", evt.HTTP)
	}
	if evt.HTTP.Host != "api" {
		t.Fatalf("missing host: %+v", evt.HTTP)
	}
	if evt.HTTP.Headers["user-agent"][0] != "curl" {
		t.Fatalf("missing user-agent header: %+v", evt.HTTP.Headers)
	}
}

func TestHTTP2Headers(t *testing.T) {
	// Build a single HEADERS frame: :method GET, :path /, :scheme https
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/svc/Method?x=1"})
	enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "api"})
	enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})
	hdrs := buf.Bytes()

	var out bytes.Buffer
	// 9-byte frame header
	length := []byte{byte(len(hdrs) >> 16), byte(len(hdrs) >> 8), byte(len(hdrs))}
	out.Write(length)
	out.WriteByte(byte(http2.FrameHeaders))
	out.WriteByte(byte(http2.FlagHeadersEndHeaders | http2.FlagHeadersEndStream))
	out.Write([]byte{0, 0, 0, 1}) // stream 1
	out.Write(hdrs)

	e := NewEngine(nil)
	evt := e.Process(Flow{}, DirRequest, out.Bytes())
	if evt == nil || evt.HTTP == nil {
		t.Fatalf("no event")
	}
	if evt.Protocol != "grpc" {
		t.Fatalf("want grpc, got %s", evt.Protocol)
	}
	if evt.HTTP.Path != "/svc/Method" || evt.HTTP.Query != "x=1" {
		t.Fatalf("bad path/query: %+v", evt.HTTP)
	}
	if evt.HTTP.Service != "svc" || evt.HTTP.RPC != "Method" {
		t.Fatalf("bad grpc split: svc=%q rpc=%q", evt.HTTP.Service, evt.HTTP.RPC)
	}
}

func TestDNS(t *testing.T) {
	// Build a minimal DNS query for example.com, A record.
	var buf bytes.Buffer
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:], 0x1234)
	binary.BigEndian.PutUint16(hdr[4:], 1) // qdcount=1
	buf.Write(hdr)
	for _, lbl := range []string{"example", "com"} {
		buf.WriteByte(byte(len(lbl)))
		buf.WriteString(lbl)
	}
	buf.WriteByte(0)
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QTYPE=A
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QCLASS=IN

	e := NewEngine(nil)
	evt := e.Process(Flow{}, DirRequest, buf.Bytes())
	if evt == nil || evt.DNS == nil {
		t.Fatalf("no DNS event")
	}
	if evt.DNS.QName != "example.com" || evt.DNS.QType != 1 || evt.DNS.TxnID != 0x1234 {
		t.Fatalf("bad DNS parse: %+v", evt.DNS)
	}
	if evt.DNS.Response {
		t.Fatalf("query should not be flagged as a response")
	}
}

// writeDNSName appends a DNS name (labels + terminating zero) to buf.
func writeDNSName(buf *bytes.Buffer, name string) {
	for _, lbl := range bytes.Split([]byte(name), []byte(".")) {
		buf.WriteByte(byte(len(lbl)))
		buf.Write(lbl)
	}
	buf.WriteByte(0)
}

func TestDNSResponseAnswers(t *testing.T) {
	var buf bytes.Buffer
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:], 0x4242)
	binary.BigEndian.PutUint16(hdr[2:], 0x8180) // QR=1 (response), RD+RA
	binary.BigEndian.PutUint16(hdr[4:], 1)      // qdcount=1
	binary.BigEndian.PutUint16(hdr[6:], 3)      // ancount=3 (CNAME + 2x A)
	buf.Write(hdr)

	// Question: api.github.com A IN
	writeDNSName(&buf, "api.github.com")
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QTYPE=A
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QCLASS=IN

	writeAnswer := func(name string, rrType uint16, ttl uint32, rdata []byte) {
		writeDNSName(&buf, name)
		binary.Write(&buf, binary.BigEndian, rrType)
		binary.Write(&buf, binary.BigEndian, uint16(1)) // class IN
		binary.Write(&buf, binary.BigEndian, ttl)
		binary.Write(&buf, binary.BigEndian, uint16(len(rdata)))
		buf.Write(rdata)
	}
	// CNAME api.github.com -> github.map.fastly.net
	var cnameRD bytes.Buffer
	writeDNSName(&cnameRD, "github.map.fastly.net")
	writeAnswer("api.github.com", 5, 30, cnameRD.Bytes())
	// Two A records.
	writeAnswer("github.map.fastly.net", 1, 60, []byte{140, 82, 112, 6})
	writeAnswer("github.map.fastly.net", 1, 90, []byte{140, 82, 113, 6})

	evt := NewEngine(nil).Process(Flow{}, DirResponse, buf.Bytes())
	if evt == nil || evt.DNS == nil {
		t.Fatalf("no DNS event")
	}
	d := evt.DNS
	if !d.Response {
		t.Fatalf("response not flagged")
	}
	if d.QName != "api.github.com" {
		t.Fatalf("bad qname: %q", d.QName)
	}
	if len(d.Answers) != 3 {
		t.Fatalf("want 3 answers, got %d: %+v", len(d.Answers), d.Answers)
	}
	if d.Answers[0].Type != 5 || d.Answers[0].CNAME != "github.map.fastly.net" {
		t.Fatalf("bad CNAME answer: %+v", d.Answers[0])
	}
	if d.Answers[1].Type != 1 || d.Answers[1].IP.String() != "140.82.112.6" || d.Answers[1].TTL != 60 {
		t.Fatalf("bad A answer 1: %+v", d.Answers[1])
	}
	if d.Answers[2].IP.String() != "140.82.113.6" || d.Answers[2].TTL != 90 {
		t.Fatalf("bad A answer 2: %+v", d.Answers[2])
	}
}

func TestMySQLQuery(t *testing.T) {
	body := append([]byte{0x03}, []byte("SELECT 1")...)
	pkt := append([]byte{byte(len(body)), 0, 0, 1}, body...)
	evt := NewEngine(nil).Process(Flow{}, DirRequest, pkt)
	if evt == nil || evt.MySQL == nil {
		t.Fatalf("no MySQL event")
	}
	if evt.MySQL.Command != "query" || evt.MySQL.Query != "SELECT 1" {
		t.Fatalf("bad MySQL parse: %+v", evt.MySQL)
	}
}

func TestPostgresQuery(t *testing.T) {
	q := "SELECT 1\x00"
	body := []byte(q)
	length := uint32(4 + len(body))
	pkt := append([]byte{'Q'}, []byte{byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)}...)
	pkt = append(pkt, body...)
	evt := NewEngine(nil).Process(Flow{}, DirRequest, pkt)
	if evt == nil || evt.Postgres == nil {
		t.Fatalf("no Postgres event")
	}
	if evt.Postgres.Command != "query" || evt.Postgres.Query != "SELECT 1" {
		t.Fatalf("bad PG parse: %+v", evt.Postgres)
	}
}

func TestPostgresStartup(t *testing.T) {
	var buf bytes.Buffer
	body := []byte("user\x00alice\x00database\x00app\x00")
	length := uint32(4 + 4 + len(body))
	binary.Write(&buf, binary.BigEndian, length)
	binary.Write(&buf, binary.BigEndian, uint32(196608))
	buf.Write(body)
	evt := NewEngine(nil).Process(Flow{}, DirRequest, buf.Bytes())
	if evt == nil || evt.Postgres == nil {
		t.Fatalf("no PG startup event")
	}
	if evt.Postgres.User != "alice" || evt.Postgres.Schema != "app" {
		t.Fatalf("bad startup: %+v", evt.Postgres)
	}
}

func TestPostgresStartupShortLength(t *testing.T) {
	// Crafted StartupMessage: length=6 (< header size), version=196608.
	// The declared length is smaller than the 8-byte header, which previously
	// caused a payload[8:6] slice-bounds panic (remote DoS).
	pkt := []byte{0x00, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x00}
	evt := NewEngine(nil).Process(Flow{}, DirRequest, pkt)
	if evt != nil {
		t.Fatalf("want nil event for malformed startup, got %+v", evt)
	}
}

func TestRedis(t *testing.T) {
	raw := []byte("*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n")
	evt := NewEngine(nil).Process(Flow{}, DirRequest, raw)
	if evt == nil || evt.Redis == nil {
		t.Fatalf("no Redis event")
	}
	if evt.Redis.Command != "SET" || !reflect.DeepEqual(evt.Redis.Args, []string{"foo", "bar"}) {
		t.Fatalf("bad Redis parse: %+v", evt.Redis)
	}
}

func TestKafka(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(14)) // size
	binary.Write(&buf, binary.BigEndian, int16(18))  // apiKey=ApiVersions
	binary.Write(&buf, binary.BigEndian, int16(3))   // apiVersion=3
	binary.Write(&buf, binary.BigEndian, int32(42))  // correlationID
	cid := "test-client"
	binary.Write(&buf, binary.BigEndian, int16(len(cid)))
	buf.WriteString(cid)

	evt := NewEngine(nil).Process(Flow{}, DirRequest, buf.Bytes())
	if evt == nil || evt.Kafka == nil {
		t.Fatalf("no Kafka event")
	}
	if evt.Kafka.APIKey != 18 || evt.Kafka.ClientID != cid {
		t.Fatalf("bad Kafka parse: %+v", evt.Kafka)
	}
}

func TestEngineSinkCalled(t *testing.T) {
	var got []L7Event
	e := NewEngine(func(e L7Event) { got = append(got, e) })
	e.Process(Flow{}, DirRequest, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if len(got) != 1 || got[0].Protocol != "http" {
		t.Fatalf("sink not called: %+v", got)
	}
}
