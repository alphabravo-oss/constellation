// Package dpi is the userspace L7 protocol-parsing engine that sits between the
// kernel data-plane (NFQUEUE / pcap) and the WAF + DLP rule engines.
//
// Supported protocols (parsers in this package):
//
//	HTTP/1.1     parseHTTP1
//	HTTP/2       parseHTTP2 (HPACK header decoding)
//	gRPC         parseGRPC  (HTTP/2 with content-type=application/grpc)
//	DNS          parseDNS
//	MySQL wire   parseMySQL  (handshake + COM_QUERY)
//	Postgres     parsePostgres (StartupMessage + Query)
//	Redis RESP   parseRedis
//	Kafka        parseKafka  (request header only)
//
// Architecture:
//
//	+--------+   payload bytes   +-------------+   L7Event    +------+
//	| source | ----------------> | Detect/Parse | -----------> | sink |
//	+--------+                    +-------------+              +------+
//	(NFQUEUE / pcap / unit-test)                               (WAF, DLP)
//
// The Engine type owns the parser registry. Source code does NOT depend on libpcap or
// libnfqueue here — the kernel-attached source lives in a separate file behind a
// `//go:build linux && cgo` tag. Tests pump bytes through Engine.Process directly.
package dpi

import (
	"net/netip"
	"strings"
	"time"
)

// Direction marks who is talking.
type Direction uint8

const (
	DirRequest Direction = iota
	DirResponse
)

// Flow identifies a logical L7 conversation. WorkloadID is filled in by the agent
// from a pid → pod mapping; for raw NFQUEUE captures it may be empty.
type Flow struct {
	WorkloadID string
	ContainerID string
	Src        netip.AddrPort
	Dst        netip.AddrPort
	Protocol   string // "tcp" | "udp"
	PID        uint32
}

// L7Event is the typed L7 record emitted by a parser. Exactly one of the protocol-
// specific fields is non-nil (HTTP, DNS, MySQL, Postgres, Redis, Kafka).
type L7Event struct {
	Flow     Flow
	At       time.Time
	Protocol string // "http" | "http2" | "grpc" | "dns" | "mysql" | "postgres" | "redis" | "kafka"
	Dir      Direction
	HTTP     *HTTPEvent
	DNS      *DNSEvent
	MySQL    *MySQLEvent
	Postgres *PostgresEvent
	Redis    *RedisEvent
	Kafka    *KafkaEvent
}

// HTTPEvent is one request or response (HTTP/1.1, HTTP/2, gRPC).
type HTTPEvent struct {
	Method     string
	Path       string
	Host       string
	Query      string // raw query string (no leading ?)
	Version    string // "HTTP/1.1" | "HTTP/2" | "gRPC"
	Headers    map[string][]string
	Body       []byte // may be truncated; see Truncated
	Truncated  bool
	StatusCode int    // response only
	Service    string // gRPC: service name from :path = /pkg.Service/Method
	RPC        string // gRPC: method name
}

// DNSEvent captures the question section of a DNS request and, for responses,
// the A/AAAA/CNAME answer records. The FQDN resolver (internal/runtime/dp)
// consumes Answers to learn which IPs an allowed name currently maps to.
type DNSEvent struct {
	TxnID    uint16
	QType    uint16 // 1=A, 28=AAAA, 5=CNAME, 16=TXT, ...
	QName    string
	Queries  []string
	Response bool        // QR bit set → this is a response, Answers may be populated
	Answers  []DNSAnswer // A/AAAA/CNAME records (responses only)
}

// DNSAnswer is one resource record from a DNS response's answer section. Only
// the record types the FQDN datapath cares about are decoded (A, AAAA, CNAME);
// other types still consume their rdata but carry no IP/Target.
type DNSAnswer struct {
	Name  string     // owner name of the record
	Type  uint16     // 1=A, 28=AAAA, 5=CNAME
	TTL   uint32     // seconds the answer may be cached
	IP    netip.Addr // valid for A/AAAA; zero Addr otherwise
	CNAME string     // canonical name target for CNAME records
}

// MySQLEvent captures a MySQL wire-protocol observation.
type MySQLEvent struct {
	Command string // "handshake" | "query" | "init-db" | ...
	Query   string
	User    string
	Schema  string
}

// PostgresEvent captures a Postgres wire-protocol observation.
type PostgresEvent struct {
	Command string // "startup" | "query" | "parse" | "bind"
	Query   string
	User    string
	Schema  string
}

// RedisEvent captures one RESP command.
type RedisEvent struct {
	Command string
	Args    []string
}

// KafkaEvent captures one Kafka request header.
type KafkaEvent struct {
	APIKey     int16
	APIVersion int16
	Correlation int32
	ClientID   string
}

// Parser is the signature every L7 parser implements. It returns nil if the bytes
// don't match its protocol (so a downstream detector can try the next parser).
type Parser func(flow Flow, dir Direction, payload []byte) *L7Event

// Engine is the registry + dispatch loop. Construct with NewEngine and feed bytes
// via Process. The engine itself is stateless — keyed conversation state belongs in
// per-flow caches owned by the caller (the kernel agent maintains those).
type Engine struct {
	parsers []namedParser
	sink    func(L7Event)
	clock   func() time.Time
}

type namedParser struct {
	name  string
	parse Parser
}

// NewEngine builds an Engine wired to `sink`. If sink is nil the engine still parses
// but drops events on the floor; useful for benchmarks.
func NewEngine(sink func(L7Event)) *Engine {
	e := &Engine{sink: sink, clock: time.Now}
	e.parsers = []namedParser{
		{"http", parseHTTP1},
		{"http2", parseHTTP2},
		{"dns", parseDNS},
		{"mysql", parseMySQL},
		{"postgres", parsePostgres},
		{"redis", parseRedis},
		{"kafka", parseKafka},
	}
	return e
}

// SetClock injects a clock (tests).
func (e *Engine) SetClock(now func() time.Time) { e.clock = now }

// Process feeds one TCP segment / UDP payload through the parsers. The first parser
// to return a non-nil event wins. Returns the emitted event (or nil).
func (e *Engine) Process(flow Flow, dir Direction, payload []byte) *L7Event {
	if len(payload) == 0 {
		return nil
	}
	for _, p := range e.parsers {
		evt := p.parse(flow, dir, payload)
		if evt == nil {
			continue
		}
		evt.At = e.clock()
		if e.sink != nil {
			e.sink(*evt)
		}
		return evt
	}
	return nil
}

// ProcessHTTP is a convenience for callers that have already classified the payload
// (e.g. the WAF sidecar that knows it's parsing HTTP). It runs only the HTTP parsers.
func (e *Engine) ProcessHTTP(flow Flow, dir Direction, payload []byte) *L7Event {
	if evt := parseHTTP1(flow, dir, payload); evt != nil {
		evt.At = e.clock()
		if e.sink != nil {
			e.sink(*evt)
		}
		return evt
	}
	if evt := parseHTTP2(flow, dir, payload); evt != nil {
		evt.At = e.clock()
		if e.sink != nil {
			e.sink(*evt)
		}
		return evt
	}
	return nil
}

// canonicalHeader is the tiny canonicalizer the parsers share. We do NOT use
// textproto.CanonicalMIMEHeaderKey because we want lowercase keys (consistent with
// HTTP/2's lowercase requirement, and WAF rules target lowercase).
func canonicalHeader(k string) string { return strings.ToLower(strings.TrimSpace(k)) }
