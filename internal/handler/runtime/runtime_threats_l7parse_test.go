package runtime

import "testing"

// TestParsePacketL7_HTTP covers the SQL_INJECTION-shaped capture that
// Wave 5's ingest test rounds through the DB. Verifies method, target, and
// the high-signal Host header.
func TestParsePacketL7_HTTP(t *testing.T) {
	pkt := []byte("GET /products?id=1' OR '1'='1 HTTP/1.1\r\n" +
		"Host: shop.example\r\n" +
		"User-Agent: sqlmap/1.7\r\n" +
		"Cookie: PHPSESSID=abc\r\n" +
		"\r\n")
	got := parsePacketL7(pkt, 8080)
	if got == nil || got.Kind != "http" || got.HTTP == nil {
		t.Fatalf("got %+v, want http preview", got)
	}
	if got.HTTP.Method != "GET" {
		t.Errorf("method=%q want GET", got.HTTP.Method)
	}
	if got.HTTP.Target == "" || got.HTTP.Target[:1] != "/" {
		t.Errorf("target=%q", got.HTTP.Target)
	}
	if got.HTTP.Version != "HTTP/1.1" {
		t.Errorf("version=%q", got.HTTP.Version)
	}
	if got.HTTP.Headers["Host"] != "shop.example" {
		t.Errorf("Host header missing: %+v", got.HTTP.Headers)
	}
	if got.HTTP.Headers["User-Agent"] != "sqlmap/1.7" {
		t.Errorf("UA missing: %+v", got.HTTP.Headers)
	}
}

// TestParsePacketL7_DNSQuery hand-builds a minimal A-record query for
// "tunnel.evil.example" (the kind of payload DNS_TUNNELING fires on).
func TestParsePacketL7_DNSQuery(t *testing.T) {
	// header: id=0xABCD, flags=0x0100 (standard query, RD), qdcount=1, others=0
	hdr := []byte{0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// qname: 6"tunnel" 4"evil" 7"example" 0
	qname := []byte{6, 't', 'u', 'n', 'n', 'e', 'l', 4, 'e', 'v', 'i', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
	// qtype=A(1), qclass=IN(1)
	tail := []byte{0x00, 0x01, 0x00, 0x01}
	pkt := append(append(hdr, qname...), tail...)

	got := parsePacketL7(pkt, 53)
	if got == nil || got.Kind != "dns" || got.DNS == nil {
		t.Fatalf("got %+v, want dns preview", got)
	}
	if got.DNS.QName != "tunnel.evil.example" {
		t.Errorf("qname=%q", got.DNS.QName)
	}
	if got.DNS.QType != "A" {
		t.Errorf("qtype=%q want A", got.DNS.QType)
	}
}

// TestParsePacketL7_TLSClientHello recognises a minimal TLS 1.2 ClientHello
// with an SNI extension for "vault.example.com". This is the payload shape
// dp's SSL_TLS_1DOT0 / SSL_CIPHER_OVF / HEARTBLEED signatures fire on.
func TestParsePacketL7_TLSClientHello(t *testing.T) {
	// Build the SNI extension bytes first so we can compute lengths.
	sni := "vault.example.com"
	sniExt := func() []byte {
		hostname := []byte(sni)
		// server_name_list: name_type(1)=0 + hostname_length(2) + hostname
		entry := append([]byte{0x00, byte(len(hostname) >> 8), byte(len(hostname))}, hostname...)
		listLen := len(entry)
		// extension data: server_name_list_length(2) + entries
		body := append([]byte{byte(listLen >> 8), byte(listLen)}, entry...)
		return body
	}()
	extType := []byte{0x00, 0x00} // server_name
	extLen := []byte{byte(len(sniExt) >> 8), byte(len(sniExt))}
	extensions := append(append(extType, extLen...), sniExt...)
	extTotalLen := []byte{byte(len(extensions) >> 8), byte(len(extensions))}

	// Handshake body:
	//   client_version(2)=0x0303(TLS1.2), random(32), sid_len(1)=0,
	//   cipher_suites_len(2)=2, cipher_suites=0x002F (1 suite),
	//   compression_methods_len(1)=1, compression=0x00,
	//   extensions_len(2), extensions...
	hsBody := []byte{0x03, 0x03}
	hsBody = append(hsBody, make([]byte, 32)...) // random
	hsBody = append(hsBody, 0x00)                // sid len
	hsBody = append(hsBody, 0x00, 0x02, 0x00, 0x2F)
	hsBody = append(hsBody, 0x01, 0x00) // compression methods
	hsBody = append(hsBody, extTotalLen...)
	hsBody = append(hsBody, extensions...)

	// Handshake header: type(1)=0x01 ClientHello, length(3) = len(hsBody)
	hsLen := len(hsBody)
	handshake := append([]byte{0x01, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}, hsBody...)

	// Record layer: type(1)=0x16 Handshake, version(2)=0x0303, length(2)
	recLen := len(handshake)
	record := append([]byte{0x16, 0x03, 0x03, byte(recLen >> 8), byte(recLen)}, handshake...)

	got := parsePacketL7(record, 443)
	if got == nil || got.Kind != "tls" || got.TLS == nil {
		t.Fatalf("got %+v, want tls preview", got)
	}
	if got.TLS.SNI != sni {
		t.Errorf("SNI=%q want %q", got.TLS.SNI, sni)
	}
	if got.TLS.Version != "TLS 1.2" {
		t.Errorf("version=%q want TLS 1.2", got.TLS.Version)
	}
}

// TestParsePacketL7_NoMatch verifies parsers don't false-positive on random
// bytes — we explicitly want the API to return l7=null rather than guessing.
func TestParsePacketL7_NoMatch(t *testing.T) {
	garbage := []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8}
	if got := parsePacketL7(garbage, 12345); got != nil {
		t.Errorf("got %+v, want nil for garbage", got)
	}
}
