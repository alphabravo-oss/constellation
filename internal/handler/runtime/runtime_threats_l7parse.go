// Wave 5b: best-effort L7 parsing of captured threat packets.
//
// dp's signature engine fires on payload patterns — when it does, it
// snapshots up to ~2 KB of the offending packet (DPLOG_MAX_PKT_LEN). The
// per-threat drilldown surfaces those bytes verbatim as a hex dump, but
// "what the user usually wants" is the parsed shape: which URL was hit,
// which DNS name was queried, which TLS hostname tripped the alarm.
//
// We do NOT re-implement the full DPI here — dp already parsed it
// authoritatively. The point of this file is to give the UI a one-line
// "here's the gist of the payload" without needing the agent to ship the
// parsed form across the wire.
//
// All parsers tolerate truncation; dp's CapLen may be larger than PktLen,
// meaning the rest of the packet existed on the wire but didn't make it
// into the captured bytes.
package runtime

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// parsePacketL7 picks one of the protocol parsers based on cheap heuristics
// (destination port and the first few bytes of the payload). The packet
// bytes can be a full Ethernet frame, an IP datagram, or a stripped L7
// payload — dp's capture point varies — so each parser does its own
// header-skipping work.
func parsePacketL7(pkt []byte, dstPort int) *ThreatL7Preview {
	if len(pkt) == 0 {
		return nil
	}
	// Skip any Ethernet/IP/TCP/UDP header dp may have included by hunting
	// for the start of an L7 payload. Heuristic: try the original buffer
	// first; if no parser fires, strip likely headers and retry.
	for _, candidate := range [][]byte{pkt, skipLikelyHeaders(pkt)} {
		if len(candidate) == 0 {
			continue
		}
		if p := tryHTTP(candidate); p != nil {
			return &ThreatL7Preview{Kind: "http", HTTP: p}
		}
		if p := tryDNS(candidate, dstPort); p != nil {
			return &ThreatL7Preview{Kind: "dns", DNS: p}
		}
		if p := tryTLS(candidate); p != nil {
			return &ThreatL7Preview{Kind: "tls", TLS: p}
		}
	}
	return nil
}

// skipLikelyHeaders tries to advance past Ethernet (14) + IPv4 (20+) + TCP/UDP
// (20+/8) headers. If the result doesn't look reasonable (eg. negative or too
// short) we return the original. Best-effort — we don't actually parse the
// fields, just step over by canonical sizes.
func skipLikelyHeaders(pkt []byte) []byte {
	// Ethernet II = 14 bytes (no VLAN tag handled). IPv4 with no options = 20.
	// TCP header without options = 20; UDP = 8. Try the most common case
	// (Eth + IPv4 + TCP).
	const off = 14 + 20 + 20
	if len(pkt) > off {
		return pkt[off:]
	}
	// Fall back to just-IP (raw IP capture).
	if len(pkt) > 40 {
		return pkt[40:]
	}
	return nil
}

// tryHTTP recognises an HTTP/1.x request or response start line followed by
// CRLF-separated headers. Anchored against the standard request methods +
// the "HTTP/" version sentinel to avoid false positives on arbitrary text.
func tryHTTP(pkt []byte) *HTTPRequestPreview {
	// First line should fit a recognisable HTTP request method or response.
	// Look for the first "\r\n" or "\n" to bound the start line.
	end := bytes.IndexByte(pkt, '\n')
	if end < 4 || end > 4096 {
		return nil
	}
	line := strings.TrimRight(string(pkt[:end]), "\r")
	// Response shape: "HTTP/1.1 200 OK".
	if strings.HasPrefix(line, "HTTP/") {
		parts := strings.SplitN(line, " ", 2)
		out := &HTTPRequestPreview{Method: "RESPONSE", Version: parts[0]}
		if len(parts) >= 2 {
			out.Target = parts[1]
		}
		return out
	}
	// Request shape: "METHOD SP target SP HTTP/x.y". The target can contain
	// spaces in attacker payloads (eg. raw SQL injection), so split the
	// METHOD off the front and the version off the BACK rather than
	// splitting on every space.
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return nil
	}
	method := line[:sp]
	if !isHTTPMethod(method) {
		return nil
	}
	startTail := line[sp+1:]
	var target, version string
	// Find " HTTP/" anchored from the end so the version always lands cleanly.
	if vIdx := strings.LastIndex(startTail, " HTTP/"); vIdx >= 0 {
		target = startTail[:vIdx]
		version = startTail[vIdx+1:]
	} else {
		target = startTail
	}
	out := &HTTPRequestPreview{Method: method, Target: target, Version: version}
	// Pluck the small set of high-value headers without doing a full RFC
	// 7230 parse. Cap at 8 — anything more is dp's job.
	headers := map[string]string{}
	rest := pkt[end+1:]
	for i := 0; i < 32 && len(rest) > 0; i++ {
		nl := bytes.IndexByte(rest, '\n')
		if nl <= 0 {
			break
		}
		hline := strings.TrimRight(string(rest[:nl]), "\r")
		rest = rest[nl+1:]
		if hline == "" {
			break // end of headers
		}
		colon := strings.IndexByte(hline, ':')
		if colon <= 0 {
			break
		}
		name := strings.TrimSpace(hline[:colon])
		value := strings.TrimSpace(hline[colon+1:])
		switch strings.ToLower(name) {
		case "host", "user-agent", "content-type", "content-length",
			"referer", "x-forwarded-for", "authorization", "cookie":
			// Truncate ridiculously long values so a payload-stuffing
			// attacker can't blow up the response.
			if len(value) > 256 {
				value = value[:256] + "…"
			}
			headers[name] = value
			if len(headers) >= 8 {
				break
			}
		}
	}
	if len(headers) > 0 {
		out.Headers = headers
	}
	// Truncate target similarly.
	if len(out.Target) > 512 {
		out.Target = out.Target[:512] + "…"
	}
	return out
}

func isHTTPMethod(s string) bool {
	switch s {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH",
		"CONNECT", "TRACE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
		"MOVE", "LOCK", "UNLOCK":
		return true
	}
	return false
}

// tryDNS recognises a DNS query/response packet. Heuristic: dst_port == 53
// (UDP) or 853 (DoT) and the buffer starts with a sane DNS header.
// We pull out the first question's qname and qtype which is the highest-
// signal piece for a threat drilldown ("dp fired on this lookup").
func tryDNS(pkt []byte, dstPort int) *DNSQueryPreview {
	if dstPort != 53 && dstPort != 853 && dstPort != 5353 {
		return nil
	}
	// DNS header is 12 bytes: id(2), flags(2), qdcount(2), ancount(2), nscount(2), arcount(2).
	if len(pkt) < 12+1 {
		return nil
	}
	qdcount := binary.BigEndian.Uint16(pkt[4:6])
	if qdcount == 0 {
		return nil
	}
	off := 12
	// Walk the qname: a sequence of length-prefixed labels terminated by 0.
	// Cap loop iterations to defend against compression pointer loops; we
	// don't follow pointers at all (they're rare in queries).
	var labels []string
	for i := 0; i < 32; i++ {
		if off >= len(pkt) {
			return nil
		}
		n := int(pkt[off])
		off++
		if n == 0 {
			break
		}
		if n&0xC0 != 0 {
			// Compression pointer — bail rather than chase it.
			return nil
		}
		if off+n > len(pkt) || n > 63 {
			return nil
		}
		labels = append(labels, string(pkt[off:off+n]))
		off += n
	}
	if len(labels) == 0 {
		return nil
	}
	out := &DNSQueryPreview{QName: strings.Join(labels, ".")}
	// qtype is the 2 bytes after the qname's trailing zero.
	if off+2 <= len(pkt) {
		qt := binary.BigEndian.Uint16(pkt[off : off+2])
		out.QType = dnsTypeString(qt)
	}
	return out
}

func dnsTypeString(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 35:
		return "NAPTR"
	case 41:
		return "OPT"
	case 65:
		return "HTTPS"
	case 255:
		return "ANY"
	}
	return ""
}

// tryTLS recognises a TLS ClientHello and extracts the SNI extension. dp's
// SSL_TLS_1DOT0 / SSL_HEARTBLEED / SSL_CIPHER_OVF signatures all fire on
// the first record of a handshake, so the captured bytes almost always
// contain a ClientHello when the threat is SSL-class.
//
// The parser is intentionally permissive: we only need to spot the
// handshake type byte (0x16 = TLS handshake), step over the record header,
// and locate the SNI extension (type 0x0000).
func tryTLS(pkt []byte) *TLSHelloPreview {
	if len(pkt) < 43 {
		return nil
	}
	// TLS record: type(1)=0x16, version(2), length(2), then handshake.
	if pkt[0] != 0x16 {
		return nil
	}
	if pkt[1] != 0x03 {
		return nil // not TLS 1.x family
	}
	// Handshake header: type(1)=0x01 (ClientHello), length(3), version(2),
	// random(32), session_id_length(1), session_id(...), cipher_suites_len(2),
	// cipher_suites(...), compression_methods_len(1), compression(...),
	// extensions_len(2), extensions(...).
	hs := pkt[5:]
	if len(hs) < 1+3+2+32+1 {
		return nil
	}
	if hs[0] != 0x01 {
		return nil // not ClientHello
	}
	versionMajor := hs[4]
	versionMinor := hs[5]
	off := 1 + 3 + 2 + 32
	sidLen := int(hs[off])
	off += 1 + sidLen
	if off+2 > len(hs) {
		return nil
	}
	csLen := int(binary.BigEndian.Uint16(hs[off : off+2]))
	off += 2 + csLen
	if off+1 > len(hs) {
		return nil
	}
	cmLen := int(hs[off])
	off += 1 + cmLen
	if off+2 > len(hs) {
		// No extensions — still surface the version.
		return &TLSHelloPreview{Version: tlsVersionString(versionMajor, versionMinor)}
	}
	extTotal := int(binary.BigEndian.Uint16(hs[off : off+2]))
	off += 2
	if off+extTotal > len(hs) {
		extTotal = len(hs) - off
	}
	end := off + extTotal
	out := &TLSHelloPreview{Version: tlsVersionString(versionMajor, versionMinor)}
	for off+4 <= end {
		extType := binary.BigEndian.Uint16(hs[off : off+2])
		extLen := int(binary.BigEndian.Uint16(hs[off+2 : off+4]))
		off += 4
		if off+extLen > end {
			break
		}
		if extType == 0x0000 { // server_name
			out.SNI = parseSNI(hs[off : off+extLen])
			break
		}
		off += extLen
	}
	return out
}

func parseSNI(b []byte) string {
	// server_name_list_length(2) | name_type(1)=0x00 | hostname_length(2) | hostname...
	if len(b) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(b[:2]))
	if listLen+2 > len(b) {
		return ""
	}
	if b[2] != 0x00 {
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(b[3:5]))
	if 5+nameLen > len(b) {
		return ""
	}
	return string(b[5 : 5+nameLen])
}

func tlsVersionString(major, minor byte) string {
	if major != 0x03 {
		return ""
	}
	switch minor {
	case 0x00:
		return "SSL 3.0"
	case 0x01:
		return "TLS 1.0"
	case 0x02:
		return "TLS 1.1"
	case 0x03:
		return "TLS 1.2"
	case 0x04:
		return "TLS 1.3"
	}
	return ""
}
