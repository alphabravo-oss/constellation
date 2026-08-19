package dpi

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

// parseDNS decodes the question section of a DNS message. We avoid pulling miekg/dns
// — the wire format is tiny and the WAF/DLP path only needs question + qtype.
func parseDNS(flow Flow, dir Direction, payload []byte) *L7Event {
	if len(payload) < 12 {
		return nil
	}
	txn := binary.BigEndian.Uint16(payload[0:2])
	flags := binary.BigEndian.Uint16(payload[2:4])
	qdcount := binary.BigEndian.Uint16(payload[4:6])
	ancount := binary.BigEndian.Uint16(payload[6:8])
	if qdcount == 0 || qdcount > 32 {
		return nil
	}
	isResponse := (flags>>15)&0x1 == 1
	// Sanity: opcode must be 0 (QUERY) for both request and response, and the QR bit
	// matches the direction.
	opcode := (flags >> 11) & 0xF
	if opcode != 0 {
		return nil
	}

	off := 12
	names := make([]string, 0, qdcount)
	var firstType uint16
	for range qdcount {
		name, n, ok := readDNSName(payload, off)
		if !ok {
			return nil
		}
		off = n
		if off+4 > len(payload) {
			return nil
		}
		qtype := binary.BigEndian.Uint16(payload[off : off+2])
		off += 4 // qtype + qclass
		names = append(names, name)
		if firstType == 0 {
			firstType = qtype
		}
	}
	// Answer section (responses only). Best-effort: a malformed RR stops the
	// walk but we still surface the question + whatever answers parsed cleanly.
	var answers []DNSAnswer
	if isResponse && ancount > 0 && ancount <= 256 {
		answers = parseDNSAnswers(payload, off, int(ancount))
	}

	return &L7Event{
		Flow: flow, Protocol: "dns", Dir: dir,
		DNS: &DNSEvent{
			TxnID: txn, QType: firstType, QName: names[0], Queries: names,
			Response: isResponse, Answers: answers,
		},
	}
}

// parseDNSAnswers decodes up to `count` resource records starting at `off`.
// Each RR is: name (compressible) | type(2) | class(2) | ttl(4) | rdlength(2)
// | rdata. Only A/AAAA/CNAME rdata is interpreted; other types are skipped by
// rdlength. Returns the records parsed before the first malformed entry.
func parseDNSAnswers(buf []byte, off, count int) []DNSAnswer {
	out := make([]DNSAnswer, 0, count)
	for range count {
		name, n, ok := readDNSName(buf, off)
		if !ok {
			break
		}
		off = n
		if off+10 > len(buf) {
			break
		}
		rrType := binary.BigEndian.Uint16(buf[off : off+2])
		ttl := binary.BigEndian.Uint32(buf[off+4 : off+8])
		rdlength := int(binary.BigEndian.Uint16(buf[off+8 : off+10]))
		off += 10
		if off+rdlength > len(buf) {
			break
		}
		ans := DNSAnswer{Name: name, Type: rrType, TTL: ttl}
		switch rrType {
		case 1: // A
			if rdlength == 4 {
				ans.IP = netip.AddrFrom4([4]byte(buf[off : off+4]))
			}
		case 28: // AAAA
			if rdlength == 16 {
				ans.IP = netip.AddrFrom16([16]byte(buf[off : off+16]))
			}
		case 5: // CNAME
			if cname, _, cok := readDNSName(buf, off); cok {
				ans.CNAME = cname
			}
		}
		out = append(out, ans)
		off += rdlength
	}
	return out
}

// readDNSName decodes a DNS name with pointer-compression support. Returns the
// dotted form and the new offset.
func readDNSName(buf []byte, off int) (string, int, bool) {
	var parts []string
	visited := map[int]bool{}
	end := off
	jumped := false
	for {
		if off >= len(buf) {
			return "", 0, false
		}
		l := int(buf[off])
		if l == 0 {
			off++
			if !jumped {
				end = off
			}
			return strings.Join(parts, "."), end, true
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(buf) {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(buf[off:off+2]) & 0x3FFF)
			if visited[ptr] {
				return "", 0, false
			}
			visited[ptr] = true
			if !jumped {
				end = off + 2
				jumped = true
			}
			off = ptr
			continue
		}
		off++
		if off+l > len(buf) || l > 63 {
			return "", 0, false
		}
		parts = append(parts, string(buf[off:off+l]))
		off += l
	}
}
