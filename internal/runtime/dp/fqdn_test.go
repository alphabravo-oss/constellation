package dp

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/dpi"
)

var t0 = time.Unix(1_700_000_000, 0)

func ip(s string) net.IP { return net.ParseIP(s) }

// kinds returns the Kind of each message, for compact assertions.
func updateIPs(msgs []IPFqdnStorageMsg) []string {
	var out []string
	for _, m := range msgs {
		if m.Kind == KindIPFqdnStorageUpdate {
			out = append(out, m.IP.String())
		}
	}
	return out
}

func TestFqdnResolverAllowedPopulatesAndEmits(t *testing.T) {
	r := NewFqdnResolver("api.github.com")
	msgs := r.Observe("api.github.com", []ResolvedIP{
		{IP: ip("140.82.112.6"), TTL: 60},
		{IP: ip("140.82.113.6"), TTL: 60},
	}, t0)

	if len(msgs) != 2 {
		t.Fatalf("want 2 update msgs, got %d: %+v", len(msgs), msgs)
	}
	for _, m := range msgs {
		if m.Kind != KindIPFqdnStorageUpdate {
			t.Fatalf("want KindIPFqdnStorageUpdate, got %d", m.Kind)
		}
		if m.Fqdn != "api.github.com" {
			t.Fatalf("bad fqdn on update: %q", m.Fqdn)
		}
	}
	// Sorted by IP.
	if got := updateIPs(msgs); got[0] != "140.82.112.6" || got[1] != "140.82.113.6" {
		t.Fatalf("update IPs not sorted: %v", got)
	}
	live := r.Lookup("api.github.com")
	if len(live) != 2 {
		t.Fatalf("fqdnMap should hold 2 IPs, got %d", len(live))
	}
}

func TestFqdnResolverNonAllowedIgnored(t *testing.T) {
	r := NewFqdnResolver("api.github.com")
	msgs := r.Observe("evil.example.com", []ResolvedIP{{IP: ip("1.2.3.4"), TTL: 60}}, t0)
	if msgs != nil {
		t.Fatalf("non-allowed FQDN must emit nothing, got %+v", msgs)
	}
	if r.Lookup("evil.example.com") != nil {
		t.Fatalf("non-allowed FQDN must not be stored")
	}
	if r.Allowed("evil.example.com") {
		t.Fatalf("evil.example.com should not be allowed")
	}
}

func TestFqdnResolverWildcardMatch(t *testing.T) {
	r := NewFqdnResolver("*.s3.amazonaws.com")

	// Wildcard subdomain matches.
	msgs := r.Observe("my-bucket.s3.amazonaws.com", []ResolvedIP{{IP: ip("52.216.0.1"), TTL: 30}}, t0)
	if len(msgs) != 1 || msgs[0].Fqdn != "my-bucket.s3.amazonaws.com" {
		t.Fatalf("wildcard should match subdomain: %+v", msgs)
	}

	// The bare suffix must NOT match "*.suffix" (needs a label in front).
	if r.Allowed("s3.amazonaws.com") {
		t.Fatalf("bare suffix should not match *.s3.amazonaws.com")
	}
	// A different domain must not match.
	if r.Allowed("foo.s3.amazonaws.com.evil.com") {
		t.Fatalf("suffix-injection name should not match")
	}
}

func TestFqdnResolverTTLExpiryReleases(t *testing.T) {
	r := NewFqdnResolver("api.github.com")
	r.Observe("api.github.com", []ResolvedIP{
		{IP: ip("140.82.112.6"), TTL: 60},  // expires at t0+60s
		{IP: ip("140.82.113.6"), TTL: 120}, // expires at t0+120s
	}, t0)

	// Before any expiry: nothing released.
	if rel := r.Expire(t0.Add(30 * time.Second)); rel != nil {
		t.Fatalf("nothing should expire at +30s, got %+v", rel)
	}

	// At +90s the first IP is stale.
	rel := r.Expire(t0.Add(90 * time.Second))
	if len(rel) != 1 || rel[0].Kind != KindIPFqdnStorageRelease || rel[0].IP.String() != "140.82.112.6" {
		t.Fatalf("want one release for 140.82.112.6, got %+v", rel)
	}
	if rel[0].Fqdn != "" {
		t.Fatalf("release messages carry no fqdn, got %q", rel[0].Fqdn)
	}
	if live := r.Lookup("api.github.com"); len(live) != 1 || live[0].String() != "140.82.113.6" {
		t.Fatalf("expected only 140.82.113.6 live, got %v", live)
	}

	// At +200s the second IP is stale and the now-empty entry is dropped.
	rel = r.Expire(t0.Add(200 * time.Second))
	if len(rel) != 1 || rel[0].IP.String() != "140.82.113.6" {
		t.Fatalf("want release for 140.82.113.6, got %+v", rel)
	}
	if r.Lookup("api.github.com") != nil {
		t.Fatalf("entry should be gone after all IPs expire")
	}
}

func TestFqdnResolverFeedDNSResponse(t *testing.T) {
	r := NewFqdnResolver("api.github.com")
	evt := &dpi.DNSEvent{
		QName:    "api.github.com",
		Response: true,
		Answers: []dpi.DNSAnswer{
			{Name: "api.github.com", Type: 5, TTL: 30, CNAME: "x.fastly.net"}, // ignored
			{Name: "x.fastly.net", Type: 1, TTL: 60, IP: netip.MustParseAddr("140.82.112.6")},
			{Name: "x.fastly.net", Type: 28, TTL: 60, IP: netip.MustParseAddr("2606:50c0::6")},
		},
	}
	msgs := r.FeedDNSResponse(evt, t0)
	if len(msgs) != 2 {
		t.Fatalf("want 2 updates (A + AAAA), got %d: %+v", len(msgs), msgs)
	}
	if live := r.Lookup("api.github.com"); len(live) != 2 {
		t.Fatalf("want 2 live IPs, got %v", live)
	}

	// A query (not a response) is ignored.
	if got := r.FeedDNSResponse(&dpi.DNSEvent{QName: "api.github.com", Response: false}, t0); got != nil {
		t.Fatalf("non-response must be ignored, got %+v", got)
	}
}

func TestIPFqdnStorageMsgEncode(t *testing.T) {
	up := IPFqdnStorageMsg{Kind: KindIPFqdnStorageUpdate, IP: ip("140.82.112.6"), Fqdn: "api.github.com"}
	b := up.Encode()
	wantLen := dpMsgHdrSize + 16 + fqdnNameMaxLen
	if len(b) != wantLen {
		t.Fatalf("update encoded len = %d, want %d", len(b), wantLen)
	}
	hdr, off, err := decodeHdr(b)
	if err != nil {
		t.Fatalf("decodeHdr: %v", err)
	}
	if hdr.Kind != KindIPFqdnStorageUpdate {
		t.Fatalf("bad kind %d", hdr.Kind)
	}
	// IPv4 lands in the first 4 bytes (NeuVector ip4_cpy convention).
	if !bytes.Equal(b[off:off+4], []byte{140, 82, 112, 6}) {
		t.Fatalf("IPv4 not in first 4 bytes: %v", b[off:off+4])
	}
	// Name is NUL-terminated within the fixed field.
	name := cString(b[off+16:])
	if name != "api.github.com" {
		t.Fatalf("bad encoded name %q", name)
	}

	rel := IPFqdnStorageMsg{Kind: KindIPFqdnStorageRelease, IP: ip("140.82.112.6")}
	rb := rel.Encode()
	if len(rb) != dpMsgHdrSize+16 {
		t.Fatalf("release encoded len = %d, want %d", len(rb), dpMsgHdrSize+16)
	}
	if _, _, err := decodeHdr(rb); err != nil {
		t.Fatalf("release decodeHdr: %v", err)
	}
}

func TestFqdnNameTruncation(t *testing.T) {
	long := make([]byte, fqdnNameMaxLen+50)
	for i := range long {
		long[i] = 'a'
	}
	m := IPFqdnStorageMsg{Kind: KindIPFqdnStorageUpdate, IP: ip("1.2.3.4"), Fqdn: string(long)}
	b := m.Encode()
	// Name field must remain exactly fqdnNameMaxLen and stay NUL-terminated.
	nameField := b[dpMsgHdrSize+16:]
	if len(nameField) != fqdnNameMaxLen {
		t.Fatalf("name field len = %d, want %d", len(nameField), fqdnNameMaxLen)
	}
	if nameField[fqdnNameMaxLen-1] != 0 {
		t.Fatalf("name field must keep a trailing NUL terminator")
	}
}

// Ensure the binary length header is well-formed for both encodings.
func TestEncodeLengthHeader(t *testing.T) {
	for _, m := range []IPFqdnStorageMsg{
		{Kind: KindIPFqdnStorageUpdate, IP: ip("10.0.0.1"), Fqdn: "x.io"},
		{Kind: KindIPFqdnStorageRelease, IP: ip("10.0.0.1")},
	} {
		b := m.Encode()
		if int(binary.BigEndian.Uint16(b[2:4])) != len(b) {
			t.Fatalf("length header mismatch for kind %d", m.Kind)
		}
	}
}
