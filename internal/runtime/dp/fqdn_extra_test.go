package dp

import (
	"net"
	"testing"
	"time"
)

func releaseIPs(msgs []IPFqdnStorageMsg) []string {
	var out []string
	for _, m := range msgs {
		if m.Kind == KindIPFqdnStorageRelease {
			out = append(out, m.IP.String())
		}
	}
	return out
}

// Two allowed FQDNs that resolve to a shared CDN IP must reference-count it:
// expiring one name must NOT release the IP while the other still holds it.
func TestFqdnResolver_SharedIPRefcount(t *testing.T) {
	r := NewFqdnResolver("a.com", "b.com")
	shared := ip("203.0.113.7")
	r.Observe("a.com", []ResolvedIP{{IP: shared, TTL: 30}}, t0)   // expires t0+30
	r.Observe("b.com", []ResolvedIP{{IP: shared, TTL: 300}}, t0)  // expires t0+300

	// a.com's lease lapses first; the IP is still held by b.com → no release.
	rel := r.Expire(t0.Add(60 * time.Second))
	if got := releaseIPs(rel); len(got) != 0 {
		t.Fatalf("shared IP must not be released while b.com holds it, got %v", got)
	}
	if r.Lookup("a.com") != nil {
		t.Fatalf("a.com entry should be evicted")
	}
	if live := r.Lookup("b.com"); len(live) != 1 || live[0].String() != "203.0.113.7" {
		t.Fatalf("b.com should still hold the shared IP, got %v", live)
	}

	// Once b.com's lease lapses too, the last holder is gone → release.
	rel = r.Expire(t0.Add(400 * time.Second))
	if got := releaseIPs(rel); len(got) != 1 || got[0] != "203.0.113.7" {
		t.Fatalf("want one release for the shared IP, got %v", got)
	}
}

// De-authorizing an FQDN (removing it from the allow-set) must release its
// learned IPs immediately, not leave them reachable until TTL.
func TestFqdnResolver_DeauthReleases(t *testing.T) {
	r := NewFqdnResolver("a.com", "b.com")
	r.Observe("a.com", []ResolvedIP{{IP: ip("198.51.100.1"), TTL: 600}}, t0)
	r.Observe("b.com", []ResolvedIP{{IP: ip("198.51.100.2"), TTL: 600}}, t0)

	rel := r.SetAllowed([]string{"a.com"}) // b.com de-authorized
	if got := releaseIPs(rel); len(got) != 1 || got[0] != "198.51.100.2" {
		t.Fatalf("de-auth of b.com must release its IP, got %v", got)
	}
	if r.Lookup("b.com") != nil {
		t.Fatalf("b.com entry must be dropped after de-auth")
	}
	if r.Lookup("a.com") == nil {
		t.Fatalf("a.com must remain")
	}
}

// De-auth must respect refcounts: a shared IP still held by an allowed name is
// not released when the other name is de-authorized.
func TestFqdnResolver_DeauthSharedIPKept(t *testing.T) {
	r := NewFqdnResolver("a.com", "b.com")
	shared := ip("203.0.113.9")
	r.Observe("a.com", []ResolvedIP{{IP: shared, TTL: 600}}, t0)
	r.Observe("b.com", []ResolvedIP{{IP: shared, TTL: 600}}, t0)

	rel := r.SetAllowed([]string{"a.com"})
	if got := releaseIPs(rel); len(got) != 0 {
		t.Fatalf("shared IP still held by a.com must not be released, got %v", got)
	}
	if live := r.Lookup("a.com"); len(live) != 1 {
		t.Fatalf("a.com must still hold the shared IP, got %v", live)
	}
}

// A wildcard allow over an attacker-controlled zone must not grow the table
// without bound: the entry cap evicts the soonest-expiring name.
func TestFqdnResolver_EntryCapEvicts(t *testing.T) {
	r := NewFqdnResolver("*.evil.test")
	r.maxEntries = 2
	r.Observe("a.evil.test", []ResolvedIP{{IP: ip("10.0.0.1"), TTL: 30}}, t0)  // soonest
	r.Observe("b.evil.test", []ResolvedIP{{IP: ip("10.0.0.2"), TTL: 300}}, t0)
	rel := r.Observe("c.evil.test", []ResolvedIP{{IP: ip("10.0.0.3"), TTL: 300}}, t0)

	if len(r.entries) != 2 {
		t.Fatalf("entry cap should hold the table at 2, got %d", len(r.entries))
	}
	if r.Lookup("a.evil.test") != nil {
		t.Fatalf("soonest-expiring entry a.evil.test should have been evicted")
	}
	// The evicted entry's IP is released as part of the Observe that overflowed.
	if got := releaseIPs(rel); len(got) != 1 || got[0] != "10.0.0.1" {
		t.Fatalf("eviction should release the dropped entry's IP, got %v", got)
	}
}

// The per-name IP set is bounded too.
func TestFqdnResolver_PerNameIPCap(t *testing.T) {
	r := NewFqdnResolver("api.test")
	r.maxIPsPerName = 2
	r.Observe("api.test", []ResolvedIP{
		{IP: ip("10.1.0.1"), TTL: 10},
		{IP: ip("10.1.0.2"), TTL: 300},
		{IP: ip("10.1.0.3"), TTL: 300},
	}, t0)
	if live := r.Lookup("api.test"); len(live) != 2 {
		t.Fatalf("per-name IP cap should hold 2 IPs, got %d: %v", len(live), live)
	}
}

// Snapshot reflects the live table for the dp reconcile diff.
func TestFqdnResolver_Snapshot(t *testing.T) {
	r := NewFqdnResolver("a.com")
	r.Observe("a.com", []ResolvedIP{{IP: ip("192.0.2.1"), TTL: 60}, {IP: ip("192.0.2.2"), TTL: 60}}, t0)
	snap := r.Snapshot()
	got := snap["a.com"]
	if len(got) != 2 || got[0].String() != "192.0.2.1" || got[1].String() != "192.0.2.2" {
		t.Fatalf("snapshot mismatch: %v", got)
	}
	// Snapshot must be a copy — mutating it must not affect the resolver.
	got[0] = net.IPv4(9, 9, 9, 9)
	if r.Snapshot()["a.com"][0].String() != "192.0.2.1" {
		t.Fatalf("snapshot must return a copy")
	}
}

func TestFqdnAllowSet_Union(t *testing.T) {
	p1 := &WorkloadPolicy{Rules: []*PolicyRule{{Fqdn: "api.github.com"}, {Fqdn: ""}, {Fqdn: "*.s3.amazonaws.com"}}}
	p2 := &WorkloadPolicy{Rules: []*PolicyRule{{Fqdn: "api.github.com"}, nil}}
	got := FqdnAllowSet(p1, p2, nil)
	if len(got) != 2 {
		t.Fatalf("want 2 unique FQDNs, got %v", got)
	}
}
