package sigverify

import "testing"

// cosignVerifySingleSig is a representative `cosign verify --output json` blob for a
// keyless, single-signature image (cosign 2.x). Pinned as a fixture so a future cosign
// output-shape change is caught by this test rather than silently returning empty.
const cosignVerifySingleSig = `[
  {
    "critical": {
      "identity": {"docker-reference": "ghcr.io/acme/app"},
      "image": {"docker-manifest-digest": "sha256:aaaa"},
      "type": "cosign container image signature"
    },
    "optional": {
      "Subject": "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main",
      "Issuer": "https://token.actions.githubusercontent.com",
      "Bundle": {"SignedEntryTimestamp": "MEUCIQ=="}
    }
  }
]`

// cosignVerifyMultiSig is a multi-signature image where the FIRST signature is from an
// untrusted identity and only the SECOND matches the trust policy. First-match regex
// scraping would have locked onto the first (untrusted) signature and rejected the image.
const cosignVerifyMultiSig = `[
  {
    "critical": {"identity": {"docker-reference": "ghcr.io/acme/app"}},
    "optional": {
      "Subject": "https://github.com/attacker/evil/.github/workflows/x.yml@refs/heads/main",
      "Issuer": "https://token.actions.githubusercontent.com"
    }
  },
  {
    "critical": {"identity": {"docker-reference": "ghcr.io/acme/app"}},
    "optional": {
      "Subject": "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main",
      "Issuer": "https://token.actions.githubusercontent.com"
    }
  }
]`

func TestDecodeCosignSignaturesSingleSig(t *testing.T) {
	sigs := decodeCosignSignatures([]byte(cosignVerifySingleSig))
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}
	if got := sigs[0].identity(); got != "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main" {
		t.Fatalf("identity = %q", got)
	}
	if got := sigs[0].issuer(); got != "https://token.actions.githubusercontent.com" {
		t.Fatalf("issuer = %q", got)
	}
}

func TestPickTrustedIdentitySingleSig(t *testing.T) {
	policy := TrustPolicy{
		Identities: []string{`https://github\.com/acme/app/.*`},
		Issuers:    []string{`https://token\.actions\.githubusercontent\.com`},
	}
	id, iss, trusted := pickTrustedIdentity(policy, decodeCosignSignatures([]byte(cosignVerifySingleSig)))
	if !trusted {
		t.Fatalf("single trusted signature should be trusted: id=%q iss=%q", id, iss)
	}
}

// TestPickTrustedIdentityMultiSigSecondMatches is the load-bearing regression: a multi-sig
// image whose only policy-matching signature is the SECOND one must be trusted. The old
// first-match regex would have evaluated the attacker's identity and failed closed.
func TestPickTrustedIdentityMultiSigSecondMatches(t *testing.T) {
	policy := TrustPolicy{
		Identities: []string{`https://github\.com/acme/app/.*`},
		Issuers:    []string{`https://token\.actions\.githubusercontent\.com`},
	}
	id, iss, trusted := pickTrustedIdentity(policy, decodeCosignSignatures([]byte(cosignVerifyMultiSig)))
	if !trusted {
		t.Fatalf("image with a matching second signature must be trusted: id=%q iss=%q", id, iss)
	}
	if id != "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main" {
		t.Fatalf("trusted identity should be the matching (second) signature, got %q", id)
	}
}

func TestPickTrustedIdentityNoMatch(t *testing.T) {
	policy := TrustPolicy{
		Identities: []string{`https://github\.com/someone-else/.*`},
		Issuers:    []string{`https://token\.actions\.githubusercontent\.com`},
	}
	id, _, trusted := pickTrustedIdentity(policy, decodeCosignSignatures([]byte(cosignVerifyMultiSig)))
	if trusted {
		t.Fatalf("no signature matches policy, must be untrusted")
	}
	// Falls back to the first signature for the human reason string.
	if id != "https://github.com/attacker/evil/.github/workflows/x.yml@refs/heads/main" {
		t.Fatalf("untrusted fallback identity = %q", id)
	}
}

// cosignVerifySuperstringSig is the trust-widening attack: the trusted policy is the
// repo "https://github.com/acme/app", and the attacker signs from the SIBLING repo
// "https://github.com/acme/app-evil". An unanchored substring match would treat the
// attacker identity as trusted because it CONTAINS the trusted prefix.
const cosignVerifySuperstringSig = `[
  {
    "critical": {"identity": {"docker-reference": "ghcr.io/acme/app"}},
    "optional": {
      "Subject": "https://github.com/acme/app-evil/.github/workflows/x.yml@refs/heads/main",
      "Issuer": "https://token.actions.githubusercontent.com"
    }
  }
]`

// TestSignatureTrustRejectsSuperstringIdentity is the load-bearing security regression
// for the anchoring fix: a sibling-repo superstring identity must NOT be trusted, for
// both a careless bare pattern and a prefix pattern.
func TestSignatureTrustRejectsSuperstringIdentity(t *testing.T) {
	for name, identities := range map[string][]string{
		"bare":   {`https://github.com/acme/app`},
		"prefix": {`https://github\.com/acme/app/.*`},
	} {
		t.Run(name, func(t *testing.T) {
			policy := TrustPolicy{
				Identities: identities,
				Issuers:    []string{`https://token\.actions\.githubusercontent\.com`},
			}
			_, _, trusted := pickTrustedIdentity(policy, decodeCosignSignatures([]byte(cosignVerifySuperstringSig)))
			if trusted {
				t.Fatalf("superstring sibling-repo identity must not be trusted (pattern %v)", identities)
			}
			// And the legitimate identity under the same policy is still trusted for the prefix form.
			if name == "prefix" {
				_, _, ok := pickTrustedIdentity(policy, decodeCosignSignatures([]byte(cosignVerifySingleSig)))
				if !ok {
					t.Fatal("legitimate acme/app identity must remain trusted under the anchored prefix policy")
				}
			}
		})
	}
}

func TestJoinAltAnchorsForCosign(t *testing.T) {
	got := joinAlt([]string{`https://github\.com/acme/app/.*`, `ci@example\.test`})
	want := `^(?:https://github\.com/acme/app/.*|ci@example\.test)$`
	if got != want {
		t.Fatalf("joinAlt = %q, want %q", got, want)
	}
	if joinAlt(nil) != "^.*$" {
		t.Fatalf("empty joinAlt = %q", joinAlt(nil))
	}
}

func TestDecodeCosignSignaturesMalformedIsUntrusted(t *testing.T) {
	for name, blob := range map[string]string{
		"empty":     "",
		"emptyArr":  "[]",
		"garbage":   "not json at all",
		"object":    `{"unexpected":"shape"}`,
		"truncated": `[{"optional":{"Subject":"x"`,
	} {
		t.Run(name, func(t *testing.T) {
			sigs := decodeCosignSignatures([]byte(blob))
			_, _, trusted := pickTrustedIdentity(TrustPolicy{
				Identities: []string{".*"},
				Issuers:    []string{".*"},
			}, sigs)
			if trusted {
				t.Fatalf("malformed/empty cosign output (%q) must not be trusted", name)
			}
		})
	}
}
