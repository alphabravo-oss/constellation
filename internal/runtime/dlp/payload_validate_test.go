package dlp

import "testing"

// TestPayloadHasValidCreditCard is the NET-41 precision check: the raw
// credit-card regex matches BOTH numbers below (16 digits), but only the
// Luhn-valid one must survive validation — the false positive is rejected.
func TestPayloadHasValidCreditCard(t *testing.T) {
	// Both are matched by the structural regex.
	valid := "4111111111111111"   // Luhn-valid Visa test PAN
	invalid := "4111111111111112" // one digit off → fails Luhn

	if !ccCandidate.MatchString(valid) || !ccCandidate.MatchString(invalid) {
		t.Fatalf("precondition: raw regex must match both candidates")
	}
	if !PayloadHasValidCreditCard([]byte("card=" + valid + " ok")) {
		t.Errorf("valid card %q rejected", valid)
	}
	if PayloadHasValidCreditCard([]byte("order=" + invalid + " ok")) {
		t.Errorf("invalid card %q accepted (Luhn not applied)", invalid)
	}
	// Spaced/dashed grouping must still validate.
	if !PayloadHasValidCreditCard([]byte("4111 1111 1111 1111")) {
		t.Errorf("spaced valid card rejected")
	}
}

// TestPayloadHasValidSSN checks the sentinel exclusion: a structurally valid but
// non-issuable SSN (000 area) is rejected while a real one is accepted.
func TestPayloadHasValidSSN(t *testing.T) {
	if !PayloadHasValidSSN([]byte("ssn 123-45-6789 end")) {
		t.Errorf("issuable SSN rejected")
	}
	if PayloadHasValidSSN([]byte("ssn 000-45-6789 end")) {
		t.Errorf("sentinel SSN (000 area) accepted")
	}
}

// TestPayloadHasValidPII_FailOpen: an empty payload must not be treated as "no
// PII" — the agent keeps the alert when dp captured no packet bytes.
func TestPayloadHasValidPII_FailOpen(t *testing.T) {
	if PayloadHasValidPII(nil) {
		t.Errorf("nil payload must return false (agent then fails open, keeps alert)")
	}
	if !PayloadHasValidPII([]byte("pan 4111111111111111")) {
		t.Errorf("payload with valid PAN must report valid PII")
	}
}

func TestLuhnValidExported(t *testing.T) {
	if !LuhnValid("4111111111111111") {
		t.Errorf("LuhnValid rejected a valid PAN")
	}
	if LuhnValid("4111111111111112") {
		t.Errorf("LuhnValid accepted an invalid PAN")
	}
}
