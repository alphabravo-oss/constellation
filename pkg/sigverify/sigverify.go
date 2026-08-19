// Package sigverify wraps cosign image-signature verification + a small policy engine
// that decides whether the verified identity is trusted.
//
// Trust policy shape (the spec's "configured trust policy"):
//
//	identities: ["https://github.com/alphabravocompany/**", "ci@example.test"]
//	issuers:    ["https://token.actions.githubusercontent.com"]
//	require_rekor: true
//	require_attestations: ["slsa.dev/provenance/v1"]
//
// Verification is shelled out to cosign 2.x which is already pinned in the scanner image.
// We do NOT vendor cosign's Go API at v1 (it's still pre-1.0 + frequently breaks).
package sigverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// TrustPolicy is the per-org configuration that determines whether an image-signature
// chain is acceptable.
type TrustPolicy struct {
	Mode                string   // keyless (default) or public-key
	Identities          []string // regex / glob patterns
	Issuers             []string // regex patterns (matches Fulcio cert OIDC issuer)
	RequireRekor        bool
	RequireAttestations []string // predicate types that must each have ≥1 attestation
	PublicKeyPEM        string   // cosign public key material for Mode=public-key
	PublicKeyPath       string   // cosign public key path for Mode=public-key
}

// Result is the outcome of verifying an image.
type Result struct {
	ImageRef     string
	Signed       bool
	Trusted      bool // signed AND identity ∈ policy.Identities AND issuer ∈ policy.Issuers
	Identity     string
	Issuer       string
	RekorLog     string
	Attestations []string
	Reason       string // human-readable explanation
}

// AttestationResult is the outcome of verifying an OCI-attached in-toto
// attestation for a subject reference.
type AttestationResult struct {
	SubjectRef    string
	PredicateType string
	PayloadSHA256 string
	Trusted       bool
	Identity      string
	Issuer        string
	Reason        string
	Payload       json.RawMessage
}

// Verifier wraps a cosign binary.
type Verifier struct {
	CosignBinary string // default: "cosign" from PATH
	Timeout      time.Duration
}

// New returns a Verifier with defaults.
func New() *Verifier { return &Verifier{CosignBinary: "cosign", Timeout: 60 * time.Second} }

// Verify runs cosign verify against the image ref + applies the trust policy.
//
// Note on shell-out: we keep cosign external because (a) its Go API hasn't stabilized,
// (b) customers run the same `cosign verify` from the CLI for offline troubleshooting.
// Same rationale as our cosign sign-blob wrapper in constellation-vulndb.
func (v *Verifier) Verify(ctx context.Context, imageRef string, policy TrustPolicy) (*Result, error) {
	// The single-policy path is just the N=1 root-of-trust case (default root, no
	// private-sigstore overrides). Multi-root callers use VerifyWithRoots.
	return v.verifyRoot(ctx, imageRef, RootOfTrust{TrustPolicy: policy})
}

// verifyRoot verifies imageRef against ONE named root-of-trust: the root's cosign trust
// policy plus its optional private Rekor/Fulcio/TUF endpoint overrides (air-gapped).
func (v *Verifier) verifyRoot(ctx context.Context, imageRef string, root RootOfTrust) (*Result, error) {
	if _, err := exec.LookPath(v.CosignBinary); err != nil {
		return nil, ErrCosignMissing
	}
	timeout := v.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args, cleanup, err := cosignVerifyArgs("verify", root.TrustPolicy)
	if err != nil {
		return &Result{ImageRef: imageRef, Signed: false, Trusted: false, Reason: err.Error()}, err
	}
	defer cleanup()
	args, env, cleanupPriv, err := privateSigstoreArgs(ctx, v, args, root)
	if err != nil {
		return &Result{ImageRef: imageRef, Signed: false, Trusted: false, Reason: err.Error()}, err
	}
	defer cleanupPriv()
	args = append(args, imageRef)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, v.CosignBinary, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Distinguish "no signature found" from real verify failures.
		out := strings.TrimSpace(stderr.String())
		if strings.Contains(out, "no matching signatures") || strings.Contains(out, "no signatures found") {
			return &Result{ImageRef: imageRef, Signed: false, Trusted: false, Reason: out}, nil
		}
		return &Result{ImageRef: imageRef, Signed: false, Trusted: false, Reason: out}, fmt.Errorf("cosign verify: %w", err)
	}

	// Decode cosign's JSON output into a typed array of signature objects and trust the
	// image only if AT LEAST ONE signature's identity AND issuer satisfy the policy. A
	// multi-signature image must not be rejected just because the first signature happens
	// to be from an untrusted identity (and vice versa). For display we surface the
	// identity/issuer of the signature that satisfied the policy, falling back to the first
	// signature when none match.
	sigs := decodeCosignSignatures(stdout.Bytes())
	identity, issuer, trusted := pickTrustedIdentity(root.TrustPolicy, sigs)
	reason := trustedSignatureReason(root.TrustPolicy)
	if !trusted {
		reason = fmt.Sprintf("signature OK but identity %q / issuer %q not in trust policy", identity, issuer)
	}
	return &Result{
		ImageRef: imageRef, Signed: true, Trusted: trusted,
		Identity: identity, Issuer: issuer, Reason: reason,
	}, nil
}

// VerifyAttestation runs cosign verify-attestation for a digest-pinned subject
// and returns the first verified in-toto statement that matches the requested
// predicate types. The caller is still responsible for comparing the returned
// payload hash and subject digest against stored scan state before trusting it.
func (v *Verifier) VerifyAttestation(ctx context.Context, subjectRef string, policy TrustPolicy) (*AttestationResult, error) {
	if _, err := exec.LookPath(v.CosignBinary); err != nil {
		return nil, ErrCosignMissing
	}
	timeout := v.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	predicateTypes := normalizePredicates(policy.RequireAttestations)
	args, cleanup, err := cosignVerifyArgs("verify-attestation", policy)
	if err != nil {
		return &AttestationResult{SubjectRef: subjectRef, Reason: err.Error()}, err
	}
	defer cleanup()
	if typ := cosignAttestationType(predicateTypes); typ != "" {
		args = append(args, "--type", typ)
	}
	args = append(args, subjectRef)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, v.CosignBinary, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return &AttestationResult{SubjectRef: subjectRef, Reason: strings.TrimSpace(stderr.String())}, fmt.Errorf("cosign verify-attestation: %w", err)
	}

	statements := extractAttestationStatements(stdout.Bytes())
	if len(statements) == 0 {
		return &AttestationResult{SubjectRef: subjectRef, Reason: "cosign output did not include an in-toto statement"}, errors.New("cosign verify-attestation: no in-toto statements")
	}
	identity, issuer := pickFirstIdentity(stdout.Bytes())
	for _, statement := range statements {
		payload, predicateType, hash := canonicalStatement(statement)
		if len(predicateTypes) > 0 && !stringInList(predicateType, predicateTypes) {
			continue
		}
		trusted := signatureTrusted(policy, identity, issuer)
		reason := trustedAttestationReason(policy)
		if !trusted {
			reason = fmt.Sprintf("attestation OK but identity %q / issuer %q not in trust policy", identity, issuer)
		}
		return &AttestationResult{
			SubjectRef:    subjectRef,
			PredicateType: predicateType,
			PayloadSHA256: hash,
			Trusted:       trusted,
			Identity:      identity,
			Issuer:        issuer,
			Reason:        reason,
			Payload:       payload,
		}, nil
	}
	return &AttestationResult{SubjectRef: subjectRef, Reason: "verified attestations did not match requested predicate type"}, errors.New("cosign verify-attestation: predicate type not found")
}

// ErrCosignMissing is returned when cosign isn't on PATH.
var ErrCosignMissing = errors.New("sigverify: cosign not in PATH (install: https://docs.sigstore.dev/cosign/installation/)")

func cosignVerifyArgs(command string, policy TrustPolicy) ([]string, func(), error) {
	args := []string{command, "--output", "json"}
	cleanup := func() {}
	switch trustPolicyMode(policy) {
	case "public-key":
		keyPath := strings.TrimSpace(policy.PublicKeyPath)
		if keyPath == "" {
			pem := strings.TrimSpace(policy.PublicKeyPEM)
			if pem == "" {
				return nil, cleanup, errors.New("public-key verification requires public key material")
			}
			dir, err := os.MkdirTemp("", "constellation-cosign-key-*")
			if err != nil {
				return nil, cleanup, fmt.Errorf("write public key: %w", err)
			}
			cleanup = func() { _ = os.RemoveAll(dir) }
			keyPath = filepath.Join(dir, "cosign.pub")
			if err := os.WriteFile(keyPath, []byte(pem+"\n"), 0o600); err != nil {
				cleanup()
				return nil, func() {}, fmt.Errorf("write public key: %w", err)
			}
		}
		args = append(args, "--key", keyPath)
	default:
		args = append(args,
			"--certificate-identity-regexp", joinAlt(policy.Identities),
			"--certificate-oidc-issuer-regexp", joinAlt(policy.Issuers),
		)
	}
	if !policy.RequireRekor {
		args = append(args, "--insecure-ignore-tlog=true")
	}
	return args, cleanup, nil
}

func trustPolicyMode(policy TrustPolicy) string {
	switch strings.ToLower(strings.TrimSpace(policy.Mode)) {
	case "", "keyless":
		return "keyless"
	case "public-key", "key", "keyed":
		return "public-key"
	default:
		return "keyless"
	}
}

func signatureTrusted(policy TrustPolicy, identity, issuer string) bool {
	if trustPolicyMode(policy) == "public-key" {
		if len(policy.Identities) > 0 && !matchesAny(identity, policy.Identities) {
			return false
		}
		if len(policy.Issuers) > 0 && !matchesAny(issuer, policy.Issuers) {
			return false
		}
		return true
	}
	if len(policy.Identities) == 0 || len(policy.Issuers) == 0 {
		return false
	}
	return matchesAny(identity, policy.Identities) && matchesAny(issuer, policy.Issuers)
}

func trustedSignatureReason(policy TrustPolicy) string {
	if trustPolicyMode(policy) == "public-key" {
		return "signature trusted by public key"
	}
	return "signature trusted"
}

func trustedAttestationReason(policy TrustPolicy) string {
	if trustPolicyMode(policy) == "public-key" {
		return "attestation trusted by public key"
	}
	return "attestation trusted"
}

// matchesAny returns true if `s` is matched IN FULL by any pattern. Patterns are
// regexes (the trust policy contract), so each is anchored with ^(?:...)$ before
// matching. Anchoring is the security-critical fix: Go's regexp.MatchString is an
// unanchored substring match, so a bare pattern "https://github.com/org/repo" would
// otherwise match an attacker superstring identity "https://github.com/org/repo-evil/..."
// and widen trust to a sibling repo. To match a repo PREFIX (keyless identities are
// workflow paths under the repo), write the pattern with a trailing separator + ".*"
// (e.g. "^https://github.com/org/repo/.*"). Callers that need explicit trust roots
// must check for an empty pattern list before calling this helper.
func matchesAny(s string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if ok, _ := regexp.MatchString(anchorPattern(p), s); ok {
			return true
		}
	}
	return false
}

// anchorPattern wraps a trust pattern so it must match the candidate string in full
// rather than as a substring, closing the superstring trust-widening hole.
func anchorPattern(p string) string {
	return "^(?:" + p + ")$"
}

// joinAlt builds a single anchored alternation for cosign's --certificate-*-regexp
// flags. cosign also evaluates the value as an UNANCHORED regex, so the ^...$ here is
// what forces cosign to require a full-identity match too (mirroring matchesAny).
func joinAlt(patterns []string) string {
	if len(patterns) == 0 {
		return "^.*$"
	}
	return "^(?:" + strings.Join(patterns, "|") + ")$"
}

// cosignSignature is one element of `cosign verify --output json`, which is a JSON array
// of signature objects. The identity (Fulcio cert subject) and OIDC issuer live in the
// `optional` map. cosign has shipped these under a few field names across versions, so we
// decode all of the spellings we have observed and let identityOf/issuerOf collapse them.
//
// ponytail: this is a hand-rolled subset of cosign's `cosign/bundle` payload shape rather
// than a vendored cosign type, because cosign's Go module is still pre-1.0 and churns. If
// cosign stabilizes its verify output type, swap this for the upstream struct.
type cosignSignature struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
	} `json:"critical"`
	Optional map[string]any `json:"optional"`
}

func (s cosignSignature) identity() string {
	for _, key := range []string{"Subject", "subject", "identity"} {
		if v := stringField(s.Optional, key); v != "" {
			return v
		}
	}
	return ""
}

func (s cosignSignature) issuer() string {
	for _, key := range []string{"Issuer", "issuer", "oidc.iss", "Issuer-URI"} {
		if v := stringField(s.Optional, key); v != "" {
			return v
		}
	}
	return ""
}

func stringField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// decodeCosignSignatures decodes `cosign verify --output json` into a typed slice. Cosign
// always emits a top-level array; malformed or empty output decodes to an empty slice
// (never a panic), which the trust evaluation then treats as untrusted.
func decodeCosignSignatures(jsonOut []byte) []cosignSignature {
	var sigs []cosignSignature
	if err := json.Unmarshal(jsonOut, &sigs); err != nil {
		return nil
	}
	return sigs
}

// pickTrustedIdentity iterates ALL decoded signatures and returns the (identity, issuer)
// of the first signature that satisfies the policy, with trusted=true. If no signature
// satisfies the policy it returns the first signature's identity/issuer (for the human
// reason string) with trusted=false. Empty input is untrusted.
func pickTrustedIdentity(policy TrustPolicy, sigs []cosignSignature) (identity, issuer string, trusted bool) {
	for _, sig := range sigs {
		id, iss := sig.identity(), sig.issuer()
		if signatureTrusted(policy, id, iss) {
			return id, iss, true
		}
	}
	if len(sigs) > 0 {
		return sigs[0].identity(), sigs[0].issuer(), false
	}
	return "", "", false
}

// pickFirstIdentity returns the first (identity, issuer) pair from cosign's JSON output.
// Retained for the verify-attestation path, which surfaces identity/issuer for display
// only and evaluates trust per-statement.
func pickFirstIdentity(jsonOut []byte) (identity, issuer string) {
	sigs := decodeCosignSignatures(jsonOut)
	if len(sigs) == 0 {
		return "", ""
	}
	return sigs[0].identity(), sigs[0].issuer()
}

func normalizePredicates(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func cosignAttestationType(predicateTypes []string) string {
	if len(predicateTypes) != 1 {
		return ""
	}
	switch strings.TrimSpace(predicateTypes[0]) {
	case "https://slsa.dev/provenance/v1", "slsa.dev/provenance/v1", "slsaprovenance":
		return "slsaprovenance"
	case "spdx", "https://spdx.dev/Document":
		return "spdx"
	case "cyclonedx", "https://cyclonedx.org/schema":
		return "cyclonedx"
	default:
		return ""
	}
}

func extractAttestationStatements(raw []byte) []map[string]any {
	var decoded any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil
	}
	out := []map[string]any{}
	walkAttestationJSON(decoded, &out)
	return out
}

func walkAttestationJSON(value any, out *[]map[string]any) {
	switch typed := value.(type) {
	case map[string]any:
		if isInTotoStatement(typed) {
			*out = append(*out, typed)
		}
		for key, child := range typed {
			switch strings.ToLower(key) {
			case "payload":
				if decoded, ok := decodeEmbeddedPayload(child); ok {
					walkAttestationJSON(decoded, out)
					continue
				}
			}
			walkAttestationJSON(child, out)
		}
	case []any:
		for _, child := range typed {
			walkAttestationJSON(child, out)
		}
	}
}

func isInTotoStatement(value map[string]any) bool {
	if strings.TrimSpace(fmt.Sprint(value["_type"])) != "https://in-toto.io/Statement/v1" {
		return false
	}
	return strings.TrimSpace(fmt.Sprint(value["predicateType"])) != ""
}

func decodeEmbeddedPayload(value any) (any, bool) {
	switch typed := value.(type) {
	case string:
		encoded := strings.TrimSpace(typed)
		var decoded []byte
		var err error
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			decoded, err = enc.DecodeString(encoded)
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, false
		}
		var out any
		dec := json.NewDecoder(bytes.NewReader(decoded))
		dec.UseNumber()
		if err := dec.Decode(&out); err != nil {
			return nil, false
		}
		return out, true
	case map[string]any, []any:
		return typed, true
	default:
		return nil, false
	}
}

func canonicalStatement(statement map[string]any) (json.RawMessage, string, string) {
	payload, _ := json.Marshal(statement)
	sum := sha256.Sum256(payload)
	return payload, strings.TrimSpace(fmt.Sprint(statement["predicateType"])), "sha256:" + hex.EncodeToString(sum[:])
}

func stringInList(value string, allowed []string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
