package sigverify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyAttestationParsesCosignOutput(t *testing.T) {
	statement := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []map[string]any{{
			"name":   "ghcr.io/acme/app",
			"digest": map[string]any{"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		}},
		"predicate": map[string]any{"buildType": "github-actions"},
	}
	statementRaw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	outputRaw, err := json.Marshal([]map[string]any{{
		"payload": base64.StdEncoding.EncodeToString(statementRaw),
		"optional": map[string]any{
			"Subject": "repo:acme/app:ref:refs/heads/main",
			"Issuer":  "https://token.actions.githubusercontent.com",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	cosign := filepath.Join(t.TempDir(), "cosign")
	if err := os.WriteFile(cosign, []byte("#!/bin/sh\ncat <<'JSON'\n"+string(outputRaw)+"\nJSON\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	verifier := &Verifier{CosignBinary: cosign}
	result, err := verifier.VerifyAttestation(context.Background(), "ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TrustPolicy{
		Identities:          []string{"repo:acme/app:ref:refs/heads/main"},
		Issuers:             []string{"https://token.actions.githubusercontent.com"},
		RequireAttestations: []string{"https://slsa.dev/provenance/v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil ||
		!result.Trusted ||
		result.PredicateType != "https://slsa.dev/provenance/v1" ||
		result.Identity != "repo:acme/app:ref:refs/heads/main" ||
		result.Issuer != "https://token.actions.githubusercontent.com" ||
		result.PayloadSHA256 == "" ||
		len(result.Payload) == 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestVerifyAttestationUsesPublicKeyMode(t *testing.T) {
	statement := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []map[string]any{{
			"name":   "ghcr.io/acme/app",
			"digest": map[string]any{"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		}},
		"predicate": map[string]any{"buildType": "github-actions"},
	}
	statementRaw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	outputRaw, err := json.Marshal([]map[string]any{{
		"payload": base64.StdEncoding.EncodeToString(statementRaw),
	}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	cosign := filepath.Join(dir, "cosign")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\ncat <<'JSON'\n" + string(outputRaw) + "\nJSON\n"
	if err := os.WriteFile(cosign, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	verifier := &Verifier{CosignBinary: cosign}
	result, err := verifier.VerifyAttestation(context.Background(), "ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TrustPolicy{
		Mode:                "public-key",
		PublicKeyPEM:        "-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----",
		RequireAttestations: []string{"https://slsa.dev/provenance/v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Trusted || result.Reason != "attestation trusted by public key" {
		t.Fatalf("result = %+v", result)
	}
	argsRaw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	args := string(argsRaw)
	if !strings.Contains(args, "verify-attestation\n") || !strings.Contains(args, "--key\n") {
		t.Fatalf("cosign args did not use public-key mode:\n%s", args)
	}
	if strings.Contains(args, "--certificate-identity-regexp") || strings.Contains(args, "--certificate-oidc-issuer-regexp") {
		t.Fatalf("public-key mode should not include keyless certificate flags:\n%s", args)
	}
}

func TestVerifyAttestationKeylessRequiresExplicitTrustPolicy(t *testing.T) {
	statement := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []map[string]any{{
			"name":   "ghcr.io/acme/app",
			"digest": map[string]any{"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		}},
		"predicate": map[string]any{"buildType": "github-actions"},
	}
	statementRaw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	outputRaw, err := json.Marshal([]map[string]any{{
		"payload": base64.StdEncoding.EncodeToString(statementRaw),
		"optional": map[string]any{
			"Subject": "repo:acme/app:ref:refs/heads/main",
			"Issuer":  "https://token.actions.githubusercontent.com",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	cosign := filepath.Join(t.TempDir(), "cosign")
	if err := os.WriteFile(cosign, []byte("#!/bin/sh\ncat <<'JSON'\n"+string(outputRaw)+"\nJSON\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	verifier := &Verifier{CosignBinary: cosign}
	result, err := verifier.VerifyAttestation(context.Background(), "ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TrustPolicy{
		RequireAttestations: []string{"https://slsa.dev/provenance/v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Trusted {
		t.Fatalf("empty keyless trust policy must not trust result: %+v", result)
	}
}
