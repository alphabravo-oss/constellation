// Signing helpers — cosign-compatible at the wire level.
//
// cosign sign-blob output for ed25519 keys is a base64-encoded raw ed25519 signature over
// the literal blob bytes; verify-blob does ed25519.Verify against the matching public key.
// We implement both ends in-process so the constellation-api server can sign a manifest
// without shelling out (and so a restore can verify without cosign being on the operator's
// laptop). When cosign IS on PATH the CLI subcommand will defer to it instead — that path
// covers keyless / Fulcio signing which requires interactive OIDC.
//
// Static-key mode:
//   sign:   ed25519.Sign(privKey, manifestBytes)            -> base64 -> manifest.json.sig
//   verify: ed25519.Verify(pubKey, manifestBytes, sigBytes)
//
// Keyless (Fulcio) mode:
//   handled by external `cosign sign-blob --identity-token ... --bundle ...` invocation;
//   we record the cosign bundle as manifest.json.sig and the Fulcio cert as manifest.json.cert.
//   Verification then runs `cosign verify-blob --certificate ... --certificate-identity ...`.
//   The library here detects the bundle format and shells out to cosign for verify-only.
package backup

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// SignMode enumerates how the manifest was signed.
type SignMode string

const (
	SignModeNone SignMode = "none"
	SignModeStaticKey SignMode = "static-key"
	SignModeKeyless SignMode = "keyless"
)

// SignerOptions configures Sign.
type SignerOptions struct {
	Mode       SignMode
	KeyPath    string // PEM-encoded ed25519 private key (cosign-compatible) when Mode=static-key
	CosignBin  string // optional override; defaults to "cosign" when keyless
	CertOutput []byte // populated for keyless mode after Sign returns
}

// Sign signs manifestBytes per opts and returns (signatureBytes, certBytes, identity).
// identity is "key:<sha256-pubkey-hex>" for static-key or "keyless:<subject>" for Fulcio.
//
// For static-key: writes nothing to disk, runs in-process; returns nil cert.
// For keyless:    requires `cosign` on PATH; produces a bundle file alongside.
// For none:       returns ("", "", "") and Verify will skip.
func Sign(manifestBytes []byte, opts SignerOptions) (sig []byte, cert []byte, identity string, err error) {
	switch opts.Mode {
	case SignModeNone, "":
		return nil, nil, "", nil
	case SignModeStaticKey:
		if opts.KeyPath == "" {
			return nil, nil, "", errors.New("static-key sign: --sign-key required")
		}
		priv, pub, err := loadEd25519Key(opts.KeyPath)
		if err != nil {
			return nil, nil, "", err
		}
		raw := ed25519.Sign(priv, manifestBytes)
		ident := "key:" + pubKeyFingerprint(pub)
		return []byte(base64.StdEncoding.EncodeToString(raw)), nil, ident, nil
	case SignModeKeyless:
		bin := opts.CosignBin
		if bin == "" {
			bin = "cosign"
		}
		if _, err := exec.LookPath(bin); err != nil {
			return nil, nil, "", fmt.Errorf("keyless sign: %s not on PATH", bin)
		}
		// Write the blob to a temp file because cosign sign-blob reads from disk.
		tmp, err := os.CreateTemp("", "cnstl-manifest-*.json")
		if err != nil {
			return nil, nil, "", err
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(manifestBytes); err != nil {
			return nil, nil, "", err
		}
		_ = tmp.Close()

		sigPath := tmp.Name() + ".sig"
		certPath := tmp.Name() + ".cert"
		defer os.Remove(sigPath)
		defer os.Remove(certPath)

		// `cosign sign-blob --yes --output-signature SIG --output-certificate CERT BLOB`.
		// We rely on ambient OIDC ($COSIGN_IDENTITY_TOKEN, or a browser prompt) which the
		// caller is responsible for arranging.
		cmd := exec.Command(bin, "sign-blob", "--yes",
			"--output-signature", sigPath,
			"--output-certificate", certPath,
			tmp.Name())
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return nil, nil, "", fmt.Errorf("cosign sign-blob: %w", err)
		}
		sigB, err := os.ReadFile(sigPath)
		if err != nil {
			return nil, nil, "", err
		}
		certB, err := os.ReadFile(certPath)
		if err != nil {
			return nil, nil, "", err
		}
		subject, _ := extractCertSubject(certB)
		return sigB, certB, "keyless:" + subject, nil
	default:
		return nil, nil, "", fmt.Errorf("unknown sign mode %q", opts.Mode)
	}
}

// VerifierOptions configures Verify.
type VerifierOptions struct {
	Mode      SignMode
	KeyPath   string // PEM public key for static-key
	CosignBin string // optional
	// Identity is the expected Fulcio cert subject for keyless mode. Empty -> any subject
	// is accepted (use --allow-unverified at the call site for that posture).
	Identity string
}

// Verify confirms sig is a valid signature over manifestBytes per opts. Returns the
// signer identity string for audit-logging on success.
func Verify(manifestBytes, sig, cert []byte, opts VerifierOptions) (identity string, err error) {
	switch opts.Mode {
	case SignModeNone, "":
		return "", errors.New("verify: no signature mode declared")
	case SignModeStaticKey:
		if opts.KeyPath == "" {
			return "", errors.New("static-key verify: --verify-key required")
		}
		pub, err := loadEd25519PubKey(opts.KeyPath)
		if err != nil {
			return "", err
		}
		raw, err := base64.StdEncoding.DecodeString(string(sig))
		if err != nil {
			return "", fmt.Errorf("decode sig: %w", err)
		}
		if !ed25519.Verify(pub, manifestBytes, raw) {
			return "", errors.New("signature does not verify against the supplied public key")
		}
		return "key:" + pubKeyFingerprint(pub), nil
	case SignModeKeyless:
		bin := opts.CosignBin
		if bin == "" {
			bin = "cosign"
		}
		if _, err := exec.LookPath(bin); err != nil {
			return "", fmt.Errorf("keyless verify: %s not on PATH", bin)
		}
		// Marshal artifacts to disk and call cosign verify-blob.
		blobTmp, err := os.CreateTemp("", "cnstl-blob-*.json")
		if err != nil {
			return "", err
		}
		defer os.Remove(blobTmp.Name())
		blobTmp.Write(manifestBytes)
		blobTmp.Close()

		sigTmp, _ := os.CreateTemp("", "cnstl-sig-*.sig")
		defer os.Remove(sigTmp.Name())
		sigTmp.Write(sig)
		sigTmp.Close()

		certTmp, _ := os.CreateTemp("", "cnstl-cert-*.pem")
		defer os.Remove(certTmp.Name())
		certTmp.Write(cert)
		certTmp.Close()

		args := []string{"verify-blob",
			"--signature", sigTmp.Name(),
			"--certificate", certTmp.Name(),
		}
		if opts.Identity != "" {
			args = append(args, "--certificate-identity", opts.Identity)
		}
		args = append(args, blobTmp.Name())
		cmd := exec.Command(bin, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("cosign verify-blob: %s: %w", out, err)
		}
		subject, _ := extractCertSubject(cert)
		return "keyless:" + subject, nil
	default:
		return "", fmt.Errorf("unknown verify mode %q", opts.Mode)
	}
}

// GenerateEd25519Keypair writes an ed25519 private/public key pair to (privPath, pubPath)
// in cosign-compatible PEM form: PRIVATE -> PKCS8 PEM, PUBLIC -> PKIX PEM. This is offered
// as a convenience for tests + the `constellationctl backup gen-key` subcommand.
func GenerateEd25519Keypair(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		return err
	}
	return nil
}

// ---- internals ----

func loadEd25519Key(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, nil, errors.New("invalid PEM in key file")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse PKCS8: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("expected ed25519 key, got %T", k)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("derive ed25519 public key")
	}
	return priv, pub, nil
}

func loadEd25519PubKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pubkey: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid PEM in pubkey file")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519 pubkey, got %T", k)
	}
	return pub, nil
}

func pubKeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// extractCertSubject returns the email SAN (or Subject CN as fallback) from a Fulcio
// cert PEM. Best-effort: errors are non-fatal so we never block a successful verify on
// a parser quirk.
func extractCertSubject(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("no PEM in cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0], nil
	}
	if cn := cert.Subject.CommonName; cn != "" {
		return cn, nil
	}
	return "unknown", nil
}

// sha256Hex returns the hex-encoded sha256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
