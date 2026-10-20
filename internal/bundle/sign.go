package bundle

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// trustedKeyPEM is the vendor bundle-signing public key compiled into every
// binary; a bundle must verify against it (or an explicit --trust-key) before
// anything in it is used. Signatures are cosign sign-blob compatible: ECDSA
// P-256 over SHA-256 of bom.json, ASN.1 DER, base64.
//
//go:embed trust/bundle-signing.pub
var trustedKeyPEM []byte

// ErrUnsigned / ErrBadSignature / ErrTampered are the fail-closed outcomes.
var (
	ErrUnsigned     = errors.New("bundle: bom.sig missing (unsigned bundle)")
	ErrBadSignature = errors.New("bundle: bom.sig does not verify against the trusted key")
	ErrTampered     = errors.New("bundle: payload digest mismatch")
)

// TrustedKey returns the embedded public key.
func TrustedKey() (*ecdsa.PublicKey, error) { return ParsePublicKey(trustedKeyPEM) }

// ParsePublicKey parses a PEM ECDSA public key (PKIX).
func ParsePublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("bundle: no PEM block in public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bundle: parse public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("bundle: public key is not ECDSA")
	}
	return ec, nil
}

// ParsePrivateKey parses an EC (SEC1) or PKCS#8 PEM private key.
func ParsePrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("bundle: no PEM block in private key")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bundle: parse private key: %w", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("bundle: private key is not ECDSA")
	}
	return ec, nil
}

// Sign writes bom.sig for the bundle's bom.json.
func Sign(dir string, key *ecdsa.PrivateKey) error {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return fmt.Errorf("bundle: sign: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, SignatureFile), []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o600) //nolint:gosec // G703: dir is the operator's --out bundle directory
}

// Verify checks bom.sig against pub (nil = embedded key), then every payload
// digest listed in the BOM. It returns the manifest only when both pass.
func Verify(dir string, pub *ecdsa.PublicKey) (*Manifest, error) {
	if pub == nil {
		k, err := TrustedKey()
		if err != nil {
			return nil, err
		}
		pub = k
	}
	m, raw, err := readManifest(dir)
	if err != nil {
		return nil, err
	}
	sigB64, err := os.ReadFile(filepath.Join(dir, SignatureFile))
	if err != nil {
		return nil, ErrUnsigned
	}
	sig, err := base64.StdEncoding.DecodeString(string(trimSpace(sigB64)))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadSignature, err)
	}
	sum := sha256.Sum256(raw)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return nil, ErrBadSignature
	}
	for _, f := range m.Files {
		got, size, err := hashFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrTampered, f.Path, err)
		}
		if got != f.SHA256 || size != f.Size {
			return nil, fmt.Errorf("%w: %s", ErrTampered, f.Path)
		}
	}
	if err := checkLayout(filepath.Join(dir, ImagesDir), m); err != nil {
		return nil, err
	}
	return m, nil
}

// ErrIncomplete is returned when an image manifest references a blob the
// layout does not contain (the BOM can only vouch for files that exist).
var ErrIncomplete = errors.New("bundle: image layout incomplete")

// checkLayout proves every BOM image is in the layout with its manifest,
// config and layer blobs present.
func checkLayout(dir string, m *Manifest) error {
	blob := func(digest string) string {
		algo, hex, _ := strings.Cut(digest, ":")
		return filepath.Join(dir, "blobs", algo, hex)
	}
	for _, im := range m.Images {
		raw, err := os.ReadFile(blob(im.Digest))
		if err != nil {
			return fmt.Errorf("%w: manifest %s for %s", ErrIncomplete, im.Digest, im.Ref)
		}
		var man struct {
			Config struct{ Digest string }   `json:"config"`
			Layers []struct{ Digest string } `json:"layers"`
		}
		if err := json.Unmarshal(raw, &man); err != nil {
			return fmt.Errorf("%w: manifest %s: %w", ErrIncomplete, im.Digest, err)
		}
		refs := []string{man.Config.Digest}
		for _, l := range man.Layers {
			refs = append(refs, l.Digest)
		}
		for _, d := range refs {
			if _, err := os.Stat(blob(d)); err != nil {
				return fmt.Errorf("%w: %s references missing blob %s", ErrIncomplete, im.Ref, d)
			}
		}
	}
	return nil
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
