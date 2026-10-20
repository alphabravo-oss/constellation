package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	maxBundleBytes  = 16 << 20
	schemaVersion   = "constellation.support_bundle.v1"
	signatureDomain = "constellation.support_bundle.signature.v1\n"
)

type bundle struct {
	SchemaVersion string         `json:"schema_version"`
	BundleID      string         `json:"bundle_id"`
	GeneratedAt   time.Time      `json:"generated_at"`
	OrgID         string         `json:"org_id"`
	Integrity     integrity      `json:"integrity"`
	Sections      map[string]any `json:"sections"`
}

type integrity struct {
	Algorithm          string `json:"algorithm"`
	Scope              string `json:"scope"`
	SHA256             string `json:"sha256"`
	Signed             bool   `json:"signed"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	Signature          string `json:"signature"`
	PublicKey          string `json:"public_key"`
	KeyID              string `json:"key_id"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "support bundle verification failed:", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("constellation-support-bundle-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("file", "", "downloaded support bundle JSON")
	pinnedKeyID := flags.String("key-id", "", "trusted Ed25519 public key SHA-256 fingerprint")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || flags.NArg() != 0 {
		return errors.New("usage: constellation-support-bundle-verify --file <bundle.json> --key-id <64 lowercase hex fingerprint>")
	}
	if !validSHA256(*pinnedKeyID) {
		return errors.New("--key-id must be a 64-character lowercase hex SHA-256 fingerprint")
	}
	file, err := os.Open(*path)
	if err != nil {
		return fmt.Errorf("open bundle: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBundleBytes+1))
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	if len(data) > maxBundleBytes {
		return errors.New("bundle exceeds 16 MiB limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var downloaded bundle
	if err := decoder.Decode(&downloaded); err != nil {
		return fmt.Errorf("decode bundle: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("decode bundle: trailing JSON content")
	}
	if err := verify(downloaded, *pinnedKeyID); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Verified bundle %s with key %s\n", downloaded.BundleID, *pinnedKeyID)
	return err
}

func verify(downloaded bundle, pinnedKeyID string) error {
	if !validSHA256(pinnedKeyID) {
		return errors.New("invalid pinned key ID")
	}
	if downloaded.SchemaVersion != schemaVersion || downloaded.BundleID == "" || downloaded.OrgID == "" || downloaded.GeneratedAt.IsZero() {
		return errors.New("invalid support bundle identity")
	}
	if !downloaded.Integrity.Signed {
		return errors.New("support bundle is unsigned")
	}
	if downloaded.Integrity.Algorithm != "sha256" || downloaded.Integrity.Scope != "sections" ||
		downloaded.Integrity.SignatureAlgorithm != "ed25519" || !validSHA256(downloaded.Integrity.SHA256) {
		return errors.New("unsupported or invalid support bundle integrity")
	}
	if downloaded.Sections == nil {
		return errors.New("missing support bundle sections")
	}
	sections, err := json.Marshal(downloaded.Sections)
	if err != nil {
		return fmt.Errorf("encode sections: %w", err)
	}
	sectionsHash := sha256.Sum256(sections)
	if hex.EncodeToString(sectionsHash[:]) != downloaded.Integrity.SHA256 {
		return errors.New("support bundle sections hash mismatch")
	}
	publicKey, err := base64.StdEncoding.DecodeString(downloaded.Integrity.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(publicKey) != downloaded.Integrity.PublicKey {
		return errors.New("invalid support bundle public key")
	}
	signature, err := base64.StdEncoding.DecodeString(downloaded.Integrity.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != downloaded.Integrity.Signature {
		return errors.New("invalid support bundle signature")
	}
	keyHash := sha256.Sum256(publicKey)
	actualKeyID := hex.EncodeToString(keyHash[:])
	if !validSHA256(downloaded.Integrity.KeyID) ||
		subtle.ConstantTimeCompare([]byte(actualKeyID), []byte(downloaded.Integrity.KeyID)) != 1 ||
		subtle.ConstantTimeCompare([]byte(actualKeyID), []byte(pinnedKeyID)) != 1 {
		return errors.New("support bundle signing key does not match pinned key ID")
	}
	payload := []byte(signatureDomain + downloaded.SchemaVersion + "\n" + downloaded.BundleID + "\n" +
		downloaded.GeneratedAt.UTC().Format(time.RFC3339Nano) + "\n" + downloaded.OrgID + "\n" + downloaded.Integrity.SHA256)
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("support bundle signature verification failed")
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			if char < 'a' || char > 'f' {
				return false
			}
		}
	}
	return true
}
