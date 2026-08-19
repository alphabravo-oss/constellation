package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
)

// fedCAAdvisoryLock serializes first-boot federation-CA generation cluster-wide (distinct
// from the session-key and fed-signing-key locks so the three never contend).
const fedCAAdvisoryLock int64 = 0x436f6e73746c4361 // "ConstlCa"

// Sealer is the minimal at-rest encryption surface LoadFedCA needs to wrap the CA private
// key. *registry/secrets.Cipher satisfies it, so the federation CA key is protected by the
// same install KEK as registries.auth_secret — auth stays decoupled from the secrets pkg.
type Sealer interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
}

// FedCA is the master-held federation certificate authority (D2). It signs a short-lived
// per-joint CLIENT certificate at each join and exposes the trust material the master uses
// to verify a presented client cert on every /sync poll. It is loaded (or first-boot
// generated) from the fed_ca table; the CA private key is encrypted at rest under the
// install KEK, mirroring registry secrets.
type FedCA struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	certPEM []byte
	pool    *x509.CertPool
}

// LoadFedCA returns the federation CA, generating + persisting one on first use (so a
// master issues per-joint client certs without any operator-provided PKI). The CA private
// key is stored only as Seal(privPEM) in fed_ca.key_enc — never in plaintext. A nil sealer
// disables the fed CA (returns nil, nil) so a deployment that has not configured a KEK
// keeps the D1 bearer-only path rather than failing startup.
func LoadFedCA(ctx context.Context, store sessionKeyStore, sealer Sealer) (*FedCA, error) {
	if sealer == nil {
		return nil, nil
	}
	var (
		certPEM string
		keyEnc  []byte
	)
	err := store.QueryRow(ctx,
		`SELECT cert_pem, key_enc FROM fed_ca WHERE active = TRUE ORDER BY created_at DESC LIMIT 1`,
	).Scan(&certPEM, &keyEnc)
	if errors.Is(err, pgx.ErrNoRows) {
		return generateAndStoreFedCA(ctx, store, sealer)
	}
	if err != nil {
		return nil, fmt.Errorf("auth: load fed CA: %w", err)
	}
	keyPEM, err := sealer.Open(keyEnc)
	if err != nil {
		return nil, fmt.Errorf("auth: decrypt fed CA key: %w", err)
	}
	return newFedCA([]byte(certPEM), keyPEM)
}

// generateAndStoreFedCA mints a self-signed CA keypair, persists the cert + the sealed
// private key, and returns the live CA. A transaction-scoped advisory lock serializes
// concurrent first-boot callers; once held we re-check for an existing CA so the loser
// adopts the winner's. Mirrors generateAndStoreFedSigningKey.
func generateAndStoreFedCA(ctx context.Context, store sessionKeyStore, sealer Sealer) (*FedCA, error) {
	tx, err := store.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: begin fed CA tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, fedCAAdvisoryLock); err != nil {
		return nil, fmt.Errorf("auth: lock fed CA: %w", err)
	}
	var (
		existingCert string
		existingKey  []byte
	)
	err = tx.QueryRow(ctx,
		`SELECT cert_pem, key_enc FROM fed_ca WHERE active = TRUE ORDER BY created_at DESC LIMIT 1`,
	).Scan(&existingCert, &existingKey)
	if err == nil {
		keyPEM, oerr := sealer.Open(existingKey)
		if oerr != nil {
			return nil, fmt.Errorf("auth: decrypt fed CA key: %w", oerr)
		}
		ca, nerr := newFedCA([]byte(existingCert), keyPEM)
		if nerr != nil {
			return nil, nerr
		}
		return ca, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("auth: recheck fed CA: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("auth: generate fed CA key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "constellation-federation-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("auth: self-sign fed CA: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	keyEnc, err := sealer.Seal(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("auth: seal fed CA key: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO fed_ca (cert_pem, key_enc, active) VALUES ($1, $2, TRUE)`,
		string(certPEM), keyEnc); err != nil {
		return nil, fmt.Errorf("auth: persist fed CA: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("auth: commit fed CA: %w", err)
	}
	return newFedCA(certPEM, keyPEM)
}

// newFedCA parses a CA cert+key PEM pair into a usable FedCA (with a verify pool).
func newFedCA(certPEM, keyPEM []byte) (*FedCA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("auth: fed CA cert PEM invalid")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("auth: parse fed CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("auth: fed CA key PEM invalid")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("auth: parse fed CA key: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &FedCA{cert: cert, key: key, certPEM: certPEM, pool: pool}, nil
}

// IssueClientCert mints a short-lived per-joint CLIENT certificate (CN = clusterID) signed
// by the CA, returning the certificate and its private key as PEM. The joint presents this
// cert on every /sync poll; the master binds its fingerprint to the per-cluster credential.
// ttl<=0 defaults to one year (revocation is via the per-cluster epoch bump, not expiry).
func (c *FedCA) IssueClientCert(clusterID string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	if c == nil {
		return nil, nil, errors.New("auth: fed CA not configured")
	}
	if ttl <= 0 {
		ttl = 365 * 24 * time.Hour
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: generate client key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: clusterID, Organization: []string{"constellation-federation"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: sign client cert: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

// CertPEM returns the CA certificate PEM — handed to a joint at join (to pin the master)
// and the trust anchor the master verifies presented client certs against.
func (c *FedCA) CertPEM() []byte {
	if c == nil {
		return nil
	}
	return c.certPEM
}

// VerifyClientCert checks that cert chains to this CA with client-auth EKU. Used by the
// /sync middleware so verification does not depend on how TLS terminated (it works whether
// the cert arrived via a directly-terminated mTLS handshake or a request-client-cert one).
func (c *FedCA) VerifyClientCert(cert *x509.Certificate) error {
	if c == nil {
		return errors.New("auth: fed CA not configured")
	}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:     c.pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

// FedCertFingerprint is the stable identity recorded in fed_credentials.cert_fingerprint
// and matched on every poll: lowercase hex sha256 of the certificate DER.
func FedCertFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// randSerial returns a positive 128-bit certificate serial number.
func randSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("auth: serial: %w", err)
	}
	return serial, nil
}
