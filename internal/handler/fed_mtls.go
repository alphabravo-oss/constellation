package handler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/auth"
)

// ── D2: joint-side per-joint mTLS plumbing ───────────────────────────────────
//
// The master mints a per-joint client certificate at join (fed_trust.go Join). The joint
// persists that cert + its private key (encrypted at rest) + the master CA here, then its
// background poller presents the cert and pins the master CA on every /sync request. This
// is the joint half of the mutual authentication: without the matching client KEY the poll
// cannot complete the TLS handshake, so a leaked bearer alone is useless.

// PersistJointJoin records the result of a successful POST /federation/join on the JOINT
// side: the per-cluster sync ticket and (when the master issued them) the per-joint client
// certificate, its private key, and the master CA to pin. The private key is sealed at rest
// under the install KEK (auth.Sealer / the registry-secrets cipher) — it is never written in
// plaintext, mirroring registries.auth_secret. A nil sealer with key material is an error so
// a misconfigured joint never persists an unencrypted key.
func PersistJointJoin(ctx context.Context, pool *pgxpool.Pool, sealer auth.Sealer, orgID uuid.UUID, clusterID, secret, clientCertPEM, clientKeyPEM, masterCAPEM string) error {
	var keyEnc []byte
	if clientKeyPEM != "" {
		if sealer == nil {
			return errors.New("federation: cannot persist joint client key without an at-rest cipher")
		}
		enc, err := sealer.Seal([]byte(clientKeyPEM))
		if err != nil {
			return err
		}
		keyEnc = enc
	}
	_, err := pool.Exec(ctx, `
INSERT INTO fed_joint_secret (org_id, cluster_id, secret, client_cert_pem, client_key_enc, master_ca_pem, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,NOW())
ON CONFLICT (org_id) DO UPDATE SET
    cluster_id=EXCLUDED.cluster_id, secret=EXCLUDED.secret,
    client_cert_pem=EXCLUDED.client_cert_pem, client_key_enc=EXCLUDED.client_key_enc,
    master_ca_pem=EXCLUDED.master_ca_pem, updated_at=NOW()`,
		orgID, clusterID, secret, clientCertPEM, keyEnc, masterCAPEM)
	return err
}

// fedJointPollClient builds the HTTP client the joint uses for one org's /sync poll. When
// the joint holds per-joint client-cert material it returns a client that presents that cert
// (mutual auth) and pins the master CA; otherwise it returns base unchanged (the D1
// bearer-only path). keyPEM is the already-decrypted private key.
func fedJointPollClient(certPEM, keyPEM, caPEM []byte, base *http.Client) (*http.Client, error) {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return base, nil
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if len(caPEM) > 0 {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("federation: master CA PEM invalid")
		}
		tlsCfg.RootCAs = roots
	}
	timeout := 30 * time.Second
	if base != nil && base.Timeout > 0 {
		timeout = base.Timeout
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}
