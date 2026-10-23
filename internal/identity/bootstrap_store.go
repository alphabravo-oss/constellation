package identity

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	columncrypto "github.com/alphabravocompany/constellation/internal/crypto"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// Bootstrap serializes first boot and the credential migration across replicas.
// Existing credentials are never overwritten by deployment defaults.
func (s Store) bootstrap(ctx context.Context, c LocalConfig, e BreakGlassConfig, enc *columncrypto.Encryptor, log *audit.Logger) error {
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock(188188)`); err != nil {
		return err
	}
	defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(188188)`) }()
	if c.BootstrapPassword != "" || e.Enabled {
		if _, err = conn.Exec(ctx, `INSERT INTO orgs(name,display_name) VALUES($1,$1) ON CONFLICT(name) DO NOTHING`, c.OrgName); err != nil {
			return err
		}
	}
	if e.Enabled {
		if err = s.migrateRecovery(ctx, conn, e, enc); err != nil {
			return err
		}
	}
	if c.BootstrapPassword == "" {
		return nil
	}
	var needed bool
	if err = conn.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM local_users l JOIN users u ON u.id=l.user_id JOIN orgs o ON o.id=u.org_id WHERE o.name=$1 AND NOT l.break_glass) AND NOT EXISTS(SELECT 1 FROM users u JOIN orgs o ON o.id=u.org_id WHERE o.name=$1 AND lower(u.email)=$2)`, c.OrgName, strings.ToLower(c.BootstrapEmail)).Scan(&needed); err != nil {
		return err
	}
	if !needed {
		return nil
	}
	if !c.Enabled {
		var recoveryExists bool
		if err = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM local_users WHERE break_glass)`).Scan(&recoveryExists); err != nil {
			return err
		}
		if recoveryExists {
			return nil
		}
	}
	return s.bootstrapAdmin(ctx, conn, c, enc, log)
}
func (s Store) migrateRecovery(ctx context.Context, conn *pgxpool.Conn, e BreakGlassConfig, enc *columncrypto.Encryptor) error {
	if enc == nil {
		return errors.New("age key required to migrate recovery administrator")
	}
	var id, org uuid.UUID
	err := conn.QueryRow(ctx, `SELECT u.id,u.org_id FROM users u JOIN orgs o ON o.id=u.org_id WHERE o.name=$1 AND u.oidc_issuer='break-glass' AND u.oidc_subject='admin'`, e.OrgName).Scan(&id, &org)
	if errors.Is(err, pgx.ErrNoRows) {
		err = conn.QueryRow(ctx, `INSERT INTO users(org_id,email,display_name,oidc_issuer,oidc_subject) SELECT id,'break-glass@constellation.local','Recovery administrator','break-glass','admin' FROM orgs WHERE name=$1 RETURNING id,org_id`, e.OrgName).Scan(&id, &org)
	}
	if err != nil {
		return err
	}
	sealed, err := enc.Encrypt([]byte(e.TOTPSecret))
	if err != nil {
		return err
	}
	if _, err = conn.Exec(ctx, `INSERT INTO local_users(user_id,password_hash,totp_secret,key_id,algorithm,break_glass,last_totp_step) SELECT $1,$2,$3,$4,$5,true,last_totp_step FROM break_glass_guard WHERE singleton ON CONFLICT(user_id) DO NOTHING`, id, e.PasswordHash, sealed.Ciphertext, sealed.KeyID, sealed.Algorithm); err != nil {
		return err
	}
	_, err = conn.Exec(ctx, `INSERT INTO role_assignments(user_id,role,scope_org_id) SELECT $1,'GlobalAdmin',$2 WHERE NOT EXISTS(SELECT 1 FROM role_assignments WHERE user_id=$1 AND role='GlobalAdmin')`, id, org)
	return err
}
func (s Store) bootstrapAdmin(ctx context.Context, conn *pgxpool.Conn, c LocalConfig, enc *columncrypto.Encryptor, log *audit.Logger) error {
	if err := checkPassword(c.BootstrapPassword, c.PasswordMinLength); err != nil {
		return err
	}
	if enc == nil {
		return errors.New("age key required for bootstrap administrator")
	}
	if !validTOTPSecret(c.BootstrapTOTP) {
		return errors.New("invalid bootstrap TOTP secret")
	}
	var org uuid.UUID
	if err := conn.QueryRow(ctx, `SELECT id FROM orgs WHERE name=$1`, c.OrgName).Scan(&org); err != nil {
		return err
	}
	var bg bool
	if err := conn.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM local_users WHERE break_glass)`).Scan(&bg); err != nil {
		return err
	}
	hash, err := HashPassword(c.BootstrapPassword)
	if err != nil {
		return err
	}
	secret, err := enc.Encrypt([]byte(c.BootstrapTOTP))
	if err != nil {
		return err
	}
	_, err = s.createLocal(ctx, org, strings.ToLower(c.BootstrapEmail), "Administrator", hash, secret, "GlobalAdmin", bg, nil, log)
	return err
}
