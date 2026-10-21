package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	columncrypto "github.com/alphabravocompany/constellation/internal/crypto"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

type LocalUser struct {
	ID             uuid.UUID  `json:"id"`
	Email          string     `json:"email"`
	DisplayName    string     `json:"display_name"`
	Status         string     `json:"status"`
	BreakGlass     bool       `json:"break_glass"`
	Roles          []string   `json:"roles"`
	LastLogin      *time.Time `json:"last_login"`
	FailedAttempts int        `json:"failed_attempts"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}
type localCredential struct {
	subject    authctx.Subject
	epoch      int64
	hash       string
	secret     columncrypto.Sealed
	breakGlass bool
	disabled   bool
	blocked    bool
	version    int64
	roles      []string
}

var errLoginBlocked = errors.New("account backoff")

type accountBackoff struct{ Seconds int }

func (e accountBackoff) Error() string { return errLoginBlocked.Error() }
func (e accountBackoff) Unwrap() error { return errLoginBlocked }

var errPasswordBusy = errors.New("password verification busy")

func (s Store) localCredential(ctx context.Context, email, org string, limit int) (localCredential, error) {
	var c localCredential
	var retry int
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT u.id,u.org_id,u.email,u.session_epoch,u.disabled,l.password_hash,l.totp_secret,l.key_id,l.algorithm,l.break_glass,l.blocked_until>now(),CASE WHEN l.blocked_until>now() THEN greatest(1,ceil(extract(epoch FROM l.blocked_until-now())))::int ELSE 0 END,l.credential_version FROM local_users l JOIN users u ON u.id=l.user_id JOIN orgs o ON o.id=u.org_id WHERE lower(u.email)=$1 AND o.name=$2 FOR UPDATE OF l`, email, org).Scan(&c.subject.UserID, &c.subject.OrgID, &c.subject.Email, &c.epoch, &c.disabled, &c.hash, &c.secret.Ciphertext, &c.secret.KeyID, &c.secret.Algorithm, &c.breakGlass, &c.blocked, &retry, &c.version)
		if err != nil {
			return err
		}
		if c.blocked {
			return accountBackoff{Seconds: retry}
		}
		_, err = tx.Exec(ctx, `UPDATE local_users SET failed_attempts=least(failed_attempts+1,1000),blocked_until=CASE WHEN failed_attempts+1 >= $2 THEN now()+make_interval(secs=>least(300,power(2,least(9,failed_attempts+1-$2)))::int) ELSE '-infinity' END,updated_at=now() WHERE user_id=$1`, c.subject.UserID, limit)
		return err
	})
	if err != nil {
		return c, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT role,scope_org_id,scope_cluster_id,scope_project_id,scope_namespace FROM role_assignments WHERE user_id=$1`, c.subject.UserID)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var a rbac.RoleAssignment
		if err := rows.Scan(&a.Role, &a.Scope.OrgID, &a.Scope.ClusterID, &a.Scope.ProjectID, &a.Scope.Namespace); err != nil {
			return c, err
		}
		c.subject.Assignments = append(c.subject.Assignments, a)
		c.roles = append(c.roles, a.Role)
	}
	return c, rows.Err()
}
func (s Store) localSuccess(ctx context.Context, c localCredential, step int64) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE local_users SET last_totp_step=CASE WHEN $3<0 THEN last_totp_step ELSE $3 END,failed_attempts=0,blocked_until='-infinity',updated_at=now() WHERE user_id=$1 AND credential_version=$2 AND ($3<0 OR last_totp_step<$3)`, c.subject.UserID, c.version, step)
	return tag.RowsAffected() == 1, err
}
func (s Store) reserveIP(ctx context.Context, ip string, limit int) (bool, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `INSERT INTO local_login_ips(ip_hash) VALUES($1) ON CONFLICT(ip_hash) DO UPDATE SET attempts=CASE WHEN local_login_ips.window_start<now()-interval '1 minute' THEN 1 ELSE local_login_ips.attempts+1 END,window_start=CASE WHEN local_login_ips.window_start<now()-interval '1 minute' THEN now() ELSE local_login_ips.window_start END RETURNING attempts`, tokenHash(ip)).Scan(&n)
	return n <= limit, err
}
func (s Store) listLocal(ctx context.Context, org uuid.UUID) ([]LocalUser, error) {
	rows, err := s.Pool.Query(ctx, `SELECT u.id,u.email,u.display_name,CASE WHEN u.disabled THEN 'disabled' ELSE 'active' END,l.break_glass,COALESCE((SELECT array_agg(role ORDER BY role) FROM role_assignments WHERE user_id=u.id),'{}'),u.last_login_at,l.failed_attempts,l.created_at,l.updated_at FROM local_users l JOIN users u ON u.id=l.user_id WHERE u.org_id=$1 ORDER BY lower(u.email)`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LocalUser{}
	for rows.Next() {
		var u LocalUser
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Status, &u.BreakGlass, &u.Roles, &u.LastLogin, &u.FailedAttempts, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
func (s Store) createLocal(ctx context.Context, org uuid.UUID, email, name, hash string, secret columncrypto.Sealed, role string, bg bool, actor *uuid.UUID, log *audit.Logger) (uuid.UUID, error) {
	var id uuid.UUID
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO users(org_id,email,display_name) VALUES($1,$2,$3) RETURNING id`, org, email, name).Scan(&id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO local_users(user_id,password_hash,totp_secret,key_id,algorithm,break_glass) VALUES($1,$2,$3,$4,$5,$6)`, id, hash, secret.Ciphertext, secret.KeyID, secret.Algorithm, bg); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO role_assignments(user_id,role,scope_org_id) VALUES($1,$2,$3)`, id, role, org); err != nil {
			return err
		}
		_, _, err := log.LogInTx(ctx, tx, audit.Event{OrgID: &org, ActorID: actor, Action: "users.create", TargetKind: "user", TargetID: id.String(), After: map[string]any{"email": email, "role": role, "break_glass": bg}})
		return err
	})
	return id, err
}

// One mutation transaction also increments the existing revocation epoch. Every
// opaque session checks that epoch, including on other replicas.
func (s Store) mutateLocal(ctx context.Context, org, id, actor uuid.UUID, action, value string, secret columncrypto.Sealed, log *audit.Logger) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var bg bool
		if err := tx.QueryRow(ctx, `SELECT l.break_glass FROM local_users l JOIN users u ON u.id=l.user_id WHERE u.id=$1 AND u.org_id=$2 FOR UPDATE OF u,l`, id, org).Scan(&bg); err != nil {
			return err
		}
		if bg && (action == "disable" || action == "role") {
			return errors.New("the recovery administrator must remain enabled with its administrator role")
		}
		var err error
		switch action {
		case "disable":
			_, err = tx.Exec(ctx, `UPDATE users SET disabled=true WHERE id=$1`, id)
		case "reset-password":
			_, err = tx.Exec(ctx, `UPDATE local_users SET password_hash=$2,credential_version=credential_version+1,failed_attempts=0,blocked_until='-infinity',updated_at=now() WHERE user_id=$1`, id, value)
		case "reset-totp":
			_, err = tx.Exec(ctx, `UPDATE local_users SET totp_secret=$2,key_id=$3,algorithm=$4,last_totp_step=0,credential_version=credential_version+1,updated_at=now() WHERE user_id=$1`, id, secret.Ciphertext, secret.KeyID, secret.Algorithm)
		case "role":
			if _, err = tx.Exec(ctx, `DELETE FROM role_assignments WHERE user_id=$1`, id); err == nil {
				_, err = tx.Exec(ctx, `INSERT INTO role_assignments(user_id,role,scope_org_id) VALUES($1,$2,$3)`, id, value, org)
			}
		default:
			return errors.New("invalid user action")
		}
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE users SET session_epoch=session_epoch+1,updated_at=now() WHERE id=$1`, id); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM identity_sessions WHERE user_id=$1`, id); err != nil {
			return err
		}
		_, _, err = log.LogInTx(ctx, tx, audit.Event{OrgID: &org, ActorID: &actor, Action: "users." + action, TargetKind: "user", TargetID: id.String()})
		return err
	})
}

type settingsRecord struct {
	Local    LocalConfig `json:"local"`
	OIDC     *OIDCConfig `json:"oidc"`
	Revision int64       `json:"revision"`
}

func (s Store) readSettings(ctx context.Context, enc *columncrypto.Encryptor) (settingsRecord, error) {
	var v settingsRecord
	var local, oidc []byte
	var secret columncrypto.Sealed
	err := s.Pool.QueryRow(ctx, `SELECT local_config,oidc_config,COALESCE(client_secret,'\x'::bytea),COALESCE(key_id,''),COALESCE(algorithm,''),revision FROM identity_settings WHERE singleton`).Scan(&local, &oidc, &secret.Ciphertext, &secret.KeyID, &secret.Algorithm, &v.Revision)
	if err != nil {
		return v, err
	}
	if err = json.Unmarshal(local, &v.Local); err != nil {
		return v, err
	}
	if len(oidc) > 0 && string(oidc) != "null" {
		v.OIDC = &OIDCConfig{}
		if err = json.Unmarshal(oidc, v.OIDC); err != nil {
			return v, err
		}
	}
	if v.OIDC != nil && len(secret.Ciphertext) > 0 {
		if enc == nil {
			return v, columncrypto.ErrNoKey
		}
		raw, err := enc.Decrypt(secret)
		if err != nil {
			return v, err
		}
		v.OIDC.ClientSecret = string(raw)
	}
	return v, nil
}
func (s Store) writeSettings(ctx context.Context, v settingsRecord, secret columncrypto.Sealed, actor *authctx.Subject, log *audit.Logger) error {
	local, _ := json.Marshal(v.Local)
	oidc, _ := json.Marshal(v.OIDC)
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if actor == nil {
			fingerprint := tokenHash(string(local) + string(oidc))
			if v.OIDC != nil {
				fingerprint = tokenHash(fingerprint + v.OIDC.ClientSecret)
			}
			_, err := tx.Exec(ctx, `INSERT INTO identity_settings(local_config,oidc_config,client_secret,key_id,algorithm,deployment_hash) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(singleton) DO UPDATE SET local_config=EXCLUDED.local_config,oidc_config=EXCLUDED.oidc_config,client_secret=EXCLUDED.client_secret,key_id=EXCLUDED.key_id,algorithm=EXCLUDED.algorithm,deployment_hash=EXCLUDED.deployment_hash,revision=identity_settings.revision+1,updated_at=now() WHERE identity_settings.deployment_hash<>EXCLUDED.deployment_hash`, local, oidc, secret.Ciphertext, secret.KeyID, secret.Algorithm, fingerprint)
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE identity_settings SET local_config=$1,oidc_config=$2,client_secret=$3,key_id=$4,algorithm=$5,revision=revision+1,updated_at=now() WHERE singleton AND revision=$6`, local, oidc, secret.Ciphertext, secret.KeyID, secret.Algorithm, v.Revision)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("settings changed; reload before saving")
		}
		// Disabling local also revokes pre-existing normal local sessions.
		if !v.Local.Enabled {
			if _, err = tx.Exec(ctx, `DELETE FROM identity_sessions WHERE kind='local'`); err != nil {
				return err
			}
		}
		_, _, err = log.LogInTx(ctx, tx, audit.Event{OrgID: &actor.OrgID, ActorID: &actor.UserID, Action: "auth.settings.update", TargetKind: "identity", After: map[string]any{"local_enabled": v.Local.Enabled, "totp_policy": v.Local.TOTPPolicy, "oidc_configured": v.OIDC != nil}})
		return err
	})
}

func (s Store) recoveryEmail(ctx context.Context, org string) (string, error) {
	var email string
	err := s.Pool.QueryRow(ctx, `SELECT u.email FROM local_users l JOIN users u ON u.id=l.user_id JOIN orgs o ON o.id=u.org_id WHERE l.break_glass AND o.name=$1 AND NOT u.disabled`, org).Scan(&email)
	return email, err
}
