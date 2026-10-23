package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

type Store struct{ Pool *pgxpool.Pool }

func (s Store) resolve(ctx context.Context, org, issuer string, p *Principal) (authctx.Subject, int64, error) {
	var subj authctx.Subject
	var epoch int64
	err := s.Pool.QueryRow(ctx, `SELECT u.id,u.org_id,u.email,u.session_epoch FROM users u JOIN orgs o ON o.id=u.org_id WHERE o.name=$1 AND u.oidc_issuer=$2 AND u.oidc_subject=$3 AND NOT u.disabled`, org, issuer, p.Subject).Scan(&subj.UserID, &subj.OrgID, &subj.Email, &epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		// Never link by email. A matching email with a different issuer/subject is rejected.
		email := p.Email
		if email == "" {
			email = p.Subject + "@oidc.invalid"
		}
		err = s.Pool.QueryRow(ctx, `INSERT INTO users(org_id,email,display_name,oidc_issuer,oidc_subject) SELECT id,$2,$3,$4,$5 FROM orgs WHERE name=$1 ON CONFLICT(oidc_issuer,oidc_subject) DO UPDATE SET updated_at=now() WHERE NOT users.disabled RETURNING id,org_id,email,session_epoch`, org, email, p.Name, issuer, p.Subject).Scan(&subj.UserID, &subj.OrgID, &subj.Email, &epoch)
	}
	if err != nil {
		return subj, 0, err
	}
	for _, role := range p.Roles {
		subj.Assignments = append(subj.Assignments, rbac.RoleAssignment{Role: role, Scope: rbac.Scope{OrgID: subj.OrgID}})
	}
	return subj, epoch, nil
}

func (s Store) startSession(ctx context.Context, subj authctx.Subject, epoch int64, roles []string, kind string, expires time.Time, log *audit.Logger) (string, error) {
	raw := "csi_" + randomToken()
	roleJSON, _ := json.Marshal(subj.Assignments)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Login reconciles persisted grants for PATs and the access-control overview.
	var currentEpoch int64
	if err = tx.QueryRow(ctx, `SELECT session_epoch FROM users WHERE id=$1 AND NOT disabled FOR UPDATE`, subj.UserID).Scan(&currentEpoch); err != nil {
		return "", err
	}
	if currentEpoch != epoch {
		return "", errors.New("account access changed during login")
	}
	if kind == "local" {
		var enabled bool
		if err = tx.QueryRow(ctx, `SELECT (local_config->>'enabled')::boolean FROM identity_settings WHERE singleton FOR SHARE`).Scan(&enabled); err != nil || !enabled {
			return "", errors.New("local login disabled")
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET last_login_at=now() WHERE id=$1`, subj.UserID); err != nil {
		return "", err
	}
	if kind == "oidc" {
		if _, err = tx.Exec(ctx, `DELETE FROM role_assignments WHERE user_id=$1`, subj.UserID); err != nil {
			return "", err
		}
		for _, role := range roles {
			if _, err = tx.Exec(ctx, `INSERT INTO role_assignments(user_id,role,scope_org_id) VALUES($1,$2,$3)`, subj.UserID, role, subj.OrgID); err != nil {
				return "", err
			}
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO identity_sessions(token_hash,user_id,roles,session_epoch,kind,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, tokenHash(raw), subj.UserID, roleJSON, epoch, kind, expires); err != nil {
		return "", err
	}
	severity := "info"
	if kind == "break-glass" {
		severity = "critical"
	}
	if _, _, err = log.LogInTx(ctx, tx, audit.Event{OrgID: &subj.OrgID, ActorID: &subj.UserID, Action: "auth.login." + kind, TargetKind: "user", TargetID: subj.UserID.String(), After: map[string]any{"severity": severity, "expires_at": expires, "roles": roles}}); err != nil {
		return "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	return raw, nil
}

func (s Store) saveAttempt(ctx context.Context, state, binding, verifier, nonce string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO oidc_login_attempts(state_hash,binding_hash,verifier,nonce,expires_at) VALUES($1,$2,$3,$4,now()+interval '5 minutes')`, tokenHash(state), tokenHash(binding), verifier, nonce)
	return err
}
func (s Store) consumeAttempt(ctx context.Context, state, binding string) (string, string, error) {
	var verifier, nonce string
	err := s.Pool.QueryRow(ctx, `DELETE FROM oidc_login_attempts WHERE state_hash=$1 AND binding_hash=$2 AND expires_at>now() RETURNING verifier,nonce`, tokenHash(state), tokenHash(binding)).Scan(&verifier, &nonce)
	return verifier, nonce, err
}
func (s Store) logout(ctx context.Context, user uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM identity_sessions WHERE user_id=$1`, user)
	return err
}
