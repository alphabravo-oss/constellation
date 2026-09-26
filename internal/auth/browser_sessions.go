package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const AccessCookie = "__Host-constellation-session"
const RefreshCookie = "__Host-constellation-refresh"
const BrowserHeader = "X-Constellation-Client"
const RefreshLifetime = 7 * 24 * time.Hour

var ErrRefreshInvalid = errors.New("invalid refresh session")
var ErrRefreshReused = errors.New("refresh token reuse detected")

type BrowserSession struct {
	UserID         uuid.UUID
	OrgID          uuid.UUID
	SessionID      uuid.UUID
	AccessToken    string
	RefreshToken   string
	AccessExpires  time.Time
	RefreshExpires time.Time
}

func BrowserRequest(request *http.Request) bool {
	return request.Header.Get(BrowserHeader) == "browser" || request.Header.Get("Origin") != "" || request.Header.Get("Sec-Fetch-Mode") != ""
}

func SetBrowserCookies(writer http.ResponseWriter, session *BrowserSession) {
	writer.Header().Set("Cache-Control", "no-store")
	for _, cookie := range []struct {
		name    string
		value   string
		expires time.Time
	}{{AccessCookie, session.AccessToken, session.AccessExpires}, {RefreshCookie, session.RefreshToken, session.RefreshExpires}} {
		http.SetCookie(writer, &http.Cookie{
			Name: cookie.name, Value: cookie.value, Path: "/", HttpOnly: true,
			Secure: true, SameSite: http.SameSiteStrictMode, Expires: cookie.expires,
			MaxAge: max(1, int(time.Until(cookie.expires).Seconds())),
		})
	}
}

func ClearBrowserCookies(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	for _, name := range []string{AccessCookie, RefreshCookie} {
		http.SetCookie(writer, &http.Cookie{
			Name: name, Path: "/", HttpOnly: true, Secure: true,
			SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0),
		})
	}
}

func newRefreshToken() (string, string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(secret)
	return raw, refreshHash(raw), nil
}

func refreshHash(raw string) string {
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:])
}

func StartBrowserSession(ctx context.Context, pool *pgxpool.Pool, signer *Signer, accessToken string) (*BrowserSession, error) {
	claims, err := signer.Verify(accessToken)
	if err != nil || !claims.Tracked || claims.ExpiresAt == nil {
		return nil, ErrRefreshInvalid
	}
	raw, digest, err := newRefreshToken()
	if err != nil {
		return nil, err
	}
	expires := time.Now().Add(RefreshLifetime)
	policy, _, err := LoadSecurityPolicy(ctx, pool, claims.OrgID)
	if err != nil {
		return nil, err
	}
	if policy.SessionTimeoutMinutes > 0 {
		expires = time.Now().Add(min(RefreshLifetime, policy.SessionTTL(RefreshLifetime)))
	}
	result, err := pool.Exec(ctx, `
INSERT INTO browser_refresh_tokens(token_hash, session_id, session_epoch, expires_at)
SELECT $1, sessions.session_id, users.session_epoch, $2
FROM user_sessions sessions JOIN users ON users.id = sessions.user_id
WHERE sessions.session_id=$3 AND users.id=$4 AND users.org_id=$5
  AND users.session_epoch=$6 AND NOT users.disabled`,
		digest, expires, claims.SessionID(), claims.UserID, claims.OrgID, claims.Epoch)
	if err != nil {
		return nil, err
	}
	if result.RowsAffected() != 1 {
		return nil, ErrRefreshInvalid
	}
	return &BrowserSession{
		UserID: claims.UserID, OrgID: claims.OrgID, SessionID: claims.SessionID(),
		AccessToken: accessToken, AccessExpires: claims.ExpiresAt.Time,
		RefreshToken: raw, RefreshExpires: expires,
	}, nil
}

func RotateBrowserSession(ctx context.Context, pool *pgxpool.Pool, signer *Signer, raw string, defaultIdle time.Duration) (*BrowserSession, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) != 32 {
		return nil, ErrRefreshInvalid
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var session BrowserSession
	var epoch int64
	var disabled bool
	var email string
	err = tx.QueryRow(ctx, `
SELECT users.id, users.org_id, users.email, users.session_epoch, users.disabled
FROM browser_refresh_tokens tokens
JOIN user_sessions sessions ON sessions.session_id=tokens.session_id
JOIN users ON users.id=sessions.user_id
WHERE tokens.token_hash=$1 FOR UPDATE OF users`, refreshHash(raw)).Scan(
		&session.UserID, &session.OrgID, &email, &epoch, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRefreshInvalid
	}
	if err != nil {
		return nil, err
	}
	var storedEpoch int64
	var consumed *time.Time
	var lastSeen time.Time
	err = tx.QueryRow(ctx, `
SELECT tokens.session_id, tokens.session_epoch, tokens.expires_at, tokens.consumed_at, sessions.last_seen_at
FROM browser_refresh_tokens tokens JOIN user_sessions sessions ON sessions.session_id=tokens.session_id
WHERE tokens.token_hash=$1 FOR UPDATE OF tokens, sessions`, refreshHash(raw)).Scan(
		&session.SessionID, &storedEpoch, &session.RefreshExpires, &consumed, &lastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRefreshInvalid
	}
	if err != nil {
		return nil, err
	}
	policy, _, err := LoadSecurityPolicy(ctx, tx, session.OrgID)
	if err != nil {
		return nil, err
	}
	idle := policy.IdleTimeout(defaultIdle)
	if consumed != nil || disabled || storedEpoch != epoch || !session.RefreshExpires.After(time.Now()) || (idle > 0 && time.Since(lastSeen) > idle) {
		if _, err := tx.Exec(ctx, `DELETE FROM user_sessions WHERE session_id=$1`, session.SessionID); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		if consumed != nil {
			return &session, ErrRefreshReused
		}
		return &session, ErrRefreshInvalid
	}
	var roles []string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT role), ARRAY[]::text[]) FROM role_assignments WHERE user_id=$1`, session.UserID).Scan(&roles); err != nil {
		return nil, err
	}
	ttl := min(policy.SessionTTL(signer.TTL()), 15*time.Minute)
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	ttl = min(ttl, time.Until(session.RefreshExpires))
	if ttl <= 0 {
		return nil, ErrRefreshInvalid
	}
	session.AccessToken, _, err = signer.IssueTracked(ttl, session.SessionID, session.UserID, session.OrgID, email, roles, epoch)
	if err != nil {
		return nil, err
	}
	session.AccessExpires = time.Now().Add(ttl)
	var digest string
	session.RefreshToken, digest, err = newRefreshToken()
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE browser_refresh_tokens SET consumed_at=now() WHERE token_hash=$1`, refreshHash(raw)); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO browser_refresh_tokens(token_hash, session_id, session_epoch, expires_at) VALUES ($1,$2,$3,$4)`, digest, session.SessionID, epoch, session.RefreshExpires); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE user_sessions SET last_seen_at=GREATEST(last_seen_at, clock_timestamp()) WHERE session_id=$1`, session.SessionID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &session, nil
}
