package identity

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	columncrypto "github.com/alphabravocompany/constellation/internal/crypto"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

func validTOTPSecret(secret string) bool {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	return err == nil && len(raw) >= 20
}
func newTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

type Enrollment struct {
	ID         uuid.UUID `json:"id"`
	Password   string    `json:"password,omitempty"`
	TOTPSecret string    `json:"totp_secret,omitempty"`
	TOTPURI    string    `json:"totp_uri,omitempty"`
}

func enrollment(id uuid.UUID, email, password, secret string) Enrollment {
	uri := ""
	if secret != "" {
		uri = "otpauth://totp/" + url.PathEscape("Constellation:"+email) + "?" + url.Values{"secret": {secret}, "issuer": {"Constellation"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}.Encode()
	}
	return Enrollment{ID: id, Password: password, TOTPSecret: secret, TOTPURI: uri}
}
func totpRequired(policy string, c localCredential) bool {
	if c.breakGlass || policy == "everyone" {
		return true
	}
	for _, a := range c.subject.Assignments {
		if a.Role == rbac.RoleGlobalAdmin || a.Role == rbac.RoleSecurityAdmin || a.Role == rbac.RoleClusterAdmin {
			return true
		}
	}
	return false
}
func (s *Service) loginLocal(ctx context.Context, email, password, code string, emergencyOnly bool) (string, time.Time, string, error) {
	select {
	case s.passwordSlots <- struct{}{}:
		defer func() { <-s.passwordSlots }()
	default:
		return "", time.Time{}, "local", errPasswordBusy
	}
	cfg, err := s.store.readSettings(ctx, s.enc)
	if err != nil {
		return "", time.Time{}, "local", err
	}
	c, err := s.store.localCredential(ctx, strings.ToLower(strings.TrimSpace(email)), s.org, cfg.Local.AccountRate)
	kind := "local"
	if c.breakGlass || emergencyOnly {
		kind = "break-glass"
	}
	if err != nil {
		if !errors.Is(err, errLoginBlocked) {
			_ = VerifyPassword(s.dummyHash, password)
		}
		return "", time.Time{}, kind, err
	}
	// Recovery remains usable if SSO was never configured as well as during an
	// outage. It is the only permitted local identity when local login is off.
	if c.disabled || (!cfg.Local.Enabled && !c.breakGlass) || (emergencyOnly && !c.breakGlass) {
		return "", time.Time{}, kind, ErrInvalidPassword
	}
	if err = s.verifyLocal(ctx, c, cfg.Local.TOTPPolicy, password, code); err != nil {
		return "", time.Time{}, kind, err
	}
	ttl := time.Duration(cfg.Local.SessionSeconds) * time.Second
	if c.breakGlass {
		ttl = s.emergency.SessionTTL
	}
	expires := time.Now().Add(ttl)
	raw, err := s.store.startSession(ctx, c.subject, c.epoch, c.roles, kind, expires, s.audit)
	if err == nil {
		err = s.publishSession(ctx)
	}
	return raw, expires, kind, err
}
func (s *Service) verifyLocal(ctx context.Context, c localCredential, policy, password, code string) error {
	if VerifyPassword(c.hash, password) != nil {
		return ErrInvalidPassword
	}
	step := int64(-1)
	if totpRequired(policy, c) || code != "" {
		if s.enc == nil {
			return columncrypto.ErrNoKey
		}
		plain, err := s.enc.Decrypt(c.secret)
		if err != nil {
			return err
		}
		step = totpStep(string(plain), code, time.Now())
		if step < 0 {
			return ErrInvalidPassword
		}
	}
	if len(c.roles) == 0 {
		return ErrInvalidPassword
	}
	ok, err := s.store.localSuccess(ctx, c, step)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidPassword
	}
	return nil
}
func (s *Service) createUser(ctx context.Context, actor authctx.Subject, email, name, password, role string) (Enrollment, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || len(email) > 254 {
		return Enrollment{}, errors.New("enter a valid email address")
	}
	if len(name) > 200 {
		return Enrollment{}, errors.New("display name exceeds 200 bytes")
	}
	if name == "" {
		name = email
	}
	if !rbac.IsRole(role) {
		return Enrollment{}, errors.New("invalid product role")
	}
	cfg, err := s.store.readSettings(ctx, s.enc)
	if err != nil {
		return Enrollment{}, err
	}
	if password == "" {
		password = randomToken()
	}
	if err = checkPassword(password, cfg.Local.PasswordMinLength); err != nil {
		return Enrollment{}, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return Enrollment{}, err
	}
	secret, err := newTOTPSecret()
	if err != nil {
		return Enrollment{}, err
	}
	if s.enc == nil {
		return Enrollment{}, columncrypto.ErrNoKey
	}
	sealed, err := s.enc.Encrypt([]byte(secret))
	if err != nil {
		return Enrollment{}, err
	}
	id, err := s.store.createLocal(ctx, actor.OrgID, email, name, hash, sealed, role, false, &actor.UserID, s.audit)
	if err != nil {
		return Enrollment{}, errors.New("cannot create local user; check that the email is unique")
	}
	return enrollment(id, email, password, secret), nil
}
func (s *Service) mutateUser(ctx context.Context, actor authctx.Subject, id uuid.UUID, action, value string) (Enrollment, error) {
	if id == actor.UserID && (action == "disable" || action == "role") {
		return Enrollment{}, errors.New("another administrator must change your own access")
	}
	var sealed columncrypto.Sealed
	out := Enrollment{ID: id}
	var err error
	switch action {
	case "reset-password":
		value, out.Password, err = s.preparePassword(ctx, value)
	case "reset-totp":
		var seed string
		seed, err = newTOTPSecret()
		if err == nil && s.enc == nil {
			err = columncrypto.ErrNoKey
		}
		if err == nil {
			sealed, err = s.enc.Encrypt([]byte(seed))
			out = enrollment(id, id.String(), "", seed)
		}
	case "role":
		if !rbac.IsRole(value) {
			return out, errors.New("invalid product role")
		}
	case "disable":
	default:
		return out, errors.New("invalid user action")
	}
	if err != nil {
		return out, err
	}
	err = s.store.mutateLocal(ctx, actor.OrgID, id, actor.UserID, action, value, sealed, s.audit)
	if err == nil {
		err = s.RefreshSessions(ctx)
	}
	return out, err
}

func (s *Service) preparePassword(ctx context.Context, password string) (hash, plain string, err error) {
	cfg, err := s.store.readSettings(ctx, s.enc)
	if err != nil {
		return "", "", err
	}
	if password == "" {
		password = randomToken()
	}
	if err = checkPassword(password, cfg.Local.PasswordMinLength); err != nil {
		return "", "", err
	}
	hash, err = HashPassword(password)
	return hash, password, err
}
