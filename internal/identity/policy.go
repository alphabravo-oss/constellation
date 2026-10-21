package identity

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"
)

//go:embed passwords/ncsc.bin
var breachedPasswords []byte

type LocalConfig struct {
	Enabled           bool   `json:"enabled"`
	Display           string `json:"display"`     // all, local, or sso; presentation never grants access.
	TOTPPolicy        string `json:"totp_policy"` // everyone or admins
	PasswordMinLength int    `json:"password_min_length"`
	SessionSeconds    int    `json:"session_seconds"`
	IPRate            int    `json:"ip_rate"`
	AccountRate       int    `json:"account_rate"`
	OrgName           string `json:"-"`
	BootstrapEmail    string `json:"-"`
	BootstrapPassword string `json:"-"`
	BootstrapTOTP     string `json:"-"`
}

func (c *LocalConfig) defaults() {
	if c.Display == "" {
		c.Display = "all"
	}
	if c.TOTPPolicy == "" {
		c.TOTPPolicy = "everyone"
	}
	if c.PasswordMinLength == 0 {
		c.PasswordMinLength = 16
	}
	if c.SessionSeconds == 0 {
		c.SessionSeconds = 3600
	}
	if c.IPRate == 0 {
		c.IPRate = 20
	}
	if c.AccountRate == 0 {
		c.AccountRate = 5
	}
	if c.OrgName == "" {
		c.OrgName = "default"
	}
}
func (c LocalConfig) validate() error {
	if c.Display != "all" && c.Display != "local" && c.Display != "sso" {
		return errors.New("invalid sign-in display policy")
	}
	if c.TOTPPolicy != "everyone" && c.TOTPPolicy != "admins" {
		return errors.New("TOTP policy must be everyone or admins")
	}
	if c.PasswordMinLength < 12 || c.PasswordMinLength > 128 {
		return errors.New("password minimum must be between 12 and 128 characters")
	}
	if c.SessionSeconds < 60 || c.SessionSeconds > 86400 {
		return errors.New("session lifetime must be between 60 and 86400 seconds")
	}
	if c.IPRate < 1 || c.IPRate > 100 || c.AccountRate < 1 || c.AccountRate > 20 {
		return errors.New("invalid login rate limit")
	}
	return nil
}
func checkPassword(password string, minimum int) error {
	if len(password) > 4096 {
		return errors.New("password exceeds 4096 bytes")
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(password))))
	n := len(breachedPasswords) / 16
	i := sort.Search(n, func(i int) bool { return bytes.Compare(breachedPasswords[i*16:(i+1)*16], sum[:16]) >= 0 })
	if i < n && bytes.Equal(breachedPasswords[i*16:(i+1)*16], sum[:16]) {
		return errors.New("password appears in the offline breached-password list; choose another")
	}
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < minimum {
		return errors.New("password is shorter than the configured minimum")
	}
	return nil
}
