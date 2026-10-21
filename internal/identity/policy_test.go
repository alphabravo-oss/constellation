package identity

import (
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestOfflinePasswordPolicy(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"password", "Password", "123456", "qwerty", "letmein"} {
		if err := checkPassword(p, 12); err == nil {
			t.Errorf("breached password accepted")
		}
	}
	if err := checkPassword("a-unique-strong-passphrase-197!", 16); err != nil {
		t.Fatal(err)
	}
	if err := checkPassword("new-short", 16); err == nil {
		t.Fatal("minimum length ignored")
	}
	if len(breachedPasswords)%16 != 0 || len(breachedPasswords)/16 != 97747 {
		t.Fatal("offline corpus truncated")
	}
}
func TestSessionExpiryAndFreshnessFailClosed(t *testing.T) {
	t.Parallel()
	s := &Service{}
	raw := "csi_" + randomToken()
	snapshot := &sessionSnapshot{Checked: time.Now(), Entries: map[string]cachedSession{tokenHash(raw): {Subject: authctx.Subject{Email: "test@example.test"}, Expires: time.Now().Add(time.Hour)}}}
	s.sessions.current.Store(snapshot)
	if _, err := s.session(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.session(raw + "tamper"); err == nil {
		t.Fatal("malformed session accepted")
	}
	s.sessions.current.Store(&sessionSnapshot{Checked: time.Now().Add(-2 * time.Second), Entries: snapshot.Entries})
	if _, err := s.session(raw); err == nil {
		t.Fatal("stale snapshot accepted")
	}
	s.sessions.current.Store(&sessionSnapshot{Checked: time.Now(), Entries: map[string]cachedSession{tokenHash(raw): {Expires: time.Now().Add(-time.Second)}}})
	if _, err := s.session(raw); err == nil {
		t.Fatal("expired session accepted")
	}
}
