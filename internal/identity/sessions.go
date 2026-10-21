package identity

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

const sessionSnapshotLimit = 10000
const sessionSnapshotMaxAge = time.Second

type cachedSession struct {
	Subject authctx.Subject
	Expires time.Time
}
type sessionSnapshot struct {
	Revision int64
	Checked  time.Time
	Entries  map[string]cachedSession
}
type sessionCache struct {
	mu      sync.Mutex
	current atomic.Pointer[sessionSnapshot]
}

// Every request hashes its opaque token and checks expiry and snapshot freshness.
// A small DB revision is polled four times/second; full snapshots are transferred
// only after changes. Triggers cover generic user APIs, logout, cleanup and direct
// operator SQL too. A DB outage fails closed within one second, never extending a
// token or retaining revoked privileges indefinitely.
// RefreshSessions synchronizes the bounded session index with committed DB state.
func (s *Service) RefreshSessions(ctx context.Context) error {
	s.sessions.mu.Lock()
	defer s.sessions.mu.Unlock()
	old := s.sessions.current.Load()
	var revision int64
	if err := s.store.Pool.QueryRow(ctx, `SELECT revision FROM identity_session_revision WHERE singleton`).Scan(&revision); err != nil {
		return err
	}
	if old != nil && old.Revision == revision {
		s.sessions.current.Store(&sessionSnapshot{Revision: revision, Checked: time.Now(), Entries: old.Entries})
		return nil
	}
	rows, err := s.store.Pool.Query(ctx, `SELECT s.token_hash,u.id,u.org_id,u.email,s.roles,s.expires_at FROM identity_sessions s JOIN users u ON u.id=s.user_id WHERE s.expires_at>now() AND NOT u.disabled AND s.session_epoch=u.session_epoch AND (s.kind<>'local' OR (SELECT (local_config->>'enabled')::boolean FROM identity_settings WHERE singleton)) LIMIT 10001`)
	if err != nil {
		return err
	}
	defer rows.Close()
	entries := make(map[string]cachedSession)
	for rows.Next() {
		var key string
		var entry cachedSession
		var grants []rbac.RoleAssignment
		if err := rows.Scan(&key, &entry.Subject.UserID, &entry.Subject.OrgID, &entry.Subject.Email, &grants, &entry.Expires); err != nil {
			return err
		}
		entry.Subject.Assignments = grants
		entries[key] = entry
		if len(entries) > sessionSnapshotLimit {
			return errors.New("active session snapshot exceeds capacity")
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// Reading the revision before rows makes concurrent changes cause another
	// refresh on the next poll, rather than marking an older snapshot current.
	s.sessions.current.Store(&sessionSnapshot{Revision: revision, Checked: time.Now(), Entries: entries})
	return nil
}
func (s *Service) session(raw string) (authctx.Subject, error) {
	if len(raw) != 47 {
		return authctx.Subject{}, errors.New("invalid session length")
	}
	snapshot := s.sessions.current.Load()
	now := time.Now()
	if snapshot == nil || now.Sub(snapshot.Checked) > sessionSnapshotMaxAge {
		return authctx.Subject{}, errors.New("session snapshot unavailable")
	}
	entry, ok := snapshot.Entries[tokenHash(raw)]
	if !ok || !now.Before(entry.Expires) {
		return authctx.Subject{}, errors.New("session expired or revoked")
	}
	return entry.Subject, nil
}
