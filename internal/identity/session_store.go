package identity

import (
	"context"

	"github.com/google/uuid"
)

func (s Store) acknowledgeSessionRevision(ctx context.Context, id uuid.UUID, revision int64) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO identity_session_replicas(id,revision) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET revision=EXCLUDED.revision,last_seen=now()`, id, revision)
	return err
}
func (s Store) replicasReady(ctx context.Context, revision int64) (bool, error) {
	var ready bool
	err := s.Pool.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM identity_session_replicas WHERE last_seen>now()-interval '1 second' AND revision<$1)`, revision).Scan(&ready)
	return ready, err
}
func (s Store) forgetSessionReplica(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM identity_session_replicas WHERE id=$1 OR last_seen<now()-interval '10 minutes'`, id)
	return err
}
