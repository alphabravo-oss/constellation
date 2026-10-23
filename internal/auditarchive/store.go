package auditarchive

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

func loadCheckpoint(ctx context.Context, tx pgx.Tx, c Config) (checkpoint, error) {
	cp := checkpoint{Hash: audit.GenesisHash}
	if !c.DryRun {
		if _, err := tx.Exec(ctx, `INSERT INTO audit_archive_progress(stream) VALUES($1) ON CONFLICT DO NOTHING`, c.stream()); err != nil {
			return cp, err
		}
	}
	query := `SELECT last_id,last_hash,last_manifest FROM audit_archive_progress WHERE stream=$1`
	if !c.DryRun {
		query += " FOR UPDATE"
	}
	err := tx.QueryRow(ctx, query, c.stream()).Scan(&cp.ID, &cp.Hash, &cp.Manifest)
	if errors.Is(err, pgx.ErrNoRows) && c.DryRun {
		return checkpoint{Hash: audit.GenesisHash}, nil
	}
	if err != nil {
		return cp, err
	}
	if cp.ID == 0 {
		if cp.Hash != audit.GenesisHash || cp.Manifest != "" {
			return cp, errors.New("invalid genesis archive checkpoint")
		}
	} else {
		var hash string
		if err = tx.QueryRow(ctx, `SELECT chain_hash FROM audit_events WHERE id=$1`, cp.ID).Scan(&hash); err != nil {
			return cp, fmt.Errorf("archive checkpoint source missing: %w", err)
		}
		if hash != cp.Hash || cp.Manifest == "" {
			return cp, errors.New("archive checkpoint does not match source chain")
		}
	}
	return cp, nil
}
