package crypto

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Column names one encrypted column in one table: the primary key, the
// ciphertext column and the key-id column written next to it.
type Column struct {
	Table, PK, Ciphertext, KeyID, Algorithm string
}

// Columns is the inventory of encrypted columns (guide ch.06 rotation job).
// Adding an encrypted column means adding it here so rotate-keys covers it.
var Columns = []Column{
	{Table: "registries", PK: "id", Ciphertext: "auth_secret", KeyID: "key_id", Algorithm: "algorithm"},
	{Table: "git_connectors", PK: "org_id", Ciphertext: "pat_sealed", KeyID: "key_id", Algorithm: "algorithm"},
	{Table: "fed_joint_secret", PK: "org_id", Ciphertext: "client_key_enc", KeyID: "key_id", Algorithm: "algorithm"},
	{Table: "fed_ca", PK: "id", Ciphertext: "key_enc", KeyID: "key_id", Algorithm: "algorithm"},
	{Table: "cluster_init_bundles", PK: "id", Ciphertext: "contents_encrypted", KeyID: "key_id", Algorithm: "algorithm"},
}

// RotateReport counts what Rotate did per table.
type RotateReport struct {
	Rotated map[string]int
	Skipped map[string]int // rows already under the current key
	Failed  map[string]int // rows that no key in the set could open
}

// Rotate re-seals every row whose key_id is not the current key under the
// current key, one row per transaction (resumable: rerunning only touches
// what is left). Rows no key can open are counted and left untouched.
func Rotate(ctx context.Context, pool *pgxpool.Pool, enc *Encryptor, dryRun bool, logger *slog.Logger) (RotateReport, error) {
	if logger == nil {
		logger = slog.Default()
	}
	rep := RotateReport{Rotated: map[string]int{}, Skipped: map[string]int{}, Failed: map[string]int{}}
	for _, c := range Columns {
		if err := rotateColumn(ctx, pool, enc, c, dryRun, logger, &rep); err != nil {
			return rep, fmt.Errorf("rotate %s.%s: %w", c.Table, c.Ciphertext, err)
		}
	}
	return rep, nil
}

type sealedRow struct {
	pk        string
	ct        []byte
	keyID     string
	algorithm string
}

func rotateColumn(ctx context.Context, pool *pgxpool.Pool, enc *Encryptor, c Column, dryRun bool, logger *slog.Logger, rep *RotateReport) error {
	pending, err := pendingRows(ctx, pool, enc, c, rep)
	if err != nil {
		return err
	}
	for _, r := range pending {
		pt, err := enc.Decrypt(Sealed{KeyID: r.keyID, Algorithm: r.algorithm, Ciphertext: r.ct})
		if err != nil {
			rep.Failed[c.Table]++
			logger.Warn("rotate-keys: row cannot be opened with any configured key",
				slog.String("table", c.Table), slog.String("pk", r.pk), slog.String("key_id", r.keyID))
			continue
		}
		if dryRun {
			rep.Rotated[c.Table]++
			continue
		}
		if err := resealRow(ctx, pool, enc, c, r, pt, rep); err != nil {
			return err
		}
	}
	logger.Info("rotate-keys", slog.String("table", c.Table), slog.Int("rotated", rep.Rotated[c.Table]),
		slog.Int("skipped", rep.Skipped[c.Table]), slog.Int("failed", rep.Failed[c.Table]), slog.Bool("dry_run", dryRun))
	return nil
}

// pendingRows lists the rows of c not yet under the current key.
func pendingRows(ctx context.Context, pool *pgxpool.Pool, enc *Encryptor, c Column, rep *RotateReport) ([]sealedRow, error) {
	q := fmt.Sprintf(`SELECT %s::text, %s, COALESCE(%s, ''), COALESCE(%s, '') FROM %s WHERE %s IS NOT NULL`,
		c.PK, c.Ciphertext, c.KeyID, c.Algorithm, c.Table, c.Ciphertext)
	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pending []sealedRow
	for rows.Next() {
		var r sealedRow
		if err := rows.Scan(&r.pk, &r.ct, &r.keyID, &r.algorithm); err != nil {
			return nil, err
		}
		if r.keyID == enc.KeyID() {
			rep.Skipped[c.Table]++
			continue
		}
		pending = append(pending, r)
	}
	return pending, rows.Err()
}

// resealRow re-encrypts one row under the current key in its own transaction,
// guarded by the key_id it was read with so a concurrent writer is never clobbered.
func resealRow(ctx context.Context, pool *pgxpool.Pool, enc *Encryptor, c Column, r sealedRow, pt []byte, rep *RotateReport) error {
	sealed, err := enc.Encrypt(pt)
	if err != nil {
		return err
	}
	upd := fmt.Sprintf(`UPDATE %s SET %s = $1, %s = $2, %s = $3 WHERE %s::text = $4 AND %s IS NOT DISTINCT FROM NULLIF($5, '')`,
		c.Table, c.Ciphertext, c.KeyID, c.Algorithm, c.PK, c.KeyID)
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, upd, sealed.Ciphertext, sealed.KeyID, sealed.Algorithm, r.pk, r.keyID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			rep.Rotated[c.Table]++
		}
		return nil
	})
}
