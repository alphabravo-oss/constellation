package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/securefiles"
)

const pcapRetentionBatch = 100

type pcapRetentionCursor struct {
	mu    sync.Mutex
	after *uuid.UUID
}

// RunPcapRetention is global maintenance, not a tenant-facing read. It requires
// explicit operator confirmation that this root is either the sole API's durable
// RWO store or the same RWX store mounted by every API replica. A missing local
// artifact cannot prove absence from another replica's private disk.
// The leader context cancels the timer and DB work on shutdown/lease loss.
func RunPcapRetention(ctx context.Context, database *db.DB, logger *slog.Logger) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("CONSTELLATION_PCAP_RETENTION_ENABLED")), "true") {
		return
	}
	if strings.TrimSpace(os.Getenv("CONSTELLATION_DATA_DIR")) == "" {
		if logger != nil {
			logger.Error("pcap retention requires an explicit verified shared or single-replica durable DATA_DIR")
		}
		return
	}
	h := NewPcapHTTP(database)
	var root *os.Root
	defer func() {
		if root != nil {
			_ = root.Close()
		}
	}()
	runPcapRetention(ctx, logger, time.Minute, func(ctx context.Context, logger *slog.Logger) (int, error) {
		if root == nil {
			var err error
			root, err = securefiles.OpenPrivateDir(pcapDataDir())
			if err != nil {
				return 0, errors.New("pcap retention store unavailable; receipts retained")
			}
		}
		return h.sweepExpired(ctx, logger, root)
	})
}

func runPcapRetention(ctx context.Context, logger *slog.Logger, interval time.Duration, sweep func(context.Context, *slog.Logger) (int, error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		cycle, cancel := context.WithTimeout(ctx, 30*time.Second)
		removed, err := sweep(cycle, logger)
		cancel()
		if err != nil && ctx.Err() == nil && logger != nil {
			logger.Warn("pcap retention incomplete; retained receipts will retry", slog.Int("removed", removed), slog.String("err", err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type expiredPcap struct{ id, org, cluster uuid.UUID }

// SweepExpired processes at most 100 expired receipts. Each receipt remains
// locked until its canonical file is removed and the row deletion commits.
// Failed removals retain the row for retry; there is no arbitrary orphan scan.
// A database failure after file removal can leave a receipt whose file is absent;
// a later cycle safely retries that idempotent removal before deleting the row.
func (h *PcapHTTP) SweepExpired(ctx context.Context, logger *slog.Logger) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	root, err := securefiles.OpenPrivateDir(pcapDataDir())
	if err != nil {
		return 0, err
	}
	defer func() { _ = root.Close() }()
	return h.sweepExpired(ctx, logger, root)
}

func (h *PcapHTTP) sweepExpired(ctx context.Context, logger *slog.Logger, root *os.Root) (int, error) {
	if err := verifyPcapRetentionRoot(root); err != nil {
		return 0, err
	}
	if !h.retention.mu.TryLock() {
		return 0, nil
	}
	defer h.retention.mu.Unlock()
	candidates, err := h.expiredPcapCandidates(ctx, h.retention.after)
	if err != nil {
		return 0, err
	}
	if len(candidates) == 0 && h.retention.after != nil {
		h.retention.after = nil
		candidates, err = h.expiredPcapCandidates(ctx, nil)
		if err != nil {
			return 0, err
		}
	}
	removed, failed := 0, 0
	for _, candidate := range candidates {
		if err = ctx.Err(); err != nil {
			return removed, err
		}
		// Advance even when locked or failed so another tenant cannot starve.
		next := candidate.id
		h.retention.after = &next
		didRemove, removeErr := h.removeExpiredPcap(ctx, candidate, root)
		if removeErr != nil {
			failed++
			if logger != nil {
				logger.Warn("pcap retention receipt retained", slog.String("id", candidate.id.String()), slog.String("err", removeErr.Error()))
			}
			continue
		}
		if didRemove {
			removed++
		}
	}
	if failed > 0 {
		return removed, fmt.Errorf("%d expired capture receipts retained for retry", failed)
	}
	if removed > 0 && logger != nil {
		logger.Info("pcap retention", slog.Int("removed", removed))
	}
	return removed, nil
}

func (h *PcapHTTP) expiredPcapCandidates(ctx context.Context, after *uuid.UUID) ([]expiredPcap, error) {
	rows, err := h.db.Pool().Query(ctx, `SELECT id,org_id,cluster_id FROM runtime_pcap_captures WHERE expires_at<NOW() AND ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT $2`, after, pcapRetentionBatch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	candidates := []expiredPcap{}
	for rows.Next() {
		var c expiredPcap
		if err = rows.Scan(&c.id, &c.org, &c.cluster); err != nil {
			return nil, err
		}
		candidates = append(candidates, c)
	}
	return candidates, rows.Err()
}

func (h *PcapHTTP) removeExpiredPcap(ctx context.Context, c expiredPcap, root *os.Root) (bool, error) {
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var id uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM runtime_pcap_captures WHERE id=$1 AND org_id=$2 AND cluster_id=$3 AND expires_at<clock_timestamp() FOR UPDATE SKIP LOCKED`, c.id, c.org, c.cluster).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}
	if err = verifyPcapRetentionRoot(root); err != nil {
		return false, err
	}
	if err = removeExpiredPcapFile(root, c.id); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM runtime_pcap_captures WHERE id=$1 AND org_id=$2 AND cluster_id=$3`, c.id, c.org, c.cluster); err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func verifyPcapRetentionRoot(root *os.Root) error {
	expected, err := os.Lstat(pcapDataDir())
	if err != nil {
		return err
	}
	actual, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !expected.IsDir() || expected.Mode()&os.ModeSymlink != 0 || !os.SameFile(expected, actual) {
		return errors.New("pcap retention root changed; receipts retained")
	}
	return nil
}

func removeExpiredPcapFile(root *os.Root, id uuid.UUID) error {
	info, err := root.Lstat(pcapFileName(id))
	if os.IsNotExist(err) {
		return syncPcapRetentionDirectory(root)
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("expired capture artifact is not a regular file")
	}
	if err = root.Remove(pcapFileName(id)); err != nil {
		return err
	}
	return syncPcapRetentionDirectory(root)
}

func syncPcapRetentionDirectory(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
