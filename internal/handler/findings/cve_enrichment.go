package findings

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CVE enrichment import — the opt-in detail layer. The lean matching bundle ships
// no descriptions; where offline CVE detail is wanted, a separate
// cve-enrichment.jsonl.gz artifact is delivered to CONSTELLATION_CVE_ENRICHMENT_PATH
// and this reconciler streams it into cve_records (description now; extensible to
// remediation / llm_summary / exploit_maturity as the producer adds fields).
// Version-keyed on the payload hash, like the core cve_records reconciler.

var cveEnrichmentMu sync.Mutex

type cveEnrichmentRecord struct {
	Table string `json:"table"`
	Row   struct {
		CVEID       string `json:"cve_id"`
		Description string `json:"description"`
	} `json:"row"`
}

// ReconcileCVEEnrichment imports the enrichment artifact at path into
// cve_records when its payload hash differs from the last import. No-op when the
// artifact isn't present (the common lean/connected case). Serialized.
func ReconcileCVEEnrichment(ctx context.Context, pool *pgxpool.Pool, path string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil // artifact not delivered: lean mode, nothing to import
	}
	if !cveEnrichmentMu.TryLock() {
		return nil
	}
	defer cveEnrichmentMu.Unlock()

	hash, err := fileSHA256(path)
	if err != nil {
		return err
	}
	var last string
	_ = pool.QueryRow(ctx, `SELECT payload_hash FROM cve_enrichment_import_state WHERE id=TRUE`).Scan(&last)
	if hash == last {
		return nil
	}
	logger.Info("cve enrichment import starting", slog.String("payload_hash", shortHash(hash)))

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open enrichment gzip: %w", err)
	}
	defer gz.Close()

	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // descriptions can be a few KB
	const batchSize = 500
	ids := make([]string, 0, batchSize)
	descs := make([]string, 0, batchSize)
	var total int
	flush := func() error {
		if len(ids) == 0 {
			return nil
		}
		if err := updateCVEDescriptions(ctx, pool, ids, descs); err != nil {
			return err
		}
		total += len(ids)
		ids = ids[:0]
		descs = descs[:0]
		return nil
	}
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec cveEnrichmentRecord
		if json.Unmarshal(line, &rec) != nil || rec.Row.CVEID == "" {
			continue
		}
		ids = append(ids, strings.ToUpper(strings.TrimSpace(rec.Row.CVEID)))
		descs = append(descs, rec.Row.Description)
		if len(ids) >= batchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read enrichment: %w", err)
	}
	if err := flush(); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO cve_enrichment_import_state (id, payload_hash, record_count, imported_at)
VALUES (TRUE, $1, $2, NOW())
ON CONFLICT (id) DO UPDATE SET payload_hash=EXCLUDED.payload_hash, record_count=EXCLUDED.record_count, imported_at=EXCLUDED.imported_at`,
		hash, total); err != nil {
		return err
	}
	logger.Info("cve enrichment import complete", slog.Int("rows", total), slog.String("payload_hash", shortHash(hash)))
	return nil
}

// updateCVEDescriptions sets description on existing cve_records rows via one
// VALUES-join UPDATE. Only rows already present (imported by the core reconciler)
// are touched; enrichment for ids not in cve_records is a harmless no-op.
func updateCVEDescriptions(ctx context.Context, pool *pgxpool.Pool, ids, descs []string) error {
	var sb strings.Builder
	sb.WriteString(`UPDATE cve_records c SET description = v.description
  FROM (VALUES `)
	args := make([]any, 0, len(ids)*2)
	for i := range ids {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, "($%d,$%d)", i*2+1, i*2+2)
		args = append(args, ids[i], descs[i])
	}
	sb.WriteString(`) AS v(cve_id, description) WHERE c.cve_id = v.cve_id`)
	_, err := pool.Exec(ctx, sb.String(), args...)
	return err
}

// ReconcileCVEEnrichmentLoop runs the enrichment reconcile shortly after start
// and on interval (picks up a newly-delivered or updated enrichment artifact).
func ReconcileCVEEnrichmentLoop(ctx context.Context, pool *pgxpool.Pool, path string, interval time.Duration, logger *slog.Logger) {
	if strings.TrimSpace(path) == "" {
		return // enrichment not configured: nothing to do
	}
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	timer := time.NewTimer(45 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := ReconcileCVEEnrichment(ctx, pool, path, logger); err != nil {
			logger.Warn("cve enrichment reconcile failed", slog.String("err", err.Error()))
		}
		timer.Reset(interval)
	}
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
