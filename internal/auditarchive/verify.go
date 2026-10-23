package auditarchive

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

// Verify needs only downloaded artifacts and operator-supplied trust. It checks
// the signed envelope, both checksums, every row hash and all chain boundaries.
// Compare FirstPrevHash/PreviousManifest to the preceding verified segment to
// establish continuity; a valid signature alone does not prove a complete set.
func Verify(ctx context.Context, path string, raw, sig, cert []byte, opts backup.VerifierOptions) (Manifest, error) {
	m, err := verifyManifest(ctx, raw, sig, cert, opts)
	if err != nil {
		return m, err
	}
	f, err := openArchiveFile(path)
	if err != nil {
		return m, err
	}
	defer func() { _ = f.Close() }()
	return m, verifyArchiveFile(ctx, f, m)
}

func verifyArchiveFile(ctx context.Context, f *os.File, m Manifest) error {
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() || stat.Size() > MaxArchiveBytes {
		return errors.New("invalid archive file size or type")
	}
	if err = verifyCompressedHash(f, m); err != nil {
		return err
	}
	if err = replay(ctx, f, m); err != nil {
		return err
	}
	return nil
}

func verifyManifest(ctx context.Context, raw, sig, cert []byte, opts backup.VerifierOptions) (Manifest, error) {
	var m Manifest
	if len(raw) > 1<<20 || len(sig) > 1<<20 || len(cert) > 1<<20 {
		return m, errors.New("archive metadata exceeds byte limit")
	}
	if opts.Mode != backup.SignModeStaticKey && opts.Mode != backup.SignModeKeyless {
		return m, errors.New("trusted signature mode required")
	}
	if opts.Mode == backup.SignModeKeyless && opts.Identity == "" {
		return m, errors.New("expected keyless identity required")
	}
	identity, err := backup.Verify(ctx, raw, sig, cert, opts)
	if err != nil {
		return m, err
	}
	if err = json.Unmarshal(raw, &m); err != nil {
		return m, err
	}
	if m.FormatVersion != archiveManifestVersion || m.SignMode != opts.Mode || m.SignerIdentity != identity || m.RecordCount < 1 || m.RecordCount > MaxBatch || m.FirstID < 1 || m.LastID < m.FirstID || m.Stream == "" || len(m.FirstPrevHash) != 64 {
		return m, errors.New("invalid signed archive manifest")
	}
	return m, nil
}

func verifyCompressedHash(f *os.File, m Manifest) error {
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if sum != m.ArchiveSHA256 || sum != m.SHA256 {
		return errors.New("archive checksum mismatch")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return nil
}

func replay(ctx context.Context, f *os.File, m Manifest) error {
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	h := sha256.New()
	bounded := &io.LimitedReader{R: gz, N: MaxArchiveBytes + 1}
	dec := json.NewDecoder(io.TeeReader(bounded, h))
	dec.DisallowUnknownFields()
	var count, lastID int64
	prev := m.FirstPrevHash
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		var r audit.Record
		err = dec.Decode(&r)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if err = verifyRowBoundary(r, m, count, lastID, prev); err != nil {
			return err
		}
		count++
		if count > m.RecordCount {
			return errors.New("archive has more records than declared")
		}
		lastID = r.ID
		prev = r.ChainHash
	}
	if bounded.N <= 0 {
		return errors.New("decompressed archive exceeds byte limit")
	}
	if count != m.RecordCount || lastID != m.LastID || prev != m.LastChain {
		return errors.New("last archive boundary or count mismatch")
	}
	if hex.EncodeToString(h.Sum(nil)) != m.JSONLSHA256 {
		return errors.New("JSONL checksum mismatch")
	}
	return nil
}

func verifyRemote(ctx context.Context, client ObjectStore, c Config, b *archiveBundle) error {
	// Compare downloaded metadata to what we signed; do not trust object metadata,
	// ETags, or a successful PUT response as proof of readable archived evidence.
	for key, want := range map[string][]byte{b.keys.Manifest: b.raw, b.keys.Signature: b.sig, b.keys.Cert: b.cert} {
		if len(want) == 0 {
			continue
		}
		var got bytes.Buffer
		if err := download(ctx, client, c.Bucket, key, &got, 1<<20); err != nil {
			return err
		}
		if !bytes.Equal(got.Bytes(), want) {
			return fmt.Errorf("archive read-back mismatch for %s", key)
		}
	}
	f, err := os.CreateTemp("", "constellation-audit-readback-*.gz")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close(); _ = os.Remove(f.Name()) }()
	if err = download(ctx, client, c.Bucket, b.keys.Archive, f, MaxArchiveBytes); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	_, err = Verify(ctx, f.Name(), b.raw, b.sig, b.cert, c.Verifier)
	return err
}

func download(ctx context.Context, client ObjectStore, bucket, key string, w io.Writer, limit int64) error {
	got, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return fmt.Errorf("archive read-back %s: %w", key, err)
	}
	if got == nil || got.Body == nil {
		return errors.New("archive read-back returned no body")
	}
	n, err := io.Copy(w, io.LimitReader(got.Body, limit+1))
	err = errors.Join(err, got.Body.Close())
	if err != nil {
		return err
	}
	if n > limit {
		return errors.New("archive read-back exceeds byte limit")
	}
	return nil
}

func verifyRowBoundary(r audit.Record, m Manifest, count, lastID int64, prev string) error {
	if r.ID <= lastID {
		return errors.New("archive IDs are not increasing")
	}
	if err := audit.VerifyRecord(r, prev); err != nil {
		return err
	}
	if count == 0 && (r.ID != m.FirstID || r.ChainHash != m.FirstChain) {
		return errors.New("first archive boundary mismatch")
	}
	return nil
}
