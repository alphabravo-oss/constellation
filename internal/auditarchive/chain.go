package auditarchive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

// ChainProof describes a complete genesis-to-head replay, not freshness beyond
// the independently trusted head. Numeric ID gaps from rollbacks are permitted.
type ChainProof struct {
	Stream       string `json:"stream"`
	HeadManifest string `json:"head_manifest"`
	HeadSHA256   string `json:"head_sha256"`
	LastID       int64  `json:"last_id"`
	LastChain    string `json:"last_chain"`
	Segments     int    `json:"segments"`
	Records      int64  `json:"records"`
}

// VerifyChain follows signed predecessor links using downloaded S3 keys relative
// to dir. The caller must obtain headKey and headSHA256 through an independent
// trusted channel; otherwise a truncated but correctly signed prefix could pass.
// No database, AWS client, source mutation, or archive restoration is involved.
func VerifyChain(ctx context.Context, dir, headKey, headSHA256 string, opts backup.VerifierOptions) (ChainProof, error) {
	var proof ChainProof
	digest, err := hex.DecodeString(headSHA256)
	if err != nil || len(digest) != sha256.Size {
		return proof, errors.New("trusted head SHA-256 required")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return proof, err
	}
	defer func() { _ = root.Close() }()
	key := headKey
	var newer Manifest
	// The deadline and this cap bound hostile predecessor graphs and memory use.
	seen := make(map[string]bool)
	for len(seen) < 100000 {
		if err = ctx.Err(); err != nil {
			return ChainProof{}, err
		}
		if seen[key] {
			return ChainProof{}, errors.New("archive predecessor cycle")
		}
		seen[key] = true
		m, rawHash, err := verifyChainSegment(ctx, root, key, opts)
		if err != nil {
			return ChainProof{}, fmt.Errorf("verify segment %q: %w", key, err)
		}
		if err = proof.include(m, newer, rawHash, hex.EncodeToString(digest)); err != nil {
			return ChainProof{}, err
		}
		if m.PreviousManifest == "" {
			if m.FirstPrevHash != audit.GenesisHash {
				return ChainProof{}, errors.New("archive chain does not start at genesis")
			}
			return proof, nil
		}
		newer, key = m, m.PreviousManifest
	}
	return ChainProof{}, errors.New("archive chain exceeds segment limit")
}

func (p *ChainProof) include(m, newer Manifest, rawHash, trusted string) error {
	if p.Segments == 0 {
		if rawHash != trusted {
			return errors.New("archive head differs from trusted digest")
		}
		*p = ChainProof{Stream: m.Stream, HeadManifest: m.ManifestKey, HeadSHA256: rawHash, LastID: m.LastID, LastChain: m.LastChain}
	} else if m.Stream != p.Stream || m.LastID >= newer.FirstID || m.LastChain != newer.FirstPrevHash {
		return errors.New("archive segment continuity mismatch")
	}
	p.Segments++
	p.Records += m.RecordCount
	return nil
}

func verifyChainSegment(ctx context.Context, root *os.Root, key string, opts backup.VerifierOptions) (Manifest, string, error) {
	var m Manifest
	raw, err := chainMetadata(root, key)
	if err != nil {
		return m, "", err
	}
	sig, err := chainMetadata(root, key+".sig")
	if err != nil {
		return m, "", err
	}
	var cert []byte
	if opts.Mode == backup.SignModeKeyless {
		cert, err = chainMetadata(root, key+".cert")
		if err != nil {
			return m, "", err
		}
	}
	m, err = verifyManifest(ctx, raw, sig, cert, opts)
	if err != nil {
		return m, "", err
	}
	if m.ManifestKey != key || !fs.ValidPath(m.ArchiveKey) {
		return m, "", errors.New("archive manifest key mismatch or invalid artifact key")
	}
	f, err := root.Open(m.ArchiveKey)
	if err != nil {
		return m, "", err
	}
	defer func() { _ = f.Close() }()
	if err = verifyArchiveFile(ctx, f, m); err != nil {
		return m, "", err
	}
	sum := sha256.Sum256(raw)
	return m, hex.EncodeToString(sum[:]), nil
}

func chainMetadata(root *os.Root, key string) ([]byte, error) {
	if !fs.ValidPath(key) {
		return nil, errors.New("invalid archive metadata key")
	}
	f, err := root.Open(key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("invalid archive metadata type or size")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if len(raw) > 1<<20 {
		return nil, errors.New("archive metadata exceeds byte limit")
	}
	return raw, err
}
