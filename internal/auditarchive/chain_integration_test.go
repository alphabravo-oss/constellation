//go:build integration

package auditarchive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOfflineChainProof(t *testing.T) {
	t.Parallel()
	pool, c, objects := fixture(t)
	var segments []Manifest
	for range 3 {
		appendEvent(t, pool, time.Now())
		appendEvent(t, pool, time.Now().Add(-24*time.Hour))
		segments = append(segments, runBatch(t, pool, objects, c))
	}
	pool.Close()
	head := segments[2]
	sum := sha256.Sum256(objects.data[head.ManifestKey])
	digest := hex.EncodeToString(sum[:])
	for _, scenario := range []string{"complete", "missing-middle", "truncated-head", "wrong-digest", "mixed-stream", "changed-link", "missing-genesis", "key-mismatch", "cycle", "corrupt-data", "path-escape", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for key, raw := range objects.data {
				path := filepath.Join(dir, key)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			key, trusted := head.ManifestKey, digest
			ctx := t.Context()
			m := segments[1]
			resign := false
			switch scenario {
			case "missing-middle":
				if err := os.Remove(filepath.Join(dir, m.ManifestKey)); err != nil {
					t.Fatal(err)
				}
			case "truncated-head":
				key = m.ManifestKey
			case "wrong-digest":
				trusted = "bad"
			case "mixed-stream":
				m.Stream = "another-stream"
				resign = true
			case "changed-link":
				// Individually valid segment, but skips a signed predecessor.
				m.PreviousManifest = ""
				resign = true
			case "missing-genesis":
				if err := os.Remove(filepath.Join(dir, segments[0].ArchiveKey)); err != nil {
					t.Fatal(err)
				}
			case "key-mismatch":
				m.ManifestKey = "wrong-key"
				resign = true
			case "cycle":
				m.PreviousManifest = head.ManifestKey
				resign = true
			case "corrupt-data":
				if err := os.WriteFile(filepath.Join(dir, m.ArchiveKey), []byte("corrupt"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "path-escape":
				m.PreviousManifest = "../outside.manifest.json"
				resign = true
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if resign {
				raw, sig, _, err := signArchiveManifest(ctx, m, c.Signer)
				if err != nil {
					t.Fatal(err)
				}
				for name, body := range map[string][]byte{segments[1].ManifestKey: raw, segments[1].SignatureKey: sig} {
					if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			proof, err := VerifyChain(ctx, dir, key, trusted, c.Verifier)
			if scenario == "complete" {
				if err != nil || proof.Segments != 3 || proof.Records != 6 || proof.LastID != head.LastID || proof.LastChain != head.LastChain || proof.HeadSHA256 != digest {
					t.Fatalf("proof=%+v err=%v", proof, err)
				}
			} else if err == nil || proof != (ChainProof{}) {
				t.Fatalf("accepted %s: proof=%+v err=%v", scenario, proof, err)
			}
		})
	}
}
