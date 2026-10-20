//go:build integration

package crypto_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/crypto"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

// Guide ch.06 proof: rows sealed under key A are re-sealed under key B by the
// rotation job, remain readable under both key sets during the overlap, and a
// row written after the rotation carries the new key_id.
func TestRotateKeysReSealsRowsAndKeepsThemReadable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pool := pgtest.Pool(t)
	secretA, keyA, _ := crypto.GenerateKey()
	secretB, keyB, _ := crypto.GenerateKey()
	encA, _ := crypto.NewEncryptor(secretA)

	var org uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs WHERE name='demo'`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	// Two registries under A, one git connector under A.
	ids := []uuid.UUID{uuid.New(), uuid.New()}
	for i, id := range ids {
		s, _ := encA.Encrypt([]byte(`{"username":"u","password":"p` + string(rune('0'+i)) + `"}`))
		if _, err := pool.Exec(ctx, `INSERT INTO registries (id, org_id, name, kind, endpoint, auth_kind, auth_secret, key_id, algorithm)
			VALUES ($1,$2,$3,'generic','https://reg.example','basic',$4,$5,$6)`, id, org, "rot-"+id.String()[:8], s.Ciphertext, s.KeyID, s.Algorithm); err != nil {
			t.Fatal(err)
		}
	}
	pat, _ := encA.Encrypt([]byte("ghp_secret"))
	if _, err := pool.Exec(ctx, `INSERT INTO git_connectors (org_id, provider, github_owner, github_repo, branch, default_file_path, committer_name, committer_email, enabled, pat_sealed, key_id, algorithm)
		VALUES ($1,'github','x','y','main','policies/','bot','bot@example.test',true,$2,$3,$4)
		ON CONFLICT (org_id) DO UPDATE SET pat_sealed=EXCLUDED.pat_sealed, key_id=EXCLUDED.key_id, algorithm=EXCLUDED.algorithm`,
		org, pat.Ciphertext, pat.KeyID, pat.Algorithm); err != nil {
		t.Fatal(err)
	}

	// Rotate: B current, A retained.
	encBA, _ := crypto.NewEncryptor(secretB + "\n" + secretA)
	dry, err := crypto.Rotate(ctx, pool, encBA, true, nil)
	if err != nil || dry.Rotated["registries"] != 2 || dry.Rotated["git_connectors"] != 1 {
		t.Fatalf("dry run: %+v %v", dry, err)
	}
	rep, err := crypto.Rotate(ctx, pool, encBA, false, nil)
	if err != nil || rep.Rotated["registries"] != 2 || rep.Rotated["git_connectors"] != 1 || len(rep.Failed) != 0 {
		t.Fatalf("rotate: %+v %v", rep, err)
	}
	again, _ := crypto.Rotate(ctx, pool, encBA, false, nil)
	if again.Rotated["registries"] != 0 || again.Skipped["registries"] != 2 {
		t.Fatalf("rotation is not idempotent: %+v", again)
	}

	// Every row now carries key B and opens under the B-only set; the retired
	// A-only set cannot open them.
	encB, _ := crypto.NewEncryptor(secretB)
	for i, id := range ids {
		var ct []byte
		var kid, alg string
		if err := pool.QueryRow(ctx, `SELECT auth_secret, key_id, algorithm FROM registries WHERE id=$1`, id).Scan(&ct, &kid, &alg); err != nil {
			t.Fatal(err)
		}
		if kid != keyB || alg != crypto.Algorithm {
			t.Fatalf("row %d key_id=%s alg=%s", i, kid, alg)
		}
		pt, err := encB.Decrypt(crypto.Sealed{KeyID: kid, Algorithm: alg, Ciphertext: ct})
		if err != nil || string(pt) != `{"username":"u","password":"p`+string(rune('0'+i))+`"}` {
			t.Fatalf("row %d under B: %q %v", i, pt, err)
		}
		if _, err := encA.Decrypt(crypto.Sealed{KeyID: kid, Algorithm: alg, Ciphertext: ct}); err == nil {
			t.Fatalf("row %d still opens under the retired key", i)
		}
	}
	// A row written after rotation under the new set, plus one legacy row still
	// under A, both read back through the overlap set by key_id.
	newRow, _ := encBA.Encrypt([]byte("fresh"))
	legacy, _ := encA.Encrypt([]byte("legacy"))
	if newRow.KeyID != keyB || legacy.KeyID != keyA {
		t.Fatalf("key ids: %s %s", newRow.KeyID, legacy.KeyID)
	}
	for _, s := range []crypto.Sealed{newRow, legacy} {
		if _, err := encBA.Decrypt(s); err != nil {
			t.Fatalf("overlap set must read %s: %v", s.KeyID, err)
		}
	}
}
