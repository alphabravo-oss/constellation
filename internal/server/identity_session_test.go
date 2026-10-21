//go:build integration

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
)

// Existing domain HTTP proofs use the same opaque, expiring session store as
// OIDC. Identity flow itself is proven with a real issuer and Playwright.
type testSessionIssuer struct{ pool *pgxpool.Pool }

func (s *testSessionIssuer) Issue(user, org uuid.UUID, email string, roles []string, epoch int64) (string, uuid.UUID, error) {
	ctx := context.Background()
	grants, err := loadRoleAssignments(ctx, db.NewFromPool(s.pool), user)
	if err != nil {
		return "", uuid.Nil, err
	}
	raw := "csi_" + base64.RawURLEncoding.EncodeToString(func() []byte { raw := make([]byte, 32); _, _ = rand.Read(raw); return raw }())
	sum := sha256.Sum256([]byte(raw))
	body, _ := json.Marshal(grants)
	_, err = s.pool.Exec(ctx, `INSERT INTO identity_sessions(token_hash,user_id,roles,session_epoch,kind,expires_at) VALUES($1,$2,$3,$4,'oidc',$5)`, fmt.Sprintf("%x", sum), user, body, epoch, time.Now().Add(5*time.Minute))
	return raw, uuid.New(), err
}
