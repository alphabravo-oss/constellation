package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestImageAcceptances_ReviewedScope(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	org, cluster, asset, user := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	digest := "sha256:" + uuid.NewString()
	for _, step := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Scope test')`, []any{org, "acceptance-scope-" + org.String()}},
		{`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'scope')`, []any{cluster, org}},
		{`INSERT INTO users(id,org_id,email,display_name) VALUES($1,$2,$3,'Reviewer')`, []any{user, org, user.String() + "@example.com"}},
		{`INSERT INTO assets(id,org_id,cluster_id,kind,name,digest) VALUES($1,$2,$3,'image','scope-image',$4)`, []any{asset, org, cluster, digest}},
		{`INSERT INTO images(asset_id,registry,repository,tag,digest) VALUES($1,'registry','scope','latest',$2)`, []any{asset, digest}},
	} {
		if _, err := pool.Exec(ctx, step.sql, step.args...); err != nil {
			t.Fatal(err)
		}
	}
	defer pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org)
	h := NewImageAcceptances(d, nil)
	expiry := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	request := func(wantedOrg uuid.UUID, expected, wantedCluster, acceptance string, revoke bool) *httptest.ResponseRecorder {
		t.Helper()
		body := map[string]string{"expected_image_digest": expected, "cluster_id": wantedCluster}
		if !revoke {
			body["rationale"] = "Reviewed scoped image risk"
			body["accepted_until"] = expiry
		}
		data, _ := json.Marshal(body)
		r := acceptanceRequest(t.Context(), "POST", "/", asset, acceptance, user, wantedOrg, string(data))
		w := httptest.NewRecorder()
		if revoke {
			h.Revoke(w, r)
		} else {
			h.Create(w, r)
		}
		return w
	}
	for _, tc := range []struct {
		name, digest, cluster string
		org                   uuid.UUID
		status                int
	}{
		{"stale digest", "sha256:other", cluster.String(), org, 409},
		{"wrong cluster", digest, uuid.NewString(), org, 409},
		{"malformed cluster", digest, "bad", org, 400},
		{"missing cluster", digest, "", org, 400},
		{"missing digest", "", cluster.String(), org, 400},
		{"foreign organization", digest, cluster.String(), uuid.New(), 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(tc.org, tc.digest, tc.cluster, "", false)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
		})
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM image_acceptances WHERE org_id=$1`, org).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected create mutated state: %d %v", count, err)
	}
	w := request(org, digest, cluster.String(), "", false)
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		ID, AssetID, ClusterID uuid.UUID
		ImageDigest            string `json:"image_digest"`
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for key, target := range map[string]any{"id": &created.ID, "asset_id": &created.AssetID, "cluster_id": &created.ClusterID, "image_digest": &created.ImageDigest} {
		if err := json.Unmarshal(raw[key], target); err != nil {
			t.Fatal(err)
		}
	}
	if created.ID == uuid.Nil || created.AssetID != asset || created.ClusterID != cluster || created.ImageDigest != digest {
		t.Fatalf("wrong confirmed identity: %+v", created)
	}
	for _, tc := range []struct {
		name, digest, cluster string
		org                   uuid.UUID
		status                int
	}{
		{"revoke stale digest", "sha256:other", cluster.String(), org, 409},
		{"revoke wrong cluster", digest, uuid.NewString(), org, 409},
		{"revoke partial scope", "", cluster.String(), org, 400},
		{"revoke foreign org", digest, cluster.String(), uuid.New(), 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(tc.org, tc.digest, tc.cluster, created.ID.String(), true)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
		})
	}
	var revoked *time.Time
	if err := pool.QueryRow(ctx, `SELECT revoked_at FROM image_acceptances WHERE id=$1`, created.ID).Scan(&revoked); err != nil || revoked != nil {
		t.Fatalf("rejected revoke mutated state: %v %v", revoked, err)
	}
	w = request(org, digest, cluster.String(), created.ID.String(), true)
	if w.Code != 200 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	var result struct {
		Status      string               `json:"status"`
		AssetID     uuid.UUID            `json:"asset_id"`
		ClusterID   uuid.UUID            `json:"cluster_id"`
		ImageDigest string               `json:"image_digest"`
		Items       []imageAcceptanceDTO `json:"image_acceptances"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "revoked" || result.AssetID != asset || result.ClusterID != cluster || result.ImageDigest != digest || len(result.Items) != 1 || result.Items[0].Status != "revoked" {
		t.Fatalf("wrong revoke confirmation: %+v", result)
	}

	t.Run("identity locked through write", func(t *testing.T) {
		ctx := t.Context()
		r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/", nil)
		tx, gotDigest, gotCluster, ok := h.lockReviewedImage(httptest.NewRecorder(), r, org, asset, imageAcceptanceScope{ExpectedImageDigest: digest, ClusterID: cluster.String()})
		if !ok {
			t.Fatal("review lock failed")
		}
		defer tx.Rollback(ctx)
		if gotDigest != digest || gotCluster == nil || *gotCluster != cluster {
			t.Fatal("wrong locked identity")
		}
		for _, sql := range []string{`UPDATE images SET digest='sha256:changed' WHERE asset_id=$1`, `UPDATE assets SET cluster_id=NULL WHERE id=$1`} {
			other, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = other.Exec(ctx, `SET LOCAL lock_timeout='50ms'`); err != nil {
				t.Fatal(err)
			}
			_, err = other.Exec(ctx, sql, asset)
			_ = other.Rollback(ctx)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
				t.Fatalf("identity update was not blocked: %v", err)
			}
		}
	})
}
