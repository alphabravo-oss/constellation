package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestScanEvidenceTargetOrgScope(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID, foreignOrgID := uuid.New(), uuid.New()
	ownedTargetID, foreignTargetID := uuid.New(), uuid.New()
	ownedEvidenceID, mismatchedEvidenceID := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{orgID, foreignOrgID} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, id, "scan-evidence-get-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, orgID, foreignOrgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO scan_targets (id, org_id, type, ref, source_type)
		VALUES ($1, $2, 'host', $3, 'host'), ($4, $5, 'host', $6, 'host')`,
		ownedTargetID, orgID, "owned-"+ownedTargetID.String(), foreignTargetID, foreignOrgID, "foreign-"+foreignTargetID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := upsertPackageScanEvidence(ctx, pool, orgID, scanTarget{ID: foreignTargetID}, "rejected-hash", scanEvidencePackagePayload{}, time.Now()); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("foreign target evidence write error = %v, want no rows", err)
	}
	var rejectedCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM scan_evidence WHERE org_id = $1 AND scan_target_id = $2`, orgID, foreignTargetID).Scan(&rejectedCount); err != nil {
		t.Fatal(err)
	}
	if rejectedCount != 0 {
		t.Fatalf("foreign target evidence write created %d rows", rejectedCount)
	}
	writtenID, err := upsertPackageScanEvidence(ctx, pool, orgID, scanTarget{ID: ownedTargetID, Type: "serverless", Ref: "spoofed"}, "written-hash", scanEvidencePackagePayload{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var targetType, targetRef string
	if err := pool.QueryRow(ctx, `SELECT target_type, target_ref FROM scan_evidence WHERE id = $1`, writtenID).Scan(&targetType, &targetRef); err != nil {
		t.Fatal(err)
	}
	if targetType != "host" || targetRef != "owned-"+ownedTargetID.String() {
		t.Fatalf("evidence metadata = %s/%s, want canonical host target", targetType, targetRef)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scan_evidence
		(id, org_id, scan_target_id, target_type, target_ref, source_type, evidence_type, inventory_hash, payload, observed_at)
		VALUES ($1, $3, $4, 'host', $5, 'host', 'package-inventory', 'owned-hash', '{"packages":[]}'::jsonb, NOW()),
		       ($2, $3, $6, 'host', $7, 'host', 'package-inventory', 'foreign-hash', '{"packages":[],"source":"foreign-marker"}'::jsonb, NOW())`,
		ownedEvidenceID, mismatchedEvidenceID, orgID, ownedTargetID, "owned-"+ownedTargetID.String(), foreignTargetID, "foreign-"+foreignTargetID.String()); err != nil {
		t.Fatal(err)
	}
	ownedLatest, err := latestPackageEvidenceID(ctx, pool, orgID, ownedTargetID, "owned-hash")
	if err != nil || ownedLatest == nil || *ownedLatest != ownedEvidenceID {
		t.Fatalf("owned latest evidence = %v, %v", ownedLatest, err)
	}
	foreignLatest, err := latestPackageEvidenceID(ctx, pool, orgID, foreignTargetID, "foreign-hash")
	if err != nil || foreignLatest != nil {
		t.Fatalf("foreign-linked latest evidence = %v, %v", foreignLatest, err)
	}
	rawToken, _, err := IssueScannerToken(ctx, pool, orgID, "evidence-get", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	handler := ScannerTokenMiddleware(pool)(http.HandlerFunc(NewScanEvidence(database).Get))
	for _, testCase := range []struct {
		name       string
		id         uuid.UUID
		wantStatus int
	}{
		{"owned target", ownedEvidenceID, http.StatusOK},
		{"foreign target link", mismatchedEvidenceID, http.StatusNotFound},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/scan-evidence/"+testCase.id.String(), nil)
			request.Header.Set("Authorization", "Bearer "+rawToken)
			route := chi.NewRouteContext()
			route.URLParams.Add("id", testCase.id.String())
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route))
			record := httptest.NewRecorder()
			handler.ServeHTTP(record, request)
			if record.Code != testCase.wantStatus || strings.Contains(record.Body.String(), "foreign-marker") {
				t.Fatalf("status=%d body=%s", record.Code, record.Body.String())
			}
			if testCase.wantStatus == http.StatusOK {
				var evidence struct {
					TargetID uuid.UUID `json:"target_id"`
				}
				if err := json.NewDecoder(record.Body).Decode(&evidence); err != nil {
					t.Fatal(err)
				}
				if evidence.TargetID != ownedTargetID {
					t.Fatalf("target=%s, want %s", evidence.TargetID, ownedTargetID)
				}
			}
		})
	}
}
