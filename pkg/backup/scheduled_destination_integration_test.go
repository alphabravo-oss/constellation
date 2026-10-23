//go:build integration

package backup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

func TestScheduledDestinationFailurePreservesBackupHistory(t *testing.T) {
	pool := openConfigTestPool(t)
	var org uuid.UUID
	if err := pool.QueryRow(t.Context(), `INSERT INTO orgs(name,display_name) VALUES('remote-failure','remote-failure') RETURNING id`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	old := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO backups(id,org_id,status,started_at) VALUES($1,$2,'succeeded',now()-interval '100 days')`, old, org); err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer endpoint.Close()
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	s := schedule{OrgID: org, OrgName: "remote-failure", CronExpr: "0 3 * * *", SignMode: "none", S3Bucket: "backups", S3Endpoint: endpoint.URL, RetentionMaxAge: 1}
	if _, err := pool.Exec(t.Context(), `INSERT INTO backup_schedules(org_id,s3_bucket,s3_endpoint,sign_mode,retention_max_age_days) VALUES($1,$2,$3,'none',1)`, org, s.S3Bucket, s.S3Endpoint); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadSchedules(t.Context(), pool)
	if err != nil || len(loaded) != 1 || loaded[0].S3Bucket != s.S3Bucket || loaded[0].S3Endpoint != s.S3Endpoint {
		t.Fatalf("destinations not loaded: %+v %v", loaded, err)
	}
	runScheduledBackup(t.Context(), pool, ScheduleExecutorConfig{BackupDir: t.TempDir()}, s, time.Now(), nil)
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM backups WHERE id=$1 AND status='succeeded'`, old).Scan(&count); err != nil || count != 1 {
		t.Fatalf("prior backup lost: %d %v", count, err)
	}
	var status, path string
	if err := pool.QueryRow(t.Context(), `SELECT status,COALESCE(local_path,'') FROM backups WHERE org_id=$1 AND id<>$2`, org, old).Scan(&status, &path); err != nil || status != "failed" || path == "" {
		t.Fatalf("failed export evidence: %s %s %v", status, path, err)
	}
	var scheduleStatus string
	if err := pool.QueryRow(t.Context(), `SELECT last_status FROM backup_schedules WHERE org_id=$1`, org).Scan(&scheduleStatus); err != nil || scheduleStatus != "failed" {
		t.Fatalf("schedule status %s %v", scheduleStatus, err)
	}
}

func TestRetentionPreservesRemoteReceiptsAndMinimum(t *testing.T) {
	pool := openConfigTestPool(t)
	var org uuid.UUID
	if err := pool.QueryRow(t.Context(), `INSERT INTO orgs(name,display_name) VALUES('retention-floor','retention-floor') RETURNING id`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO backups(org_id,status,started_at,s3_uri) VALUES($1,'succeeded',now()-interval '100 days','s3://backups/archive'),($1,'succeeded',now()-interval '50 days',NULL)`, org); err != nil {
		t.Fatal(err)
	}
	if count := applyRetention(context.Background(), pool, org, 0, 1, time.Now(), nil); count != 0 {
		t.Fatalf("pruned %d protected receipts", count)
	}
}

// Opt-in service qualification creates and removes only a unique test bucket.
// AWS credentials must already be provided through the standard SDK chain.
func TestScheduledBackupRealObjectStore(t *testing.T) {
	endpoint := os.Getenv("CONSTELLATION_TEST_BACKUP_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("set CONSTELLATION_TEST_BACKUP_S3_ENDPOINT for isolated real object-store qualification")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"))
	if err != nil {
		t.Fatal("object-store credentials unavailable")
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) { o.BaseEndpoint = aws.String(endpoint); o.UsePathStyle = true })
	bucket := "constellation-qa-" + uuid.NewString()
	if _, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal("create isolated qualification bucket failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		if _, err := client.DeleteBucket(cleanup, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
			t.Error("remove isolated qualification bucket failed")
		}
	})
	pool := openConfigTestPool(t)
	var org uuid.UUID
	if err = pool.QueryRow(ctx, `INSERT INTO orgs(name,display_name) VALUES('object-qualification','object-qualification') RETURNING id`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	private, public := filepath.Join(t.TempDir(), "private"), filepath.Join(t.TempDir(), "public")
	if err = GenerateEd25519Keypair(private, public); err != nil {
		t.Fatal(err)
	}
	runScheduledBackup(ctx, pool, ScheduleExecutorConfig{BackupDir: t.TempDir(), SignKeyPath: private}, schedule{OrgID: org, OrgName: "object-qualification", CronExpr: "0 3 * * *", SignMode: "static-key", S3Bucket: bucket, S3Prefix: "evidence/", S3Endpoint: endpoint}, time.Now(), nil)
	var status, uri, digest string
	if err = pool.QueryRow(ctx, `SELECT status,COALESCE(s3_uri,''),COALESCE(sha256,'') FROM backups WHERE org_id=$1`, org).Scan(&status, &uri, &digest); err != nil {
		t.Fatal(err)
	}
	if status != "succeeded" || len(digest) != 64 || !strings.HasPrefix(uri, "s3://"+bucket+"/") {
		t.Fatalf("remote backup not verified: status=%s", status)
	}
	key := strings.TrimPrefix(uri, "s3://"+bucket+"/")
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		if _, err := client.DeleteObject(cleanup, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}); err != nil {
			t.Error("remove qualification object failed")
		}
	})
	object, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatal("independent download failed")
	}
	defer object.Body.Close()
	verified, err := VerifyArchive(ctx, RestoreOptions{In: object.Body, Verify: VerifierOptions{KeyPath: public}})
	if err != nil || !verified.Verified || verified.Manifest.OrgName != "object-qualification" {
		t.Fatalf("remote signed artifact verification failed: %v", err)
	}
	t.Log("real object-store upload, exact read-back, and independent signature verification passed")
}

func TestScheduledFailureFinalizesAfterCancellation(t *testing.T) {
	pool := openConfigTestPool(t)
	var org uuid.UUID
	if err := pool.QueryRow(t.Context(), `INSERT INTO orgs(name,display_name) VALUES('cancel-backup','cancel-backup') RETURNING id`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO backups(id,org_id,status) VALUES($1,$2,'running');`, id, org); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	recordScheduledFailure(ctx, pool, schedule{OrgID: org, CronExpr: "0 3 * * *"}, id, time.Now(), "canceled", "", 0)
	var status string
	if err := pool.QueryRow(t.Context(), `SELECT status FROM backups WHERE id=$1`, id).Scan(&status); err != nil || status != "failed" {
		t.Fatalf("stranded receipt %s %v", status, err)
	}
}
