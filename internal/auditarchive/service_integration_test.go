//go:build integration

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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

type memoryStore struct {
	mu                        sync.Mutex
	data                      map[string][]byte
	failPut, failGet, corrupt string
	beforePut                 func()
}

func (s *memoryStore) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if s.beforePut != nil {
		s.beforePut()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := aws.ToString(in.Key)
	if aws.ToString(in.IfNoneMatch) != "*" {
		return nil, errors.New("missing conditional create")
	}
	if s.failPut != "" && strings.HasSuffix(key, s.failPut) {
		return nil, errors.New("injected upload failure")
	}
	if s.data == nil {
		s.data = map[string][]byte{}
	}
	if _, ok := s.data[key]; ok {
		return nil, errors.New("object overwrite")
	}
	b, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	s.data[key] = b
	return &s3.PutObjectOutput{}, nil
}
func (s *memoryStore) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := aws.ToString(in.Key)
	if s.failGet != "" && strings.HasSuffix(key, s.failGet) {
		return nil, errors.New("injected download failure")
	}
	b, ok := s.data[key]
	if !ok {
		return nil, errors.New("missing object")
	}
	if s.corrupt != "" && strings.HasSuffix(key, s.corrupt) {
		b = []byte("corrupt")
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(b))}, nil
}
func fixture(t *testing.T) (*pgxpool.Pool, Config, *memoryStore) {
	t.Helper()
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "key"), filepath.Join(dir, "pub")
	if err := backup.GenerateEd25519Keypair(priv, pub); err != nil {
		t.Fatal(err)
	}
	c := Config{Bucket: "archive-test", Prefix: "audit", BatchSize: 2, OutDir: filepath.Join(dir, "out"), Signer: backup.SignerOptions{Mode: backup.SignModeStaticKey, KeyPath: priv}, Verifier: backup.VerifierOptions{Mode: backup.SignModeStaticKey, KeyPath: pub}}
	return pgtest.Pool(t), c, &memoryStore{}
}
func appendEvent(t *testing.T, pool *pgxpool.Pool, at time.Time) int64 {
	t.Helper()
	id, _, err := audit.New(pool).Log(t.Context(), audit.Event{Action: "test.archive", ActorIP: net.ParseIP("2001:db8::1"), After: map[string]any{"nested": map[string]any{"number": 42, "string": "escaped\nvalue"}}, At: at})
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func runBatch(t *testing.T, pool *pgxpool.Pool, s *memoryStore, c Config) Manifest {
	t.Helper()
	m, err := Run(t.Context(), pool, s, c)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func assertProgress(t *testing.T, pool *pgxpool.Pool, c Config, want int64) {
	t.Helper()
	var id int64
	err := pool.QueryRow(t.Context(), `SELECT COALESCE((SELECT last_id FROM audit_archive_progress WHERE stream=$1),0)`, c.stream()).Scan(&id)
	if err != nil || id != want {
		t.Fatalf("checkpoint=%d want=%d err=%v", id, want, err)
	}
}
func offlineVerify(t *testing.T, s *memoryStore, m Manifest, c Config) Manifest {
	t.Helper()
	path := filepath.Join(t.TempDir(), "archive.gz")
	if err := os.WriteFile(path, s.data[m.ArchiveKey], 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Verify(t.Context(), path, s.data[m.ManifestKey], s.data[m.SignatureKey], nil, c.Verifier)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestCatchUpBackdatedEventsSequenceGapsAndOfflineReplay(t *testing.T) {
	t.Parallel()
	pool, c, s := fixture(t)
	ids := []int64{appendEvent(t, pool, time.Now().Add(-30*24*time.Hour))}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = audit.New(pool).LogInTx(t.Context(), tx, audit.Event{Action: "rolled-back"}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		ids = append(ids, appendEvent(t, pool, time.Now().Add(time.Duration(-i)*time.Hour)))
	}
	var prior Manifest
	total := int64(0)
	for batch := range 3 {
		m := runBatch(t, pool, s, c)
		if batch == 0 && (m.FirstID != ids[0] || m.LastID != ids[1] || m.FirstPrevHash != audit.GenesisHash || m.PreviousManifest != "") {
			t.Fatalf("first segment: %+v", m)
		}
		if batch > 0 && (m.FirstPrevHash != prior.LastChain || m.PreviousManifest != prior.ManifestKey || m.FirstID <= prior.LastID) {
			t.Fatalf("discontinuous archive: %+v", m)
		}
		if m.RecordCount > 2 {
			t.Fatal("batch limit ignored")
		}
		total += m.RecordCount
		prior = m
	}
	if total != 5 {
		t.Fatalf("count=%d", total)
	}
	assertProgress(t, pool, c, ids[4])
	if m := runBatch(t, pool, s, c); m.RecordCount != 0 {
		t.Fatal("re-exported committed batch")
	}
	// New backdated event must not be filtered out by the last run's wall clock.
	late := appendEvent(t, pool, time.Now().Add(-365*24*time.Hour))
	m := runBatch(t, pool, s, c)
	if m.FirstID != late || m.RecordCount != 1 || m.FirstPrevHash != prior.LastChain {
		t.Fatalf("backdated event lost: %+v", m)
	}
	pool.Close() // verification must need neither the source connection nor its schema
	for key, raw := range s.data {
		if !strings.HasSuffix(key, ".manifest.json") {
			continue
		}
		var manifest Manifest
		if err = json.Unmarshal(raw, &manifest); err != nil {
			t.Fatal(err)
		}
		offlineVerify(t, s, manifest, c)
	}
}

func TestArchiveFailuresNeverAdvanceAndRetryUsesFreshKeys(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"put-data", "put-manifest", "put-signature", "get-data", "get-manifest", "get-signature", "corrupt-data", "corrupt-manifest", "corrupt-signature", "commit"} {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			pool, c, s := fixture(t)
			appendEvent(t, pool, time.Now())
			first := runBatch(t, pool, s, c)
			last := appendEvent(t, pool, time.Now())
			switch failure {
			case "put-data":
				s.failPut = ".jsonl.gz"
			case "put-manifest":
				s.failPut = ".manifest.json"
			case "put-signature":
				s.failPut = ".sig"
			case "get-data":
				s.failGet = ".jsonl.gz"
			case "get-manifest":
				s.failGet = ".manifest.json"
			case "get-signature":
				s.failGet = ".sig"
			case "corrupt-data":
				s.corrupt = ".jsonl.gz"
			case "corrupt-manifest":
				s.corrupt = ".manifest.json"
			case "corrupt-signature":
				s.corrupt = ".sig"
			case "commit":
				_, err := pool.Exec(t.Context(), `CREATE FUNCTION fail_archive_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected commit failure'; END $$;
    CREATE CONSTRAINT TRIGGER fail_commit AFTER UPDATE ON audit_archive_progress DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_archive_commit()`)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Run(t.Context(), pool, s, c); err == nil {
				t.Fatal("accepted injected failure")
			}
			assertProgress(t, pool, c, first.LastID)
			old := map[string][]byte{}
			for key, b := range s.data {
				old[key] = append([]byte(nil), b...)
			}
			s.failPut = ""
			s.failGet = ""
			s.corrupt = ""
			if failure == "commit" {
				if _, err := pool.Exec(t.Context(), `DROP TRIGGER fail_commit ON audit_archive_progress`); err != nil {
					t.Fatal(err)
				}
			}
			m := runBatch(t, pool, s, c)
			if m.LastID != last || m.FirstPrevHash != first.LastChain {
				t.Fatal("retry skipped evidence")
			}
			for key, b := range old {
				if !bytes.Equal(s.data[key], b) {
					t.Fatalf("retry overwrote %s", key)
				}
			}
			assertProgress(t, pool, c, last)
			offlineVerify(t, s, m, c)
		})
	}
}

func TestConcurrentWorkersSerializeWithoutBlockingAuditWriters(t *testing.T) {
	t.Parallel()
	pool, c, s := fixture(t)
	c.BatchSize = 1
	appendEvent(t, pool, time.Now())
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.beforePut = func() { once.Do(func() { close(entered); <-release }) }
	errs := make(chan error, 2)
	go func() { _, err := Run(t.Context(), pool, s, c); errs <- err }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("first worker did not upload")
	}
	// An archive transaction holds only the progress row, not the audit writer lock.
	last := appendEvent(t, pool, time.Now())
	go func() { _, err := Run(t.Context(), pool, s, c); errs <- err }()
	close(release)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	assertProgress(t, pool, c, last)
	if len(s.data) != 6 {
		t.Fatalf("wanted two disjoint 3-object batches, got %d objects", len(s.data))
	}
}

func TestDryRunAndDestinationIsolation(t *testing.T) {
	t.Parallel()
	pool, c, s := fixture(t)
	firstID := appendEvent(t, pool, time.Now())
	dry := c
	dry.DryRun = true
	dry.Signer = backup.SignerOptions{Mode: backup.SignModeNone}
	dry.Verifier = backup.VerifierOptions{}
	if m := runBatch(t, pool, nil, dry); m.RecordCount != 1 {
		t.Fatal("missing dry-run output")
	}
	assertProgress(t, pool, c, 0)
	var rows int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_archive_progress`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("dry-run persisted cursor: %d %v", rows, err)
	}
	first := runBatch(t, pool, s, c)
	last := appendEvent(t, pool, time.Now())
	dry = c
	dry.DryRun = true
	m := runBatch(t, pool, nil, dry)
	if m.FirstID != last {
		t.Fatal("dry-run ignored checkpoint")
	}
	assertProgress(t, pool, c, firstID)
	for _, other := range []Config{func() Config { x := c; x.Bucket = "other-bucket"; return x }(), func() Config { x := c; x.Prefix = "other-prefix"; return x }(), func() Config { x := c; x.Endpoint = "https://other.example"; return x }()} {
		m := runBatch(t, pool, &memoryStore{}, other)
		if m.FirstID != firstID || m.FirstPrevHash != audit.GenesisHash {
			t.Fatal("destination skipped catch-up")
		}
	}
	if first.LastID != firstID {
		t.Fatal("unexpected initial progress")
	}
}

func TestMissingOrCorruptChainAndCheckpointFailClosed(t *testing.T) {
	t.Parallel()
	for _, damage := range []string{"missing-row", "changed-row", "checkpoint-hash", "checkpoint-missing"} {
		t.Run(damage, func(t *testing.T) {
			t.Parallel()
			pool, c, s := fixture(t)
			appendEvent(t, pool, time.Now())
			first := runBatch(t, pool, s, c)
			middle := appendEvent(t, pool, time.Now())
			appendEvent(t, pool, time.Now())
			var query string
			switch damage {
			case "missing-row":
				query = fmt.Sprintf(`ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_delete; DELETE FROM audit_events WHERE id=%d; ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_delete`, middle)
			case "changed-row":
				query = fmt.Sprintf(`ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update; UPDATE audit_events SET action='tampered' WHERE id=%d; ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update`, middle)
			case "checkpoint-hash":
				query = `UPDATE audit_archive_progress SET last_hash=repeat('f',64)`
			case "checkpoint-missing":
				query = fmt.Sprintf(`ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_delete; DELETE FROM audit_events WHERE id=%d; ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_delete`, first.LastID)
			}
			if _, err := pool.Exec(t.Context(), query); err != nil {
				t.Fatal(err)
			}
			if _, err := Run(t.Context(), pool, s, c); err == nil {
				t.Fatal("archived damaged evidence")
			}
			if len(s.data) != 3 {
				t.Fatal("uploaded corrupt batch")
			}
			assertProgress(t, pool, c, first.LastID)
		})
	}
}

func TestAuditLedgerRejectsAllDestructiveStatements(t *testing.T) {
	t.Parallel()
	pool, _, _ := fixture(t)
	id := appendEvent(t, pool, time.Now())
	for _, query := range []string{`UPDATE audit_events SET action='tampered'`, `DELETE FROM audit_events`, `TRUNCATE audit_events`, `TRUNCATE audit_events RESTART IDENTITY CASCADE`} {
		if _, err := pool.Exec(t.Context(), query); err == nil {
			t.Fatalf("allowed %s", query)
		}
	}
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE id=$1`, id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("lost evidence %d %v", count, err)
	}
	if broken, err := audit.VerifyChain(t.Context(), pool); err != nil || broken != nil {
		t.Fatalf("chain changed: %v %v", broken, err)
	}
}

func TestWrongSigningKeyAndCancellationLeaveNoCheckpoint(t *testing.T) {
	t.Parallel()
	pool, c, s := fixture(t)
	appendEvent(t, pool, time.Now())
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "other-key"), filepath.Join(dir, "other-pub")
	if err := backup.GenerateEd25519Keypair(priv, pub); err != nil {
		t.Fatal(err)
	}
	wrong := c
	wrong.Verifier.KeyPath = pub
	if _, err := Run(t.Context(), pool, s, wrong); err == nil {
		t.Fatal("accepted wrong verification key")
	}
	if len(s.data) != 0 {
		t.Fatal("uploaded before verifying signer")
	}
	assertProgress(t, pool, c, 0)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s.beforePut = cancel
	if _, err := Run(ctx, pool, s, c); err == nil {
		t.Fatal("accepted canceled archive")
	}
	assertProgress(t, pool, c, 0)
	s.beforePut = nil
	runBatch(t, pool, s, c)
}

func TestOfflineVerifierRejectsTamperedEnvelopeAndPayload(t *testing.T) {
	t.Parallel()
	pool, c, s := fixture(t)
	c.BatchSize = 3
	for range 3 {
		appendEvent(t, pool, time.Now())
	}
	m := runBatch(t, pool, s, c)
	for _, mutation := range []string{"signature", "wrong-mode", "format", "count", "first-id", "last-id", "first-hash", "last-hash", "prev-hash", "compressed-checksum", "jsonl-checksum", "changed-row", "missing-row", "duplicate-row", "reversed-rows"} {
		t.Run(mutation, func(t *testing.T) {
			t.Parallel()
			copyManifest := m
			data := append([]byte(nil), s.data[m.ArchiveKey]...)
			switch mutation {
			case "wrong-mode":
				copyManifest.SignMode = backup.SignModeKeyless
			case "format":
				copyManifest.FormatVersion = 1
			case "count":
				copyManifest.RecordCount++
			case "first-id":
				copyManifest.FirstID++
			case "last-id":
				copyManifest.LastID++
			case "first-hash":
				copyManifest.FirstChain = strings.Repeat("f", 64)
			case "last-hash":
				copyManifest.LastChain = strings.Repeat("f", 64)
			case "prev-hash":
				copyManifest.FirstPrevHash = strings.Repeat("f", 64)
			case "compressed-checksum":
				data[0] ^= 0xff
			case "jsonl-checksum":
				copyManifest.JSONLSHA256 = strings.Repeat("f", 64)
			case "changed-row", "missing-row", "duplicate-row", "reversed-rows":
				gz, err := gzip.NewReader(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				plain, err := io.ReadAll(gz)
				if err != nil {
					t.Fatal(err)
				}
				_ = gz.Close()
				lines := bytes.Split(bytes.TrimSpace(plain), []byte("\n"))
				switch mutation {
				case "changed-row":
					lines[1] = bytes.ReplaceAll(lines[1], []byte("test.archive"), []byte("evil.archive"))
				case "missing-row":
					lines = append(lines[:1], lines[2:]...)
					copyManifest.RecordCount--
				case "duplicate-row":
					lines[1] = lines[0]
				case "reversed-rows":
					lines[1], lines[2] = lines[2], lines[1]
				}
				plain = append(bytes.Join(lines, []byte("\n")), '\n')
				var buf bytes.Buffer
				writer := gzip.NewWriter(&buf)
				_, _ = writer.Write(plain)
				if err = writer.Close(); err != nil {
					t.Fatal(err)
				}
				data = buf.Bytes()
				sum := sha256.Sum256(data)
				copyManifest.ArchiveSHA256 = hex.EncodeToString(sum[:])
				copyManifest.SHA256 = copyManifest.ArchiveSHA256
				sum = sha256.Sum256(plain)
				copyManifest.JSONLSHA256 = hex.EncodeToString(sum[:])
			}
			// Re-sign altered manifests so payload replay, not merely the signature or
			// compressed checksum, must catch reordered/missing/modified rows.
			raw, err := json.Marshal(copyManifest)
			if err != nil {
				t.Fatal(err)
			}
			sig, _, _, err := backup.Sign(t.Context(), raw, c.Signer)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "signature" {
				sig[0] ^= 1
			}
			path := filepath.Join(t.TempDir(), "archive.gz")
			if err = os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err = Verify(t.Context(), path, raw, sig, nil, c.Verifier); err == nil {
				t.Fatalf("accepted %s", mutation)
			}
		})
	}
}

func TestS3SDKUploadAndReadBackPreserveCompressedBytes(t *testing.T) {
	t.Parallel()
	pool, c, _ := fixture(t)
	appendEvent(t, pool, time.Now())
	var mu sync.Mutex
	objects := map[string][]byte{}
	puts, gets := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			if r.Header.Get("If-None-Match") != "*" || r.Header.Get("X-Amz-Checksum-Sha256") == "" {
				http.Error(w, "conditional checksum required", http.StatusBadRequest)
				return
			}
			if _, ok := objects[r.URL.Path]; ok {
				http.Error(w, "already exists", http.StatusPreconditionFailed)
				return
			}
			b, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "body", http.StatusBadRequest)
				return
			}
			objects[r.URL.Path] = b
			puts++
		case http.MethodGet:
			b, ok := objects[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			gets++
			if strings.HasSuffix(r.URL.Path, ".jsonl.gz") {
				w.Header().Set("Content-Encoding", "gzip")
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			_, _ = w.Write(b)
		default:
			http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	c.Endpoint = server.URL
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), UsePathStyle: true,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "fixture", SecretAccessKey: "fixture"}, nil
		})})
	m, err := Run(t.Context(), pool, client, c)
	if err != nil {
		t.Fatal(err)
	}
	if m.RecordCount != 1 {
		t.Fatal("no SDK archive")
	}
	assertProgress(t, pool, c, m.LastID)
	mu.Lock()
	defer mu.Unlock()
	if puts != 3 || gets != 3 {
		t.Fatalf("PUT=%d GET=%d", puts, gets)
	}
}
