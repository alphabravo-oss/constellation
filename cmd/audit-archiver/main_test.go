package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

func TestAuditArchiveHeartbeatSnapshotIsBounded(t *testing.T) {
	state := &auditArchiveHeartbeatState{
		Bucket:        "sensitive-audit-bucket",
		Prefix:        "constellation/audit",
		Window:        24 * time.Hour,
		DryRun:        true,
		SignMode:      string(backup.SignModeStaticKey),
		Stage:         "dry-run",
		RecordCount:   3,
		ArchiveKey:    "constellation/audit/window.jsonl.gz",
		ManifestKey:   "constellation/audit/window.manifest.json",
		Success:       true,
		LastErrorText: "previous failure",
	}
	got, ok := state.snapshot().(map[string]any)
	if !ok {
		t.Fatalf("snapshot type = %T", state.snapshot())
	}
	if got["bucket_configured"] != true || got["prefix"] != "constellation/audit" || got["record_count"] != int64(3) {
		t.Fatalf("snapshot = %+v", got)
	}
	if _, ok := got["bucket"]; ok {
		t.Fatalf("snapshot leaked bucket name: %+v", got)
	}
	if state.lastError() != "previous failure" {
		t.Fatalf("lastError = %q", state.lastError())
	}
}

func TestMakeArchiveKeys(t *testing.T) {
	start := time.Date(2026, 6, 12, 1, 2, 3, 0, time.UTC)
	end := start.Add(24 * time.Hour)

	keys := makeArchiveKeys("/constellation/audit/", start, end)
	wantBase := "constellation/audit/20260612T010203Z--20260613T010203Z"
	if keys.Archive != wantBase+".jsonl.gz" {
		t.Fatalf("archive key = %q", keys.Archive)
	}
	if keys.Manifest != wantBase+".manifest.json" {
		t.Fatalf("manifest key = %q", keys.Manifest)
	}
	if keys.Signature != wantBase+".manifest.json.sig" {
		t.Fatalf("signature key = %q", keys.Signature)
	}
	if keys.Cert != wantBase+".manifest.json.cert" {
		t.Fatalf("cert key = %q", keys.Cert)
	}
}

func TestSignArchiveManifestStaticKey(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "cosign.key")
	pub := filepath.Join(dir, "cosign.pub")
	if err := backup.GenerateEd25519Keypair(priv, pub); err != nil {
		t.Fatal(err)
	}

	manifest := archiveManifest{
		FormatVersion: archiveManifestVersion,
		WindowStart:   "2026-06-12T00:00:00Z",
		WindowEnd:     "2026-06-13T00:00:00Z",
		RecordCount:   2,
		ArchiveSHA256: "archive",
		JSONLSHA256:   "jsonl",
		SHA256:        "archive",
		ArchiveKey:    "audit/window.jsonl.gz",
		ManifestKey:   "audit/window.manifest.json",
		SignatureKey:  "audit/window.manifest.json.sig",
		SignMode:      backup.SignModeStaticKey,
		CreatedAt:     "2026-06-12T00:01:00Z",
	}
	manifestBytes, sig, cert, err := signArchiveManifest(manifest, backup.SignerOptions{
		Mode:    backup.SignModeStaticKey,
		KeyPath: priv,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) == 0 {
		t.Fatal("signature was empty")
	}
	if len(cert) != 0 {
		t.Fatalf("static-key cert length = %d, want 0", len(cert))
	}
	if _, err := backup.Verify(manifestBytes, sig, nil, backup.VerifierOptions{
		Mode:    backup.SignModeStaticKey,
		KeyPath: pub,
	}); err != nil {
		t.Fatalf("signature verify: %v", err)
	}

	var signed archiveManifest
	if err := json.Unmarshal(manifestBytes, &signed); err != nil {
		t.Fatal(err)
	}
	if signed.SignerIdentity == "" {
		t.Fatal("signed manifest missing signer identity")
	}
	if signed.SignMode != backup.SignModeStaticKey {
		t.Fatalf("sign mode = %q", signed.SignMode)
	}
}

func TestUploadArchive(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "archive.jsonl.gz")
	archiveBody := []byte("compressed-jsonl")
	if err := os.WriteFile(archivePath, archiveBody, 0o644); err != nil {
		t.Fatal(err)
	}
	keys := archiveKeys{
		Archive:   "audit/window.jsonl.gz",
		Manifest:  "audit/window.manifest.json",
		Signature: "audit/window.manifest.json.sig",
		Cert:      "audit/window.manifest.json.cert",
	}
	manifest := []byte(`{"ok":true}`)
	sig := []byte("sig")
	cert := []byte("cert")
	uploader := &fakeUploader{}

	err := uploadArchive(context.Background(), uploader, "bucket-a", keys, archivePath, manifest, sig, cert, archiveManifest{
		WindowStart:   "2026-06-12T00:00:00Z",
		WindowEnd:     "2026-06-13T00:00:00Z",
		RecordCount:   3,
		ArchiveSHA256: "archive-sha",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(uploader.puts) != 4 {
		t.Fatalf("puts = %d, want 4", len(uploader.puts))
	}
	if uploader.puts[0].key != keys.Archive {
		t.Fatalf("first key = %q", uploader.puts[0].key)
	}
	if uploader.puts[0].contentEncoding != "gzip" {
		t.Fatalf("archive content encoding = %q", uploader.puts[0].contentEncoding)
	}
	sum := sha256.Sum256(archiveBody)
	wantChecksum := base64.StdEncoding.EncodeToString(sum[:])
	if uploader.puts[0].checksumSHA256 != wantChecksum {
		t.Fatalf("checksum = %q, want %q", uploader.puts[0].checksumSHA256, wantChecksum)
	}
	if string(uploader.puts[1].body) != string(manifest) {
		t.Fatalf("manifest body = %q", string(uploader.puts[1].body))
	}
	if string(uploader.puts[2].body) != string(sig) {
		t.Fatalf("signature body = %q", string(uploader.puts[2].body))
	}
	if string(uploader.puts[3].body) != string(cert) {
		t.Fatalf("cert body = %q", string(uploader.puts[3].body))
	}
}

type fakeUploader struct {
	puts []putCall
}

type putCall struct {
	bucket          string
	key             string
	contentType     string
	contentEncoding string
	checksumSHA256  string
	body            []byte
}

func (f *fakeUploader) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	body, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	f.puts = append(f.puts, putCall{
		bucket:          aws.ToString(input.Bucket),
		key:             aws.ToString(input.Key),
		contentType:     aws.ToString(input.ContentType),
		contentEncoding: aws.ToString(input.ContentEncoding),
		checksumSHA256:  aws.ToString(input.ChecksumSHA256),
		body:            body,
	})
	return &s3.PutObjectOutput{}, nil
}
