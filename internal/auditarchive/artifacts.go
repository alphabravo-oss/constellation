package auditarchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/alphabravocompany/constellation/internal/securefiles"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

const archiveManifestVersion = 2

type archiveKeys struct {
	Archive   string
	Manifest  string
	Signature string
	Cert      string
}

type Manifest struct {
	Stream           string            `json:"stream"`
	FirstID          int64             `json:"first_id"`
	LastID           int64             `json:"last_id"`
	FirstPrevHash    string            `json:"first_prev_hash"`
	PreviousManifest string            `json:"previous_manifest,omitempty"`
	FormatVersion    int               `json:"format_version"`
	WindowStart      string            `json:"window_start"`
	WindowEnd        string            `json:"window_end"`
	RecordCount      int64             `json:"record_count"`
	ArchiveSHA256    string            `json:"archive_sha256"`
	JSONLSHA256      string            `json:"jsonl_sha256"`
	SHA256           string            `json:"sha256"`
	FirstChain       string            `json:"first_chain"`
	LastChain        string            `json:"last_chain"`
	ArchiveKey       string            `json:"archive_key"`
	ManifestKey      string            `json:"manifest_key"`
	SignatureKey     string            `json:"signature_key,omitempty"`
	CertificateKey   string            `json:"certificate_key,omitempty"`
	SignMode         backup.SignMode   `json:"sign_mode"`
	SignerIdentity   string            `json:"signer_identity,omitempty"`
	CreatedAt        string            `json:"created_at"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

func makeArchiveKeys(prefix string, first, last int64, attempt string) archiveKeys {
	base := fmt.Sprintf("%020d--%020d--%s", first, last, attempt)
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix != "" {
		base = prefix + "/" + base
	}
	archive, manifest := base+".jsonl.gz", base+".manifest.json"
	return archiveKeys{Archive: archive, Manifest: manifest, Signature: manifest + ".sig", Cert: manifest + ".cert"}
}

func signArchiveManifest(ctx context.Context, manifest Manifest, opts backup.SignerOptions) ([]byte, []byte, []byte, error) {
	if opts.Mode == "" {
		opts.Mode = backup.SignModeNone
	}
	if opts.Mode == backup.SignModeNone {
		manifest.SignMode = backup.SignModeNone
		manifest.SignatureKey = ""
		manifest.CertificateKey = ""
		manifest.SignerIdentity = ""
		b, err := json.MarshalIndent(manifest, "", "  ")
		return b, nil, nil, err
	}

	manifest.SignMode = opts.Mode
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, nil, nil, err
	}
	sig, cert, identity, err := backup.Sign(ctx, manifestBytes, opts)
	if err != nil {
		return nil, nil, nil, err
	}
	if identity != "" {
		manifest.SignerIdentity = identity
		manifestBytes, err = json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return nil, nil, nil, err
		}
		sig, cert, _, err = backup.Sign(ctx, manifestBytes, opts)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	return manifestBytes, sig, cert, nil
}

func fileSHA256(path string) (string, error) {
	f, err := openArchiveFile(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeLocalArtifacts(outDir string, keys archiveKeys, archivePath string, manifest, sig, cert []byte) error {
	if outDir == "" {
		outDir = filepath.Join(os.TempDir(), "constellation-audit")
	}
	root, err := securefiles.OpenPrivateDir(outDir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	source, err := openArchiveFile(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()
	if err = securefiles.CopyFile(root, filepath.Base(keys.Archive), source, 0o600); err != nil {
		return err
	}
	for name, body := range map[string][]byte{keys.Manifest: manifest, keys.Signature: sig, keys.Cert: cert} {
		if len(body) == 0 {
			continue
		}
		if err = securefiles.WriteFile(root, filepath.Base(name), body, 0o600); err != nil {
			return err
		}
	}
	return nil
}

type objectUploader interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

func uploadArchive(ctx context.Context, client objectUploader, bucket string, keys archiveKeys, archivePath string, manifest, sig, cert []byte, m Manifest) error {
	if strings.TrimSpace(bucket) == "" {
		return errors.New("bucket required")
	}
	commonMeta := map[string]string{
		"window-start":   m.WindowStart,
		"window-end":     m.WindowEnd,
		"record-count":   fmt.Sprintf("%d", m.RecordCount),
		"archive-sha256": m.ArchiveSHA256,
	}
	if err := putFile(ctx, client, bucket, keys.Archive, archivePath, "application/x-ndjson", "gzip", commonMeta); err != nil {
		return err
	}
	if err := putBytes(ctx, client, bucket, keys.Manifest, manifest, "application/json", "", commonMeta); err != nil {
		return err
	}
	if len(sig) > 0 {
		if err := putBytes(ctx, client, bucket, keys.Signature, sig, "text/plain", "", commonMeta); err != nil {
			return err
		}
	}
	if len(cert) > 0 {
		if err := putBytes(ctx, client, bucket, keys.Cert, cert, "application/x-pem-file", "", commonMeta); err != nil {
			return err
		}
	}
	return nil
}

func putFile(ctx context.Context, client objectUploader, bucket, key, path, contentType, contentEncoding string, metadata map[string]string) error {
	f, err := openArchiveFile(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return putObject(ctx, client, bucket, key, f, contentType, contentEncoding, metadata)
}

func putBytes(ctx context.Context, client objectUploader, bucket, key string, body []byte, contentType, contentEncoding string, metadata map[string]string) error {
	return putObject(ctx, client, bucket, key, bytes.NewReader(body), contentType, contentEncoding, metadata)
}

func putObject(ctx context.Context, client objectUploader, bucket, key string, body io.Reader, contentType, contentEncoding string, metadata map[string]string) error {
	input := &s3.PutObjectInput{
		IfNoneMatch: aws.String("*"),
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        body,
		ContentType: aws.String(contentType),
		Metadata:    metadata,
	}
	if contentEncoding != "" {
		input.ContentEncoding = aws.String(contentEncoding)
	}
	sum, err := payloadSHA256(body)
	if err != nil {
		return fmt.Errorf("checksum %s: %w", key, err)
	}
	if sum != "" {
		input.ChecksumSHA256 = aws.String(sum)
	}
	_, err = client.PutObject(ctx, input)
	if err != nil {
		return fmt.Errorf("put s3://%s/%s: %w", bucket, key, err)
	}
	return nil
}

func payloadSHA256(r io.Reader) (string, error) {
	seeker, ok := r.(io.ReadSeeker)
	if !ok {
		return "", nil
	}
	pos, err := seeker.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, seeker); err != nil {
		return "", err
	}
	if _, err := seeker.Seek(pos, io.SeekStart); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// openArchiveFile pins the source directory and refuses a leaf symlink escaping
// it; archive paths come from this job's private tempfile or explicit test input.
func openArchiveFile(path string) (*os.File, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.Open(filepath.Base(path))
}
