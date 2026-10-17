package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// S3BackupURI uses the actual catalog identity, not only a wall-clock second.
func S3BackupURI(destination, organization string, id uuid.UUID, at time.Time) (string, error) {
	if id == uuid.Nil {
		return "", errors.New("backup identity is required")
	}
	return S3ArtifactURI(destination, ArtifactName(organization, id, at))
}

// S3ArtifactURI preserves an opaque object prefix, including spaces and repeated
// separators. It never treats object keys as local filesystem paths.
func S3ArtifactURI(destination, name string) (string, error) {
	if !strings.HasPrefix(destination, "s3://") || !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." {
		return "", errors.New("invalid backup S3 destination")
	}
	rest := strings.TrimPrefix(destination, "s3://")
	bucket, prefix, _ := strings.Cut(rest, "/")
	if len(bucket) < 3 || len(bucket) > 63 || !bucketEdge(rune(bucket[0])) || !bucketEdge(rune(bucket[len(bucket)-1])) {
		return "", errors.New("invalid backup S3 bucket")
	}
	for _, c := range bucket {
		if !bucketEdge(c) && c != '.' && c != '-' {
			return "", errors.New("invalid backup S3 bucket")
		}
	}
	for _, c := range destination + name {
		if c < 0x20 || c == 0x7f {
			return "", errors.New("invalid backup S3 destination")
		}
	}
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return "s3://" + bucket + "/" + prefix + name, nil
}
func bucketEdge(c rune) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }

type cliOperationError struct {
	stage string
	cause error
}

func (e *cliOperationError) Error() string { return e.stage + " failed" }
func (e *cliOperationError) Unwrap() error { return e.cause }

// UploadS3Artifact uploads the exact already-open regular artifact. Database
// credentials are not forwarded to AWS. Child diagnostics are never echoed;
// errors preserve their cause for cancellation/exit-status inspection.
func UploadS3Artifact(ctx context.Context, destination, endpoint string, file *os.File, size int64) error {
	if _, err := S3ArtifactURI(destination, "validation"); err != nil {
		return err
	}
	if err := ValidateS3Endpoint(endpoint); err != nil {
		return err
	}
	if file == nil || size < 0 {
		return errors.New("backup upload requires an open artifact")
	}
	info, err := file.Stat()
	if err != nil {
		return &cliOperationError{"backup artifact inspection", err}
	}
	if !info.Mode().IsRegular() || info.Size() != size {
		return errors.New("backup artifact differs from reviewed upload")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return &cliOperationError{"backup artifact rewind", err}
	}
	if _, err = exec.LookPath("aws"); err != nil {
		return &cliOperationError{"AWS CLI lookup", err}
	}
	args := []string{"s3", "cp", "-", destination, "--expected-size", strconv.FormatInt(size, 10), "--only-show-errors"}
	if endpoint != "" {
		args = append([]string{"--endpoint-url", endpoint}, args...)
	}
	cmd := exec.CommandContext(ctx, "aws", args...)
	cmd.Stdin = file
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = make([]string, 0, len(os.Environ()))
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if key != "DATABASE_URL" && !strings.HasPrefix(key, "PG") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	if err = cmd.Run(); err != nil {
		return &cliOperationError{"backup S3 upload", err}
	}
	offset, err := file.Seek(0, io.SeekCurrent)
	if err != nil || offset != size {
		return &cliOperationError{"backup S3 upload consumption", errors.Join(err, fmt.Errorf("incomplete input"))}
	}
	return nil
}

// CLIWorkspace owns only its newly-created private directory. Explicit caller
// output paths are never passed to this cleanup routine.
type CLIWorkspace struct {
	Path      string
	directory string
	keep      bool
	closed    bool
	identity  os.FileInfo
}

func NewCLIWorkspace(organization string, id uuid.UUID, at time.Time) (*CLIWorkspace, error) {
	if id == uuid.Nil {
		return nil, errors.New("backup identity is required")
	}
	directory, err := os.MkdirTemp("", "constellation-backup-*")
	if err != nil {
		return nil, &cliOperationError{"private backup workspace", err}
	}
	identity, err := os.Stat(directory)
	if err != nil {
		return nil, errors.Join(CLIFailure("private backup workspace identity", err), CLIFailure("private backup workspace cleanup", os.Remove(directory)))
	}
	return &CLIWorkspace{Path: filepath.Join(directory, ArtifactName(organization, id, at)), directory: directory, identity: identity}, nil
}
func (w *CLIWorkspace) Preserve() { w.keep = true }
func (w *CLIWorkspace) Close() error {
	if w == nil || w.keep || w.closed {
		return nil
	}
	current, err := os.Lstat(w.directory)
	if os.IsNotExist(err) {
		w.closed = true
		return nil
	}
	if err != nil || !current.IsDir() || !os.SameFile(current, w.identity) {
		return errors.New("private backup workspace identity changed; cleanup refused")
	}
	if err = os.RemoveAll(w.directory); err != nil {
		return CLIFailure("private backup workspace cleanup", err)
	}
	w.closed = true
	return nil
}

// CLIFailure keeps internal causes available to errors.Is/As without including
// connection strings, child output or operator-provided values in diagnostics.
func CLIFailure(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	return &cliOperationError{stage, cause}
}
func (w *CLIWorkspace) Discard() { w.keep = false }

// ValidateCLIBackupSigning checks mutually exclusive flags before opening a
// database, creating an artifact, or invoking any signer or upload subprocess.
func ValidateCLIBackupSigning(key string, keyless bool, verify string) (SignMode, error) {
	if key != "" && keyless {
		return "", errors.New("--sign-key and --sign-keyless cannot be combined")
	}
	if verify != "" && (key == "" || keyless) {
		return "", errors.New("--verify-key requires static-key signing")
	}
	if keyless {
		return SignModeKeyless, nil
	}
	if key != "" {
		return SignModeStaticKey, nil
	}
	return SignModeNone, nil
}

func ValidateS3Endpoint(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid backup S3 endpoint")
	}
	return nil
}
