package awslambda

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/alphabravocompany/constellation/internal/securefiles"
)

type HTTPDownloader struct {
	Client *http.Client
}

// packageDownloadError preserves errors.Is/As without putting a presigned URL,
// redirect Location, or transport-provided credential into persisted job errors.
type packageDownloadError struct {
	stage string
	cause error
}

func (e *packageDownloadError) Error() string {
	return "download lambda package: " + e.stage + " failed"
}
func (e *packageDownloadError) Unwrap() error { return e.cause }

func downloadFailure(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &packageDownloadError{stage: stage, cause: err}
}

func (d HTTPDownloader) Download(ctx context.Context, url string, dst string, maxBytes int64) (written int64, err error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxZipBytes
	}
	if maxBytes == math.MaxInt64 {
		return 0, errors.New("lambda package max zip size must allow a one-byte overflow check")
	}
	client := d.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := requestPackageResponse(ctx, client, url)
	if err != nil {
		return 0, err
	}
	// The explicit fallback also covers future early returns here. The
	// transfer helper closes before publication; the wrapper makes that one
	// underlying Close even when the safety defer also runs.
	resp.Body = &packageResponseBody{ReadCloser: resp.Body}
	defer func() { err = errors.Join(err, downloadFailure("close response", resp.Body.Close())) }()
	return downloadResponse(ctx, resp, dst, maxBytes, securefiles.WriteStream)
}

// Return the response to its single owning consumer, which closes it before
// publication and on every early failure path.
func requestPackageResponse(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, downloadFailure("request", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, downloadFailure("transport", err)
	}
	return resp, nil
}

// Each response has a single sequential consumer. A repeated safety close is
// harmless; the first Close error remains in the transfer result.
type packageResponseBody struct {
	io.ReadCloser
	closed bool
}

func (b *packageResponseBody) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	return b.ReadCloser.Close()
}

type packagePublisher func(*os.Root, string, os.FileMode, func(io.Writer) error) (int64, error)

// The production caller supplies a file beneath its owned0700 per-function
// workspace. Pin that dedicated parent; never publish via a substituted path.
// A response read/close, cancellation or file finalization failure must not
// replace a previously complete package or expose a partial destination.
func downloadResponse(ctx context.Context, resp *http.Response, dst string, maxBytes int64, publish packagePublisher) (written int64, err error) {
	bodyClosed := false
	defer func() {
		if !bodyClosed {
			err = errors.Join(err, downloadFailure("close response", resp.Body.Close()))
		}
	}()
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("download lambda package: HTTP status %d", resp.StatusCode)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if dst == "" || strings.HasSuffix(dst, string(filepath.Separator)) || filepath.Base(dst) == "." || filepath.Base(dst) == ".." {
		return 0, errors.New("lambda package destination must name a file")
	}
	root, err := securefiles.OpenPrivateDir(filepath.Dir(dst))
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	var copied int64
	size, err := publish(root, filepath.Base(dst), 0o600, func(destination io.Writer) error {
		limited := &io.LimitedReader{R: resp.Body, N: maxBytes + 1}
		var copyErr error
		copied, copyErr = io.Copy(destination, limited)
		bodyClosed = true
		closeErr := downloadFailure("close response", resp.Body.Close())
		var limitErr error
		if copied > maxBytes {
			limitErr = fmt.Errorf("lambda package exceeds max zip size %d bytes", maxBytes)
		}
		return errors.Join(downloadFailure("transfer response", copyErr), closeErr, limitErr, ctx.Err(), checkDownloadDirectory(root))
	})
	if err != nil {
		return copied, err
	}
	return size, checkDownloadDirectory(root)
}

func checkDownloadDirectory(root *os.Root) error {
	current, err := os.Lstat(root.Name())
	if err != nil {
		return errors.New("lambda package destination directory unavailable")
	}
	pinned, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !current.IsDir() || !os.SameFile(current, pinned) {
		return errors.New("lambda package destination directory changed")
	}
	return nil
}
