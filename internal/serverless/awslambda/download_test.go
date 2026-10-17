package awslambda

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/internal/securefiles"
)

var errPackageRead = errors.New("owned package read failure")
var errPackageClose = errors.New("owned package close failure")
var errPackageWrite = errors.New("owned package write failure")

type lambdaDownloadTransport func(*http.Request) (*http.Response, error)

func (f lambdaDownloadTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type lambdaDownloadBody struct {
	reader    io.Reader
	readErr   error
	closeErr  error
	onClose   func() error
	readBytes int
	closed    int
}

func (b *lambdaDownloadBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.readBytes += n
	if errors.Is(err, io.EOF) && b.readErr != nil {
		return n, b.readErr
	}
	return n, err
}

func (b *lambdaDownloadBody) Close() error {
	b.closed++
	var callbackErr error
	if b.onClose != nil {
		callbackErr = b.onClose()
	}
	return errors.Join(b.closeErr, callbackErr)
}

func lambdaDownloadClient(body *lambdaDownloadBody, status int) *http.Client {
	return &http.Client{Transport: lambdaDownloadTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d owned status", status), Body: body, Header: make(http.Header), Request: r}, nil
	})}
}

func packageFixtureRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return root
}

func packageFixtureEntries(t *testing.T, root *os.Root) []os.DirEntry {
	t.Helper()
	directory, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	entries, readErr := directory.ReadDir(-1)
	if err := errors.Join(readErr, directory.Close()); err != nil {
		t.Fatal(err)
	}
	return entries
}

func packageDestination(t *testing.T) (string, []byte) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "function.zip")
	prior := []byte("prior complete package")
	if err := packageFixtureRoot(t, dir).WriteFile("function.zip", prior, 0o600); err != nil {
		t.Fatal(err)
	}
	return dst, prior
}

func assertPackagePreserved(t *testing.T, dst string, expected []byte) {
	t.Helper()
	root := packageFixtureRoot(t, filepath.Dir(dst))
	got, err := root.ReadFile(filepath.Base(dst))
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("prior package changed: %v", err)
	}
	entries := packageFixtureEntries(t, root)
	if len(entries) != 1 || entries[0].Name() != filepath.Base(dst) {
		t.Fatal("temporary or partial package leaked")
	}
}

func TestHTTPDownloaderPublishesOnlyCompletePrivatePackage(t *testing.T) {
	for _, max := range []int64{0, -1, 16, 17, math.MaxInt64 - 1} {
		t.Run(fmt.Sprint(max), func(t *testing.T) {
			dst, prior := packageDestination(t)
			payload := []byte("complete package")
			body := &lambdaDownloadBody{reader: bytes.NewReader(payload)}
			closedBeforePublication := false
			fixture := packageFixtureRoot(t, filepath.Dir(dst))
			body.onClose = func() error {
				got, err := fixture.ReadFile("function.zip")
				if err != nil || !bytes.Equal(got, prior) {
					return errors.New("destination published before response Close")
				}
				closedBeforePublication = true
				return nil
			}
			n, err := (HTTPDownloader{Client: lambdaDownloadClient(body, http.StatusOK)}).Download(t.Context(), "https://lambda.example/package", dst, max)
			if err != nil || n != int64(len(payload)) || body.closed != 1 || !closedBeforePublication {
				t.Fatalf("complete package receipt: bytes=%d closed=%d err=%v", n, body.closed, err)
			}
			assertPackagePreserved(t, dst, payload)
			for path, want := range map[string]os.FileMode{filepath.Dir(dst): 0o700, dst: 0o600} {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != want {
					t.Fatalf("private mode for %s: %v", filepath.Base(path), err)
				}
			}
		})
	}
}

func TestHTTPDownloaderPreservesAcceptedStatusClass(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusFound} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			dst, _ := packageDestination(t)
			body := &lambdaDownloadBody{reader: strings.NewReader("complete package")}
			n, err := (HTTPDownloader{Client: lambdaDownloadClient(body, status)}).Download(t.Context(), "https://lambda.example/package", dst, 64)
			if err != nil || n != 16 || body.closed != 1 {
				t.Fatalf("previously accepted HTTP status changed: %v", err)
			}
			assertPackagePreserved(t, dst, []byte("complete package"))
		})
	}
}

func TestHTTPDownloaderFirstFailureLeavesNoDestination(t *testing.T) {
	for _, fault := range []string{"read", "close", "overflow"} {
		t.Run(fault, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "private", "function.zip")
			body := &lambdaDownloadBody{reader: strings.NewReader("complete package")}
			if fault == "read" {
				body.readErr = errPackageRead
			}
			if fault == "close" {
				body.closeErr = errPackageClose
			}
			limit := int64(64)
			if fault == "overflow" {
				limit = 15
			}
			_, err := (HTTPDownloader{Client: lambdaDownloadClient(body, http.StatusOK)}).Download(t.Context(), "https://lambda.example/package", dst, limit)
			if err == nil || body.closed != 1 {
				t.Fatal("failed first download returned a successful receipt")
			}
			entries := packageFixtureEntries(t, packageFixtureRoot(t, filepath.Dir(dst)))
			if len(entries) != 0 {
				t.Fatal("failed first download retained a partial package or pending file")
			}
		})
	}
}

func assertPackageFailureCauses(t *testing.T, err error, body *lambdaDownloadBody) {
	t.Helper()
	if body.readErr != nil && !errors.Is(err, errPackageRead) {
		t.Fatal("read failure cause was discarded")
	}
	if body.closeErr != nil && !errors.Is(err, errPackageClose) {
		t.Fatal("close failure cause was discarded")
	}
}

func TestHTTPDownloaderFailedResponsesPreservePriorPackage(t *testing.T) {
	for _, fault := range []string{"read", "close", "read-and-close", "overflow"} {
		t.Run(fault, func(t *testing.T) {
			dst, prior := packageDestination(t)
			payload := []byte("complete package")
			body := &lambdaDownloadBody{reader: bytes.NewReader(payload)}
			if strings.Contains(fault, "read") {
				body.readErr = errPackageRead
			}
			if strings.Contains(fault, "close") {
				body.closeErr = errPackageClose
			}
			limit := int64(len(payload))
			if fault == "overflow" {
				body.reader = bytes.NewReader(append(payload, 'x', 'y'))
			}
			_, err := (HTTPDownloader{Client: lambdaDownloadClient(body, http.StatusOK)}).Download(t.Context(), "https://lambda.example/package", dst, limit)
			if err == nil || body.closed != 1 {
				t.Fatalf("failed response accepted or closed incorrectly: %v", err)
			}
			assertPackageFailureCauses(t, err, body)
			if fault == "overflow" && body.readBytes != len(payload)+1 {
				t.Fatal("overflow was not bounded to one extra byte")
			}
			assertPackagePreserved(t, dst, prior)
		})
	}
}

type cancelPackageReader struct {
	reader io.Reader
	cancel func()
}

func (r cancelPackageReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.cancel()
	return n, err
}

func TestHTTPDownloaderCancellationNeverPublishes(t *testing.T) {
	dst, prior := packageDestination(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	body := &lambdaDownloadBody{reader: cancelPackageReader{reader: strings.NewReader("complete package"), cancel: sync.OnceFunc(cancel)}}
	_, err := (HTTPDownloader{Client: lambdaDownloadClient(body, http.StatusOK)}).Download(ctx, "https://lambda.example/package", dst, 64)
	if !errors.Is(err, context.Canceled) || body.closed != 1 {
		t.Fatalf("cancellation lost or body left open: %v", err)
	}
	assertPackagePreserved(t, dst, prior)
}

func TestHTTPDownloaderStatusAndUnrepresentableLimitFailBeforePublication(t *testing.T) {
	t.Run("HTTP status", func(t *testing.T) {
		dst, prior := packageDestination(t)
		body := &lambdaDownloadBody{reader: strings.NewReader("must not publish"), closeErr: errPackageClose}
		_, err := (HTTPDownloader{Client: lambdaDownloadClient(body, http.StatusForbidden)}).Download(t.Context(), "https://lambda.example/package", dst, 64)
		if err == nil || !strings.Contains(err.Error(), "403") || !errors.Is(err, errPackageClose) || body.closed != 1 || body.readBytes != 0 {
			t.Fatalf("status/close contract changed: %v", err)
		}
		assertPackagePreserved(t, dst, prior)
	})
	t.Run("MaxInt64 overflow probe", func(t *testing.T) {
		dst, prior := packageDestination(t)
		calls := 0
		client := &http.Client{Transport: lambdaDownloadTransport(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("must not dispatch")
		})}
		if _, err := (HTTPDownloader{Client: client}).Download(t.Context(), "https://lambda.example/package", dst, math.MaxInt64); err == nil || calls != 0 {
			t.Fatal("unrepresentable limit dispatched or silently wrapped")
		}
		assertPackagePreserved(t, dst, prior)
	})
}

type failedPackageWriter struct{}

func (failedPackageWriter) Write([]byte) (int, error) { return 0, errPackageWrite }

func TestDownloadResponseFileFinalizationNeverReplacesPriorPackage(t *testing.T) {
	for _, fault := range []string{"write", "close"} {
		t.Run(fault, func(t *testing.T) {
			dst, prior := packageDestination(t)
			body := &lambdaDownloadBody{reader: strings.NewReader("complete package")}
			publish := func(root *os.Root, name string, mode os.FileMode, produce func(io.Writer) error) (int64, error) {
				return securefiles.WriteStream(root, name, mode, func(destination io.Writer) error {
					if fault == "write" {
						return produce(failedPackageWriter{})
					}
					if err := produce(destination); err != nil {
						return err
					}
					// Force the real securefiles chmod/sync/Close finalizers to
					// encounter a closed descriptor, before atomic publication.
					return destination.(*os.File).Close()
				})
			}
			_, err := downloadResponse(t.Context(), &http.Response{StatusCode: http.StatusOK, Body: body}, dst, 64, publish)
			want := errPackageWrite
			if fault == "close" {
				want = os.ErrClosed
			}
			if !errors.Is(err, want) || body.closed != 1 {
				t.Fatalf("file finalization failure hidden: %v", err)
			}
			assertPackagePreserved(t, dst, prior)
		})
	}
}

func packageLinkedDestination(t *testing.T, link string) (string, *os.Root) {
	t.Helper()
	parent := t.TempDir()
	fixture := packageFixtureRoot(t, parent)
	dir := filepath.Join(parent, "private")
	if err := fixture.Mkdir("private", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := fixture.WriteFile("unrelated", []byte("unrelated private bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "function.zip")
	var linkErr error
	if link == "hardlink" {
		linkErr = fixture.Link("unrelated", "private/function.zip")
	} else {
		linkErr = fixture.Symlink("../unrelated", "private/function.zip")
	}
	if err := linkErr; err != nil {
		t.Fatal(err)
	}
	return dst, fixture
}

func TestHTTPDownloaderRejectsSymlinksAndPreservesHardlinkVictim(t *testing.T) {
	for _, link := range []string{"symlink", "hardlink"} {
		t.Run(link, func(t *testing.T) {
			dst, fixture := packageLinkedDestination(t, link)
			body := &lambdaDownloadBody{reader: strings.NewReader("complete package")}
			_, err := (HTTPDownloader{Client: lambdaDownloadClient(body, http.StatusOK)}).Download(t.Context(), "https://lambda.example/package", dst, 64)
			if link == "symlink" && err == nil || link == "hardlink" && err != nil || body.closed != 1 {
				t.Fatalf("link handling changed: %v", err)
			}
			got, readErr := fixture.ReadFile("unrelated")
			info, statErr := fixture.Stat("unrelated")
			if readErr != nil || statErr != nil || string(got) != "unrelated private bytes" || info.Mode().Perm() != 0o644 {
				t.Fatal("unrelated hardlink/symlink target was changed")
			}
		})
	}
}

func TestHTTPDownloaderDirectoryReplacementDoesNotRedirectPublication(t *testing.T) {
	dst, prior := packageDestination(t)
	dir := filepath.Dir(dst)
	moved := filepath.Join(filepath.Dir(dir), "original")
	fixture := packageFixtureRoot(t, filepath.Dir(dir))
	body := &lambdaDownloadBody{reader: strings.NewReader("complete package")}
	body.onClose = func() error {
		if err := fixture.Rename("private", "original"); err != nil {
			return err
		}
		if err := fixture.Mkdir("private", 0o700); err != nil {
			return err
		}
		return fixture.WriteFile("private/function.zip", []byte("replacement owner"), 0o600)
	}
	_, err := (HTTPDownloader{Client: lambdaDownloadClient(body, http.StatusOK)}).Download(t.Context(), "https://lambda.example/package", dst, 64)
	if err == nil || body.closed != 1 {
		t.Fatal("replaced directory returned a successful artifact receipt")
	}
	assertPackagePreserved(t, filepath.Join(moved, "function.zip"), prior)
	assertPackagePreserved(t, dst, []byte("replacement owner"))
}

const signedLambdaURL = "https://lambda.example/function.zip?X-Amz-Credential=credential-canary&X-Amz-Signature=signature-canary&X-Amz-Security-Token=token-canary"

type forbiddenPackageCataloger struct{ t *testing.T }

func (c forbiddenPackageCataloger) Catalog(context.Context, string, string, string) ([]scanner.Package, error) {
	c.t.Fatal("cataloger ran after a failed package receipt")
	return nil, nil
}

func assertNoSignedLocation(t *testing.T, err error, summaries []string) {
	t.Helper()
	values := append([]string{err.Error()}, summaries...)
	for _, value := range values {
		for _, forbidden := range []string{"lambda.example", "X-Amz", "credential-canary", "signature-canary", "token-canary", "transport-canary"} {
			if strings.Contains(value, forbidden) {
				t.Fatal("presigned package URL or credential appeared in propagated error")
			}
		}
	}
}

func packageCollectFailureClient(t *testing.T, fault string) (string, *http.Client) {
	t.Helper()
	location := signedLambdaURL
	if fault == "request" {
		location = "https://[malformed/function.zip?X-Amz-Credential=credential-canary&X-Amz-Signature=signature-canary"
	}
	body := &lambdaDownloadBody{reader: bytes.NewReader(testZip(t, map[string]string{"handler.py": "print('ok')"}))}
	if fault == "read" {
		body.readErr = &url.Error{Op: "read", URL: signedLambdaURL, Err: errPackageRead}
	}
	if fault == "close" {
		body.closeErr = &url.Error{Op: "close", URL: signedLambdaURL, Err: errPackageClose}
	}
	client := lambdaDownloadClient(body, http.StatusOK)
	if fault == "transport" {
		client.Transport = lambdaDownloadTransport(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("transport-canary %s", signedLambdaURL)
		})
	}
	return location, client
}

func TestCollectDownloadFailuresDoNotExposeSignedLocationOrAdvance(t *testing.T) {
	for _, fault := range []string{"request", "transport", "read", "close"} {
		t.Run(fault, func(t *testing.T) {
			location, client := packageCollectFailureClient(t, fault)
			fn := lambdatypes.FunctionConfiguration{FunctionName: awssdk.String("payments"), PackageType: lambdatypes.PackageTypeZip}
			aws := &fakeLambdaAPI{getFunction: &lambda.GetFunctionOutput{Configuration: &fn, Code: &lambdatypes.FunctionCodeLocation{Location: awssdk.String(location)}}}
			reporter := &fakeReporter{}
			summary, err := Collect(t.Context(), aws, HTTPDownloader{Client: client}, forbiddenPackageCataloger{t: t}, reporter, Options{FunctionName: "payments", TempDir: t.TempDir()})
			if err == nil || summary.Failed != 1 || summary.Reported != 0 || len(reporter.payloads) != 0 || len(summary.Errors) != 1 {
				t.Fatal("failed download advanced to catalog/report or lost its failure")
			}
			assertNoSignedLocation(t, err, summary.Errors)
			if fault == "read" && !errors.Is(err, errPackageRead) || fault == "close" && !errors.Is(err, errPackageClose) {
				t.Fatal("redaction discarded errors.Is cause")
			}
		})
	}
}

func TestHTTPDownloaderTransportCancellationRetainsCauseWithoutSignedURL(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			dst, prior := packageDestination(t)
			client := &http.Client{Transport: lambdaDownloadTransport(func(*http.Request) (*http.Response, error) { return nil, cause })}
			_, err := (HTTPDownloader{Client: client}).Download(t.Context(), signedLambdaURL, dst, 64)
			if !errors.Is(err, cause) {
				t.Fatal("request cancellation cause lost")
			}
			assertNoSignedLocation(t, err, nil)
			assertPackagePreserved(t, dst, prior)
		})
	}
}
