package securefiles

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func streamFixtureRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := OpenPrivateDir(filepath.Join(t.TempDir(), "private"))
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

func TestWriteStreamPublishesFinalSizeAndPrivatePermissions(t *testing.T) {
	t.Parallel()
	root := streamFixtureRoot(t)
	size, err := WriteStream(root, "evidence", 0o600, func(w io.Writer) error {
		_, err := io.WriteString(w, "complete confidential evidence")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := root.Stat("evidence")
	if err != nil || size != info.Size() || size != int64(len("complete confidential evidence")) || info.Mode().Perm() != 0o600 {
		t.Fatal("stream size or private permissions incorrect")
	}
}

func checkFailedStream(t *testing.T, closeFile bool) {
	t.Helper()
	root := streamFixtureRoot(t)
	if err := WriteFile(root, "evidence", []byte("prior complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("owned producer failure")
	size, err := WriteStream(root, "evidence", 0o600, func(w io.Writer) error {
		if _, err := io.WriteString(w, "partial"); err != nil {
			return err
		}
		if closeFile {
			if err := w.(*os.File).Close(); err != nil {
				t.Fatal(err)
			}
		}
		return failure
	})
	if size != 0 || !errors.Is(err, failure) || (closeFile && !errors.Is(err, os.ErrClosed)) {
		t.Fatal("producer or finalization failure hidden")
	}
	body, readErr := root.ReadFile("evidence")
	if readErr != nil || string(body) != "prior complete" {
		t.Fatal("failed stream replaced prior complete artifact")
	}
	entries, readErr := os.ReadDir(root.Name())
	if readErr != nil || len(entries) != 1 {
		t.Fatal("failed stream leaked pending file")
	}
}

func TestWriteStreamFailurePreservesPriorArtifactAndAllErrors(t *testing.T) {
	for _, closeFile := range []bool{false, true} {
		t.Run(map[bool]string{false: "producer", true: "producer-and-close"}[closeFile], func(t *testing.T) { checkFailedStream(t, closeFile) })
	}
}

func TestWriteStreamFinalizationFailureNeverPublishes(t *testing.T) {
	t.Parallel()
	root := streamFixtureRoot(t)
	size, err := WriteStream(root, "closed", 0o600, func(w io.Writer) error { return w.(*os.File).Close() })
	if size != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed stream reported success")
	}
	if _, err := root.Stat("closed"); !os.IsNotExist(err) {
		t.Fatal("closed stream was published")
	}
}

func TestWriteStreamRejectsNilProducerBeforePublication(t *testing.T) {
	t.Parallel()
	root := streamFixtureRoot(t)
	if _, err := WriteStream(root, "missing", 0o600, nil); err == nil {
		t.Fatal("nil producer accepted")
	}
	entries, err := os.ReadDir(root.Name())
	if err != nil || len(entries) != 0 {
		t.Fatal("nil producer created an artifact")
	}
}
