package archiveio

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeRejectsAmbiguousArchives(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{`{"name":"a","name":"b"}`, `{"name":"a","\u006eame":"a"}`, `{"unknown":1}`, `{"name":"a"} {}`, `{"name":"` + string([]byte{0xff}) + `"}`, strings.Repeat("[", 130) + "0" + strings.Repeat("]", 130)} {
		var value struct {
			Name string `json:"name"`
		}
		if err := Decode([]byte(raw), &value); err == nil {
			t.Fatalf("accepted ambiguous archive %q", raw)
		}
	}
	var value struct {
		Name string `json:"name"`
	}
	if err := Decode([]byte(`{"name":"valid"}`), &value); err != nil || value.Name != "valid" {
		t.Fatalf("valid archive: %v", err)
	}
	var nested map[string]any
	if err := Decode([]byte(`{"outer":{"a":1,"a":2}}`), &nested); err == nil {
		t.Fatal("nested duplicate accepted")
	}
}

type cancelReader struct{ cancel context.CancelFunc }

func (r cancelReader) Read(p []byte) (int, error) { p[0] = 'x'; r.cancel(); return 1, nil }

func TestReaderCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if _, err := io.ReadAll(Reader{ctx, cancelReader{cancel}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-read cancellation: %v", err)
	}
	if _, err := io.ReadAll(Reader{ctx, strings.NewReader("unread")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("entry cancellation: %v", err)
	}
}

func TestWriteVerifiedPrivateReadBack(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "archives")
	payload := []byte("private archive content")
	path, err := WriteVerified(t.Context(), dir, ".archive", payload, func(r io.Reader) error {
		got, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, payload) {
			return errors.New("mismatch")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
		stat, err := os.Stat(name)
		if err != nil || stat.Mode().Perm() != want {
			t.Fatalf("permissions %s: %v", name, err)
		}
	}
	if path, err := WriteVerified(t.Context(), dir, ".archive", payload, func(io.Reader) error { return errors.New("signature rejected") }); err == nil || path != "" {
		t.Fatal("failed verification returned receipt")
	}
}

func TestWriteVerifiedRejectsChangedBytes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	payload := []byte("original")
	path, err := WriteVerified(t.Context(), dir, ".archive", payload, func(io.Reader) error {
		copy(payload, "replaced")
		names, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, names[0].Name()), []byte("replaced"), 0o600)
	})
	if err == nil || path != "" {
		t.Fatal("changed file accepted by digest read-back")
	}
}

func TestWriteVerifiedRejectsUnsafeDestinationAndCancellation(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	dir := filepath.Join(base, "link")
	if err := os.Symlink(base, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteVerified(t.Context(), dir, ".archive", []byte("data"), func(io.Reader) error { return nil }); err == nil {
		t.Fatal("symlink output accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	path := filepath.Join(base, "not-created")
	if _, err := WriteVerified(ctx, path, ".archive", []byte("data"), func(io.Reader) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("canceled write created output")
	}
}
