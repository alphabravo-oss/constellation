package backup

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func readArtifactTestFile(t *testing.T, path string) string {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	body, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestArtifactNamesAreSafeAndJobUnique(t *testing.T) {
	now := time.Date(2026, 10, 17, 1, 2, 3, 0, time.UTC)
	for _, org := range []string{"acme", "../../outside/../quoted\"\r\nname", "\\windows\\name", strings.Repeat("a", 400), "日本語", ""} {
		a, b := uuid.New(), uuid.New()
		name := ArtifactName(org, a, now)
		if filepath.Base(name) != name || !filepath.IsLocal(name) || len(name) > 150 || strings.ContainsAny(name, "/\\\r\n\"") {
			t.Fatalf("unsafe artifact name %q", name)
		}
		if name == ArtifactName(org, b, now) || !strings.Contains(name, a.String()) {
			t.Fatal("job identity lost")
		}
	}
}

func TestExportToFileFailurePreservesExistingOutput(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "caller-parent")
	if err := os.Mkdir(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "explicit.tar.gz")
	if err := os.WriteFile(path, []byte("prior complete backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	// OrgID validation fails before a database is needed, after the old writer
	// would already have opened/truncated the explicit output.
	if _, err := ExportToFile(t.Context(), nil, path, ExportOptions{}); err == nil {
		t.Fatal("expected export failure")
	}
	if got := readArtifactTestFile(t, path); got != "prior complete backup" {
		t.Fatalf("old output destroyed: %q", got)
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatal("CLI parent was hardened")
	}
}

func TestArtifactWriterAtomicPrivacyAndOverwrite(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "caller-parent")
	if err := os.Mkdir(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "chosen-output")
	original := filepath.Join(parent, "linked-original")
	if err := os.WriteFile(original, []byte("old"), 0o644); err != nil { // #nosec G306 -- Deliberately public-mode archive tests private replacement without changing the linked original.
		t.Fatal(err)
	}
	if err := os.Link(original, path); err != nil {
		t.Fatal(err)
	}
	size, err := writeArtifact(t.Context(), path, false, func(w io.Writer) error { _, err := io.WriteString(w, "replacement"); return err })
	if err != nil || size != 11 {
		t.Fatalf("size=%d error=%v", size, err)
	}
	if readArtifactTestFile(t, original) != "old" || readArtifactTestFile(t, path) != "replacement" {
		t.Fatal("hardlink target truncated")
	}
	originalInfo, err := os.Stat(original)
	if err != nil {
		t.Fatal(err)
	}
	if originalInfo.Mode().Perm() != 0o644 {
		t.Fatal("linked original permissions changed")
	}
	for _, target := range []string{path, parent} {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o600)
		if target == parent {
			want = 0o750
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode=%o", target, info.Mode().Perm())
		}
	}
	if _, err := writeArtifact(t.Context(), path, false, func(w io.Writer) error { _, err := io.WriteString(w, "second"); return err }); err != nil {
		t.Fatal(err)
	}
	if readArtifactTestFile(t, path) != "second" {
		t.Fatal("regular overwrite contract lost")
	}
}

func TestArtifactWriterFailureAndCancellationDoNotPublish(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(map[bool]string{false: "producer", true: "cancellation"}[cancel], func(t *testing.T) { assertArtifactWriterFailure(t, cancel) })
	}
}

func assertArtifactWriterFailure(t *testing.T, cancel bool) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "backup")
	if err := os.WriteFile(path, []byte("complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	sentinel := errors.New("producer failure")
	_, err := writeArtifact(ctx, path, false, func(w io.Writer) error {
		if _, err := io.WriteString(w, "partial"); err != nil {
			return err
		}
		if cancel {
			stop()
			return nil
		}
		return sentinel
	})
	want := sentinel
	if cancel {
		want = context.Canceled
	}
	if !errors.Is(err, want) {
		t.Fatalf("error=%v", err)
	}
	if readArtifactTestFile(t, path) != "complete" {
		t.Fatal("failed stream was published")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("partial files retained: %v", entries)
	}
}

func TestManagedArtifactsRejectParentSubstitution(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "managed")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "backup")
	moved := filepath.Join(base, "moved")
	_, err := writeArtifact(t.Context(), path, true, func(w io.Writer) error {
		if _, err := io.WriteString(w, "complete but not published"); err != nil {
			return err
		}
		if err := os.Rename(dir, moved); err != nil {
			return err
		}
		return os.Mkdir(dir, 0o750)
	})
	if err == nil {
		t.Fatal("substituted parent accepted")
	}
	for _, parent := range []string{dir, moved} {
		entries, err := os.ReadDir(parent)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("published through changed parent: %v", entries)
		}
	}
	info, err := os.Stat(moved)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatal("managed artifact parent not private")
	}
}

func TestArtifactReadersAndWritersRejectSymlinksAndDirectories(t *testing.T) {
	base := t.TempDir()
	victim := filepath.Join(base, "victim")
	if err := os.WriteFile(victim, []byte("private victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []bool{false, true} {
		target := filepath.Join(base, map[bool]string{false: "link", true: "directory"}[directory])
		if directory {
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.Symlink(victim, target); err != nil {
			t.Fatal(err)
		}
		if _, err := writeArtifact(t.Context(), target, false, func(w io.Writer) error { _, err := io.WriteString(w, "bad"); return err }); err == nil {
			t.Fatal("unsafe output accepted")
		}
		if file, err := OpenArtifact(target); err == nil {
			_ = file.Close()
			t.Fatal("unsafe download accepted")
		}
		if err := RemoveArtifact(target); err == nil {
			t.Fatal("unsafe retention target accepted")
		}
	}
	if readArtifactTestFile(t, victim) != "private victim" {
		t.Fatal("symlink target modified")
	}
}

func TestManagedArtifactDirDoesNotFallbackForExplicitInvalidRoot(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ManagedArtifactDir(link); err == nil {
		t.Fatal("configured symlink accepted/fell back")
	}
	dir, err := ManagedArtifactDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if dir != target {
		t.Fatal("configured root redirected")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatal("managed root not private")
	}
}

func TestArtifactOpenChecksBothReviewedAndCurrentInodes(t *testing.T) {
	for _, replaceBeforeOpen := range []bool{false, true} {
		t.Run(map[bool]string{false: "after open", true: "before open"}[replaceBeforeOpen], func(t *testing.T) { assertArtifactOpenChecks(t, replaceBeforeOpen) })
	}
}

func assertArtifactOpenChecks(t *testing.T, replaceBeforeOpen bool) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "archive")
	if err := os.WriteFile(path, []byte("reviewed"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent, name, err := openArtifactParent(path, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := parent.root.Close(); err != nil {
			t.Error(err)
		}
	})
	before, err := parent.root.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	replace := func() {
		t.Helper()
		if err := os.Rename(path, filepath.Join(dir, "original")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("substitution"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if replaceBeforeOpen {
		replace()
	}
	file, err := parent.root.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	if !replaceBeforeOpen {
		replace()
	}
	if err := parent.checkOpened(name, before, file); err == nil {
		t.Fatal("changed reviewed/current file was accepted")
	}
}

func TestExportManagedRejectsMissingRootBeforeDatabaseOrFilesystem(t *testing.T) {
	if _, err := ExportManaged(t.Context(), nil, "", "backup.tar.gz", ExportOptions{}); err == nil {
		t.Fatal("empty managed root accepted")
	}
	for _, name := range []string{"../outside", "nested/archive", "."} {
		if _, err := ExportManaged(t.Context(), nil, t.TempDir(), name, ExportOptions{}); err == nil {
			t.Fatalf("unsafe managed name accepted: %q", name)
		}
	}
}

func TestManagedArtifactDirDistinguishesImplicitAndExplicitDefault(t *testing.T) {
	for _, configured := range []string{"", defaultArtifactDir} {
		name := "explicit default"
		if configured == "" {
			name = "implicit default"
		}
		t.Run(name, func(t *testing.T) { assertManagedArtifactDirFallback(t, configured) })
	}
}

func assertManagedArtifactDirFallback(t *testing.T, configured string) {
	t.Helper()
	sentinel := errors.New("configured output unavailable")
	var opened []string
	directory := t.TempDir()
	actual, err := managedArtifactDir(configured, func(path string) (*os.Root, error) {
		opened = append(opened, path)
		if len(opened) == 1 {
			return nil, sentinel
		}
		return os.OpenRoot(directory)
	})
	if len(opened) == 0 || opened[0] != defaultArtifactDir {
		t.Fatalf("default effective location changed: %v", opened)
	}
	if configured != "" {
		if !errors.Is(err, sentinel) || actual != "" || len(opened) != 1 {
			t.Fatalf("explicit failure fell back: path=%q calls=%v err=%v", actual, opened, err)
		}
		return
	}
	fallback := filepath.Join(os.TempDir(), "constellation-backups")
	if err != nil || actual != fallback || len(opened) != 2 || opened[1] != fallback {
		t.Fatalf("implicit fallback mismatch: path=%q calls=%v err=%v", actual, opened, err)
	}
}
