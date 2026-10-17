package securefiles

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func pathFixtureRead(t *testing.T, path string) string {
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

func pathFixtureMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func pathFixtureWrite(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWritePathPrivateReplacementPreservesOtherHardlinkAndParent(t *testing.T) {
	parent := t.TempDir()
	pathFixtureMode(t, parent, 0o750)
	original := filepath.Join(parent, "linked-original")
	path := filepath.Join(parent, "selected-output")
	pathFixtureWrite(t, original, "previous complete report")
	pathFixtureMode(t, original, 0o644)
	if err := os.Link(original, path); err != nil {
		t.Fatal(err)
	}
	if err := WritePath(t.Context(), path, []byte("new report")); err != nil {
		t.Fatal(err)
	}
	if pathFixtureRead(t, original) != "previous complete report" || pathFixtureRead(t, path) != "new report" {
		t.Fatal("publication truncated the linked original")
	}
	for _, fixture := range []struct {
		path string
		mode os.FileMode
	}{{parent, 0o750}, {original, 0o644}, {path, 0o600}} {
		info, err := os.Stat(fixture.path)
		if err != nil || info.Mode().Perm() != fixture.mode {
			t.Fatal("publication changed parent/original mode or retained public output mode")
		}
	}
	if err := WritePath(t.Context(), path, []byte("next report")); err != nil {
		t.Fatal(err)
	}
	if pathFixtureRead(t, path) != "next report" {
		t.Fatal("regular-file overwrite was lost")
	}
}

func TestWritePathRejectsKnownSymlinkAndNonregularDestination(t *testing.T) {
	parent := t.TempDir()
	original := filepath.Join(parent, "original")
	pathFixtureWrite(t, original, "do not change")
	link := filepath.Join(parent, "link")
	if err := os.Symlink(original, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, parent, "", parent + string(os.PathSeparator)} {
		if err := WritePath(t.Context(), path, []byte("replacement")); err == nil {
			t.Fatal("nonregular or unnamed destination accepted")
		}
	}
	if pathFixtureRead(t, original) != "do not change" {
		t.Fatal("symlink target modified")
	}
}

func TestWritePathAcceptsExplicitRelativePathWithoutCreatingParents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePath(t.Context(), relative, []byte("relative report")); err != nil {
		t.Fatal(err)
	}
	if pathFixtureRead(t, path) != "relative report" {
		t.Fatal("selected relative path changed")
	}
	missing := filepath.Join(filepath.Dir(path), "missing", "report")
	if err := WritePath(t.Context(), missing, nil); !os.IsNotExist(err) {
		t.Fatal("missing parent did not remain an error")
	}
	if _, err := os.Stat(filepath.Dir(missing)); !os.IsNotExist(err) {
		t.Fatal("report publication created a parent directory")
	}
}

func TestWritePathFailuresPreservePriorReportAndRemovePending(t *testing.T) {
	for _, stage := range []string{"producer", "finalization", "cancellation"} {
		t.Run(stage, func(t *testing.T) { checkPathFailure(t, stage) })
	}
}

func checkPathFailure(t *testing.T, stage string) {
	t.Helper()
	parent := t.TempDir()
	path := filepath.Join(parent, "report")
	pathFixtureWrite(t, path, "prior complete")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	failure := errors.New("injected report producer failure")
	err := WritePathStream(ctx, path, func(out io.Writer) error {
		if _, err := io.WriteString(out, "partial replacement"); err != nil {
			return err
		}
		switch stage {
		case "producer":
			return failure
		case "finalization":
			return out.(*os.File).Close()
		case "cancellation":
			cancel()
		}
		return nil
	})
	if err == nil || (stage == "producer" && !errors.Is(err, failure)) || (stage == "cancellation" && !errors.Is(err, context.Canceled)) {
		t.Fatal("injected publication failure was not preserved")
	}
	if pathFixtureRead(t, path) != "prior complete" {
		t.Fatal("failed publication replaced the prior report")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 {
		t.Fatal("failed publication leaked a pending artifact")
	}
}

func TestWritePathRefusesObservedParentReplacementBeforePublication(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	moved := filepath.Join(base, "original-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	pathFixtureWrite(t, filepath.Join(parent, "report"), "prior complete")
	err := WritePathStream(t.Context(), filepath.Join(parent, "report"), func(out io.Writer) error {
		if _, err := io.WriteString(out, "replacement"); err != nil {
			return err
		}
		if err := os.Rename(parent, moved); err != nil {
			return err
		}
		return os.Mkdir(parent, 0o700)
	})
	if err == nil {
		t.Fatal("observed replacement was accepted")
	}
	if pathFixtureRead(t, filepath.Join(moved, "report")) != "prior complete" {
		t.Fatal("known parent change still published into the original parent")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("publication escaped into the replacement parent")
	}
	entries, err = os.ReadDir(moved)
	if err != nil || len(entries) != 1 {
		t.Fatal("pending artifact remained in the original parent")
	}
}

func TestWritePathCanceledBeforeStartHasNoEffects(t *testing.T) {
	parent := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := WritePath(ctx, filepath.Join(parent, "report"), nil); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled publication accepted")
	}
	if err := WritePathStream(t.Context(), filepath.Join(parent, "report"), nil); err == nil {
		t.Fatal("missing producer accepted")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("refused publication had filesystem effects")
	}
}
