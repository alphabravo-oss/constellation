package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/scanner"
)

type publicationFixture struct {
	name    string
	publish func(context.Context, string, io.Writer) error
	field   string
	value   string
	exact   string
}

func publicationFixtures() []publicationFixture {
	var fixtures []publicationFixture
	for _, format := range []struct {
		flag  string
		field string
		value string
	}{{"sarif", "version", "2.1.0"}, {"json", "ImageRef", "fixture.invalid/private:review"}, {"spdx", "spdxVersion", "SPDX-2.3"}, {"cyclonedx", "bomFormat", "CycloneDX"}} {
		command := imageCheckWithScanner(func(context.Context, string, scanner.ScanOptions) (*scanner.ScanResult, error) {
			return &scanner.ScanResult{ImageRef: "fixture.invalid/private:review"}, nil
		})
		fixtures = append(fixtures, publicationFixture{
			name:  format.flag,
			field: format.field,
			value: format.value,
			publish: func(ctx context.Context, path string, out io.Writer) error {
				return executeRemainingOutput(ctx, command, out, "fixture.invalid/private:review", "--"+format.flag, path)
			},
		})
	}
	iacCommand := iacCheckWithRunner(func(context.Context, string, ...string) ([]byte, error) {
		return []byte(`{ "version": "2.1.0", "runs": [] }`), nil
	})
	fixtures = append(fixtures, publicationFixture{
		name:  "iac",
		exact: `{ "version": "2.1.0", "runs": [] }`,
		publish: func(ctx context.Context, path string, out io.Writer) error {
			return executeRemainingOutput(ctx, iacCommand, out, "fixture-infrastructure", "--sarif", path)
		},
	}, publicationFixture{
		name:  "policy-crds",
		exact: "kind: First\n---\nkind: Second\n",
		publish: func(ctx context.Context, path string, out io.Writer) error {
			return writePolicyCRDOutput(ctx, out, path, [][]byte{[]byte("kind: First\n"), []byte("kind: Second\n")})
		},
	})
	return fixtures
}

func publicationRead(t *testing.T, path string) []byte {
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
	return body
}

func publicationMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func assertPublicationBody(t *testing.T, path string, fixture publicationFixture) {
	t.Helper()
	body := publicationRead(t, path)
	if fixture.exact != "" {
		if string(body) != fixture.exact {
			t.Fatal("artifact bytes changed")
		}
		return
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil || fields[fixture.field] != fixture.value {
		t.Fatal("artifact format or selected image changed")
	}
}

func TestCLIReportFilesArePrivateAndPreserveRegularOverwrite(t *testing.T) {
	for _, fixture := range publicationFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			parent := t.TempDir()
			publicationMode(t, parent, 0o750)
			path := filepath.Join(parent, "explicit-report")
			if err := os.WriteFile(path, []byte("old report"), 0o600); err != nil {
				t.Fatal(err)
			}
			publicationMode(t, path, 0o644)
			var out bytes.Buffer
			if err := fixture.publish(t.Context(), path, &out); err != nil {
				t.Fatal(err)
			}
			assertPublicationBody(t, path, fixture)
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatal("report retained public permissions")
			}
			info, err = os.Stat(parent)
			if err != nil || info.Mode().Perm() != 0o750 {
				t.Fatal("publication hardened the caller's parent directory")
			}
			if !strings.Contains(out.String(), "wrote") {
				t.Fatal("successful artifact confirmation disappeared")
			}
		})
	}
}

func TestCLIReportRejectsSymlinkWithoutSuccessOrSentinelMutation(t *testing.T) {
	for _, fixture := range publicationFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			parent := t.TempDir()
			original := filepath.Join(parent, "sentinel")
			if err := os.WriteFile(original, []byte("sentinel"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "report")
			if err := os.Symlink(original, path); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := fixture.publish(t.Context(), path, &out); err == nil || out.Len() != 0 {
				t.Fatal("unsafe destination reported success")
			}
			if string(publicationRead(t, original)) != "sentinel" {
				t.Fatal("symlink target overwritten")
			}
		})
	}
}

func TestCLIReportRetainsCompletedPrivateArtifactAfterConfirmationFailure(t *testing.T) {
	for _, fixture := range publicationFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report")
			if err := fixture.publish(t.Context(), path, &failingCommandOutput{}); !errors.Is(err, errCommandOutputTest) {
				t.Fatal("failed confirmation was reported as success")
			}
			assertPublicationBody(t, path, fixture)
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatal("completed private report lost after confirmation failure")
			}
		})
	}
}

func TestCLIReportCanceledPublicationPreservesExistingArtifact(t *testing.T) {
	for _, fixture := range publicationFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report")
			if err := os.WriteFile(path, []byte("prior complete"), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			var out bytes.Buffer
			if err := fixture.publish(ctx, path, &out); !errors.Is(err, context.Canceled) || out.Len() != 0 {
				t.Fatal("canceled publication reported success")
			}
			if string(publicationRead(t, path)) != "prior complete" {
				t.Fatal("canceled publication replaced prior report")
			}
		})
	}
}

func TestSaveConfigReplacesPermissiveHardlinkPrivatelyWithoutChangingParent(t *testing.T) {
	parent := t.TempDir()
	publicationMode(t, parent, 0o750)
	original := filepath.Join(parent, "original")
	path := filepath.Join(parent, "config")
	if err := os.WriteFile(original, []byte("old config"), 0o600); err != nil {
		t.Fatal(err)
	}
	publicationMode(t, original, 0o644)
	if err := os.Link(original, path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONSTELLATION_CONFIG", path)
	if err := saveConfig(t.Context(), &config{Server: "https://fixture.invalid", Token: "fixture-token"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("config token remains publicly readable")
	}
	if string(publicationRead(t, original)) != "old config" {
		t.Fatal("saving a token mutated a linked original")
	}
	var saved config
	if err := json.Unmarshal(publicationRead(t, path), &saved); err != nil || saved.Token != "fixture-token" {
		t.Fatal("configuration content changed")
	}
	info, err = os.Stat(parent)
	if err != nil || info.Mode().Perm() != 0o750 {
		t.Fatal("config save hardened an existing parent")
	}
}

func TestSaveConfigCreatesMissingParentAndRejectsSymlink(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "new-parent", "config")
	t.Setenv("CONSTELLATION_CONFIG", path)
	if err := saveConfig(t.Context(), &config{Token: "fixture-token"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatal("new config directory is not private")
	}
	link := filepath.Join(base, "config-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONSTELLATION_CONFIG", link)
	if err := saveConfig(t.Context(), &config{Token: "replacement"}); err == nil {
		t.Fatal("symlinked token destination accepted")
	}
	var saved config
	if err := json.Unmarshal(publicationRead(t, path), &saved); err != nil || saved.Token != "fixture-token" {
		t.Fatal("rejected config save modified its target")
	}
}

func TestSaveConfigCancellationDoesNotCreateParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "config")
	t.Setenv("CONSTELLATION_CONFIG", path)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := saveConfig(ctx, &config{Token: "fixture-token"}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled config save accepted")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("canceled config save created a directory")
	}
}

func TestPolicyCRDOutputPreservesStdoutWithoutCreatingArtifact(t *testing.T) {
	var out bytes.Buffer
	if err := writePolicyCRDOutput(t.Context(), &out, "", [][]byte{[]byte("one\n"), []byte("two\n")}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "one\n---\ntwo\n" {
		t.Fatal("CRD stdout format changed")
	}
}
