package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/pkg/sarif"
)

func TestOneShotReportsArePrivateAndComplete(t *testing.T) {
	dir := t.TempDir()
	jsonPath, sarifPath := filepath.Join(dir, "scan.json"), filepath.Join(dir, "scan.sarif")
	result := &scanner.ScanResult{ImageRef: "registry.example.test/app:1"}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	if err := completeOneShotScan(t.Context(), logger, result, jsonPath, sarifPath); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{jsonPath, sarifPath} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private report %s: %v / %v", path, info, err)
		}
	}
	var actual scanner.ScanResult
	readReport(t, jsonPath, &actual)
	if actual.ImageRef != result.ImageRef {
		t.Fatal("JSON result changed")
	}
	var doc sarif.Doc
	readReport(t, sarifPath, &doc)
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || doc.Runs[0].Tool.Driver.Name != "Constellation" {
		t.Fatalf("missing SARIF document: %+v", doc)
	}
	if strings.Count(logs.String(), "scan complete") != 1 {
		t.Fatalf("completion receipt: %s", logs.String())
	}
}

func readReport(t *testing.T, path string, destination any) {
	t.Helper()
	if err := json.Unmarshal(readOutput(t, path), destination); err != nil {
		t.Fatal(err)
	}
}

func readOutput(t *testing.T, path string) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	body, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type outputFailureFixture struct {
	dir, path, jsonPath, sarifPath string
	prior                          []byte
	result                         *scanner.ScanResult
	ctx                            context.Context
}

func outputFailure(t *testing.T, mode string) outputFailureFixture {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.json")
	prior := []byte("prior complete report")
	if err := os.WriteFile(path, prior, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	f := outputFailureFixture{dir: dir, path: path, jsonPath: path, prior: prior, ctx: ctx,
		result: &scanner.ScanResult{ImageRef: "registry.example.test/app:1"}}
	switch mode {
	case "missing-parent":
		f.jsonPath = filepath.Join(dir, "missing", "scan.json")
	case "directory":
		f.jsonPath = dir
	case "symlink":
		f.jsonPath = filepath.Join(dir, "alias.json")
		if err := os.Symlink(path, f.jsonPath); err != nil {
			t.Fatal(err)
		}
	case "encode":
		f.result.Findings = []scanner.Finding{{CVSSBase: math.NaN()}}
	case "canceled":
		cancel()
	case "second-output":
		f.sarifPath = dir
	default:
		t.Fatalf("unknown failure fixture %q", mode)
	}
	return f
}

func assertFailedOutputFiles(t *testing.T, mode string, f outputFailureFixture) {
	t.Helper()
	body := readOutput(t, f.path)
	if mode == "second-output" {
		if !json.Valid(body) {
			t.Fatal("first complete artifact was lost after second output failed")
		}
	} else if !bytes.Equal(body, f.prior) {
		t.Fatal("failed output changed the prior report")
	}
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".pending-") {
			t.Fatal("temporary output left after failure")
		}
	}
}

func TestOneShotOutputFailureNeverReportsCompletion(t *testing.T) {
	for _, mode := range []string{"missing-parent", "directory", "symlink", "encode", "canceled", "second-output"} {
		t.Run(mode, func(t *testing.T) {
			f := outputFailure(t, mode)
			var logs bytes.Buffer
			err := completeOneShotScan(f.ctx, slog.New(slog.NewJSONHandler(&logs, nil)), f.result, f.jsonPath, f.sarifPath)
			if err == nil || strings.Contains(logs.String(), "scan complete") {
				t.Fatalf("output failure reported success: %v / %s", err, logs.String())
			}
			assertFailedOutputFiles(t, mode, f)
		})
	}
}

type replacingOutputParent struct {
	parent, displaced string
}

func (p replacingOutputParent) MarshalJSON() ([]byte, error) {
	if err := os.Rename(p.parent, p.displaced); err != nil {
		return nil, err
	}
	if err := os.Mkdir(p.parent, 0o700); err != nil {
		return nil, err
	}
	return []byte(`{"complete":true}`), nil
}

func TestOneShotOutputRejectsParentReplacementDuringEncoding(t *testing.T) {
	base := t.TempDir()
	parent, displaced := filepath.Join(base, "reports"), filepath.Join(base, "displaced")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "scan.json"), []byte("prior"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeOneShotOutput(t.Context(), filepath.Join(parent, "scan.json"), replacingOutputParent{parent, displaced}); err == nil {
		t.Fatal("directory replacement reported success")
	}
	if _, err := os.Stat(filepath.Join(parent, "scan.json")); !os.IsNotExist(err) {
		t.Fatalf("replacement directory received output: %v", err)
	}
	body := readOutput(t, filepath.Join(displaced, "scan.json"))
	if string(body) != "prior" {
		t.Fatalf("old report changed: %q", body)
	}
	entries, err := os.ReadDir(displaced)
	if err != nil || len(entries) != 1 {
		t.Fatalf("displaced directory retained temporary data: %v / %v", entries, err)
	}
}

func TestOneShotConflictingDestinationsRejectedBeforeWrites(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "scan.json")
	for _, second := range []string{path, filepath.Join(alias, "scan.json")} {
		if err := validateOneShotOutputs("image", path, second); err == nil {
			t.Fatal("conflicting formats accepted at the same destination")
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("validation wrote output: %v", err)
	}
}

func TestOneShotOutputFlagsRequireCLIRef(t *testing.T) {
	if os.Getenv("CONSTELLATION_TEST_OUTPUT_FLAGS_CHILD") == "1" {
		flag.CommandLine = flag.NewFlagSet("constellation-scanner", flag.ExitOnError)
		os.Args = []string{"constellation-scanner", "--json=unused.json"}
		main()
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), executable, "-test.run=^TestOneShotOutputFlagsRequireCLIRef$") // #nosec G204 -- Runs the current Go test executable with fixed arguments; no external input selects a command.
	command.Env = append(os.Environ(), "CONSTELLATION_TEST_OUTPUT_FLAGS_CHILD=1")
	body, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || !bytes.Contains(body, []byte("require --ref")) {
		t.Fatalf("flags did not fail before service startup: %v / %s", err, body)
	}
}
