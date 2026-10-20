package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/internal/securefiles"
	"github.com/alphabravocompany/constellation/pkg/sarif"
	"github.com/alphabravocompany/constellation/pkg/version"
)

func validateOneShotOutputs(ref, jsonPath, sarifPath string) error {
	if jsonPath == "" && sarifPath == "" {
		return nil
	}
	if ref == "" {
		return errors.New("--json and --sarif require --ref")
	}
	if jsonPath == "" || sarifPath == "" {
		return nil
	}
	jsonDestination, err := oneShotDestination(jsonPath)
	if err != nil {
		return fmt.Errorf("JSON output directory: %w", err)
	}
	sarifDestination, err := oneShotDestination(sarifPath)
	if err != nil {
		return fmt.Errorf("SARIF output directory: %w", err)
	}
	if jsonDestination == sarifDestination {
		return errors.New("--json and --sarif require different output files")
	}
	return nil
}

func oneShotDestination(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

// Each requested output is atomic on its own. If a later output fails, earlier
// complete artifacts remain available, but the command does not claim success.
func completeOneShotScan(ctx context.Context, logger *slog.Logger, result *scanner.ScanResult, jsonPath, sarifPath string) error {
	if result == nil {
		return errors.New("scan result is unavailable")
	}
	if err := validateOneShotOutputs(result.ImageRef, jsonPath, sarifPath); err != nil {
		return err
	}
	if jsonPath != "" {
		if err := writeOneShotOutput(ctx, jsonPath, result); err != nil {
			return fmt.Errorf("JSON output: %w", err)
		}
	}
	if sarifPath != "" {
		if err := writeOneShotOutput(ctx, sarifPath, sarif.FromScanResult(version.Version, result)); err != nil {
			return fmt.Errorf("SARIF output: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	logger.Info("scan complete", "image", result.ImageRef, "packages", len(result.Packages), "findings", len(result.Findings))
	return nil
}

// Pin the existing caller-selected parent without changing its permissions.
// Reuse the private atomic writer so a failed encoding or write cannot truncate
// a prior report or follow its destination symlink.
func writeOneShotOutput(ctx context.Context, path string, value any) (resultErr error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	parent := filepath.Dir(absolute)
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	identity, err := root.Stat(".")
	if err != nil {
		return err
	}
	current := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := os.Stat(parent)
		if err != nil {
			return err
		}
		if !info.IsDir() || !os.SameFile(identity, info) {
			return errors.New("scan output directory changed")
		}
		return nil
	}
	if err := current(); err != nil {
		return err
	}
	_, err = securefiles.WriteStream(root, filepath.Base(absolute), 0o600, func(out io.Writer) error {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(value); err != nil {
			return err
		}
		return current()
	})
	if err != nil {
		return err
	}
	return current()
}
