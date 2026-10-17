package securefiles

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// WritePath atomically replaces an explicitly selected file with private bytes.
// It requires an existing parent and does not change that directory's mode.
func WritePath(ctx context.Context, path string, body []byte) error {
	return WritePathStream(ctx, path, func(out io.Writer) error {
		_, err := io.Copy(out, bytes.NewReader(body))
		return err
	})
}

// WritePathStream pins the selected parent and delegates publication to
// WriteStream. Observed parent changes fail before publication, or report an
// uncertain pathname after publication while retaining the completed file.
// These checks do not lock the pathname: a rename between a check and publication
// can still occur, but writes remain confined to the pinned directory.
func WritePathStream(ctx context.Context, path string, produce func(io.Writer) error) (resultErr error) {
	if ctx == nil || produce == nil {
		return errors.New("artifact context and producer are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if path == "" || strings.HasSuffix(path, string(os.PathSeparator)) {
		return errors.New("artifact destination must name a file")
	}
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
	current := func() error { return currentPathParent(parent, identity) }
	if err := current(); err != nil {
		return err
	}
	_, err = WriteStream(root, filepath.Base(absolute), 0o600, func(out io.Writer) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := produce(out); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return current()
	})
	if err != nil {
		return err
	}
	return current()
}

func currentPathParent(path string, identity os.FileInfo) error {
	current, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !current.IsDir() || !os.SameFile(current, identity) {
		return errors.New("artifact parent changed; inspect the original directory")
	}
	return nil
}
