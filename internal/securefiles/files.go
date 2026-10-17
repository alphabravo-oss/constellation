// Package securefiles writes confidential job artifacts beneath an explicitly
// configured directory. Root-relative atomic replacement never truncates a
// pre-existing symlink/hard link and does not follow a substituted parent path.
package securefiles

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// OpenPrivateDir creates or hardens a dedicated output directory and pins its
// identity for subsequent access. Callers must not use a filesystem/shared temp
// root as their managed output directory.
func OpenPrivateDir(dir string) (*os.Root, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	sharedTemp, err := filepath.Abs(os.TempDir())
	if err != nil {
		return nil, err
	}
	if absolute == filepath.VolumeName(absolute)+string(filepath.Separator) || absolute == sharedTemp {
		return nil, errors.New("use a dedicated private artifact directory")
	}
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("artifact directory must not be a symlink")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	err = hardenDirectory(root, info)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

// hardenDirectory checks the pinned descriptor before changing permissions, so
// a path swap cannot redirect chmod or retain another user's directory access.
func hardenDirectory(root *os.Root, expected os.FileInfo) (err error) {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(expected, opened) {
		return errors.New("artifact directory changed while opening")
	}
	if err = checkDirectoryOwner(opened); err != nil {
		return err
	}
	return file.Chmod(0o700)
}

// OpenPrivateSubdir creates a child of an already trusted root. Relative
// traversal and symlinks leaving that root are rejected by os.Root itself.
func OpenPrivateSubdir(parent *os.Root, name string) (*os.Root, error) {
	if !filepath.IsLocal(name) {
		return nil, errors.New("artifact directory must remain under the configured root")
	}
	if err := parent.MkdirAll(name, 0o700); err != nil {
		return nil, err
	}
	info, err := parent.Stat(name)
	if err != nil {
		return nil, err
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	if err = hardenDirectory(root, info); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

// WriteFile atomically replaces a single artifact. mode is 0600 for confidential
// evidence/private keys; explicitly public key material may use 0644.
func WriteFile(root *os.Root, name string, body []byte, mode os.FileMode) error {
	return CopyFile(root, name, bytes.NewReader(body), mode)
}

// CopyFile writes a stream without loading a large archive into memory.
func CopyFile(root *os.Root, name string, source io.Reader, mode os.FileMode) error {
	_, err := WriteStream(root, name, mode, func(destination io.Writer) error {
		_, err := io.Copy(destination, source)
		return err
	})
	return err
}

// WriteStream atomically publishes a completed stream and reports its file size.
// A callback or finalization failure preserves the prior artifact. The callback
// must finish all buffered writers before returning and must not retain writer.
func WriteStream(root *os.Root, name string, mode os.FileMode, produce func(io.Writer) error) (int64, error) {
	if !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." {
		return 0, errors.New("artifact name must be a single relative filename")
	}
	if mode != 0o600 && mode != 0o644 {
		return 0, errors.New("unsupported artifact permissions")
	}
	if produce == nil {
		return 0, errors.New("artifact stream producer is required")
	}
	if info, err := root.Lstat(name); err == nil && !info.Mode().IsRegular() {
		return 0, errors.New("artifact destination must be a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return 0, err
	}
	temporary := ".pending-" + hex.EncodeToString(token)
	file, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer func() { _ = root.Remove(temporary) }()
	err = produce(file)
	if err == nil {
		err = file.Chmod(mode)
	}
	if err == nil {
		err = file.Sync()
	}
	var size int64
	if err == nil {
		var info os.FileInfo
		info, err = file.Stat()
		if err == nil {
			size = info.Size()
		}
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return 0, err
	}
	if err = root.Rename(temporary, name); err != nil {
		return 0, fmt.Errorf("publish artifact: %w", err)
	}
	return size, nil
}
