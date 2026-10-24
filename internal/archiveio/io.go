// Package archiveio provides bounded archive parsing and verified private files.
package archiveio

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/securefiles"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

// Reader checks cancellation between reads. It cannot interrupt a blocked Read;
// callers must use regular local files or a transport with its own deadline.
type Reader struct {
	Context context.Context
	Input   io.Reader
}

func (r Reader) Read(p []byte) (int, error) {
	if err := r.Context.Err(); err != nil {
		return 0, err
	}
	n, err := r.Input.Read(p)
	if canceled := r.Context.Err(); canceled != nil {
		return 0, canceled
	}
	return n, err
}

// Decode rejects ambiguous object keys (including escaped aliases), invalid
// UTF-8, unknown fields, excessive nesting and trailing JSON values.
func Decode(raw []byte, dst any) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid archive UTF-8")
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	check.UseNumber()
	if err := uniqueValue(check, 0); err != nil {
		return err
	}
	if _, err := check.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing archive content")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func uniqueValue(dec *json.Decoder, depth int) error {
	if depth > 128 {
		return errors.New("archive nesting limit exceeded")
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		if err = uniqueObject(dec, depth); err != nil {
			return err
		}
	case '[':
		for dec.More() {
			if err = uniqueValue(dec, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected archive delimiter")
	}
	_, err = dec.Token()
	return err
}

func uniqueObject(dec *json.Decoder, depth int) error {
	seen := make(map[string]bool)
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return errors.New("duplicate or invalid archive key")
		}
		seen[name] = true
		if err = uniqueValue(dec, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// WriteVerified publishes a private uniquely named file, syncs its directory,
// and verifies both its exact bytes and caller-supplied signature contract from
// disk before returning a path. A failure never returns a successful receipt.
func WriteVerified(ctx context.Context, dir, suffix string, data []byte, verify func(io.Reader) error) (string, error) {
	if verify == nil || suffix == "" || len(suffix) > 64 || strings.ContainsAny(suffix, "/\\") {
		return "", errors.New("invalid archive output options")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	want := sha256.Sum256(data)
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	root, err := securefiles.OpenPrivateDir(absolute)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	name := uuid.NewString() + suffix
	if err = securefiles.CopyFile(root, name, Reader{ctx, bytes.NewReader(data)}, 0o600); err != nil {
		return "", err
	}
	directory, err := root.Open(".")
	if err != nil {
		return "", err
	}
	if err = errors.Join(directory.Sync(), directory.Close()); err != nil {
		return "", err
	}
	path := filepath.Join(absolute, name)
	if err = sameDirectory(root, absolute); err != nil {
		return "", err
	}
	file, err := backup.OpenArtifact(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	read := io.TeeReader(io.LimitReader(Reader{ctx, file}, int64(len(data))+1), hash)
	if err = verify(read); err != nil {
		return "", err
	}
	if _, err = io.Copy(io.Discard, read); err != nil {
		return "", err
	}
	if !bytes.Equal(hash.Sum(nil), want[:]) {
		return "", errors.New("archive read-back mismatch")
	}
	if err = sameDirectory(root, absolute); err != nil {
		return "", err
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	return path, nil
}

func sameDirectory(root *os.Root, path string) error {
	expected, err := root.Stat(".")
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !current.IsDir() || !os.SameFile(expected, current) {
		return errors.New("archive output directory changed")
	}
	return nil
}
