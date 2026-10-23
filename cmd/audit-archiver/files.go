package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

func readMetadata(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("archive metadata exceeds byte limit")
	}
	return b, nil
}
