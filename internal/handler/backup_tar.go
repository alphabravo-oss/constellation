// Tiny tar.gz extraction helper used by the Backups verify endpoint. Kept separate so
// the main backup.go file doesn't have to drag archive/tar imports.
package handler

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
)

// extractTarTriplet pulls up to three named files out of a gzipped-tar reader and returns
// their raw bytes. Files not present in the archive return nil byte slices (no error).
func extractTarTriplet(r io.Reader, a, b, c string) (aBytes, bBytes, cBytes []byte, err error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, nil, nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, nil, err
		}
		switch hdr.Name {
		case a:
			aBytes, _ = io.ReadAll(tr)
		case b:
			bBytes, _ = io.ReadAll(tr)
		case c:
			cBytes, _ = io.ReadAll(tr)
		}
	}
	return aBytes, bBytes, cBytes, nil
}
