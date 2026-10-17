package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/securefiles"
)

var errPcapTooLarge = errors.New("pcap exceeds upload limit")

type stagedPcap struct {
	name   string
	size   int64
	sha256 string
}

func stagePcapUpload(root *os.Root, id uuid.UUID, body io.Reader) (stagedPcap, error) {
	staged := stagedPcap{name: ".upload-" + id.String() + "-" + uuid.NewString()}
	limited := &io.LimitedReader{R: body, N: maxPcapBytes + 1}
	hash := sha256.New()
	if err := securefiles.CopyFile(root, staged.name, io.TeeReader(limited, hash), 0o600); err != nil {
		return stagedPcap{}, err
	}
	staged.size = maxPcapBytes + 1 - limited.N
	if staged.size > maxPcapBytes {
		_ = root.Remove(staged.name)
		return stagedPcap{}, errPcapTooLarge
	}
	staged.sha256 = hex.EncodeToString(hash.Sum(nil))
	return staged, nil
}

func pcapFileName(id uuid.UUID) string { return id.String() + ".pcap" }

func publishPcapUpload(root *os.Root, staged stagedPcap, id uuid.UUID) error {
	name := pcapFileName(id)
	if info, err := root.Lstat(name); err == nil && !info.Mode().IsRegular() {
		return errors.New("pcap destination is not a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := root.Rename(staged.name, name); err != nil {
		return err
	}
	// The file was synced before rename. Persist the directory entry before a
	// completed database receipt can commit.
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func openPcapFile(root *os.Root, id uuid.UUID) (*os.File, error) {
	name := pcapFileName(id)
	expected, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !expected.Mode().IsRegular() {
		return nil, errors.New("pcap is not a regular file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	actual, err := file.Stat()
	if err != nil || !os.SameFile(expected, actual) {
		_ = file.Close()
		return nil, fmt.Errorf("pcap file changed while opening: %w", errors.Join(err, errors.New("identity mismatch")))
	}
	return file, nil
}

// Removing via a pinned private root never follows a replaced parent path.
// Missing stores are harmless; symlinked stores fail without touching targets.
func removePcapFile(id uuid.UUID) error {
	if _, err := os.Lstat(pcapDataDir()); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	root, err := securefiles.OpenPrivateDir(pcapDataDir())
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	err = root.Remove(pcapFileName(id))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

type pcapUploadFailure struct {
	status  int
	message string
}

func (h *PcapHTTP) uploadCapture(ctx context.Context, id, org, cluster uuid.UUID, body io.Reader) (*PcapCapture, *pcapUploadFailure) {
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return nil, &pcapUploadFailure{http.StatusInternalServerError, "upload database unavailable"}
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Ownership and running status are evaluated under the same lock held through
	// publication and commit. DELETE/sweep must acquire this row lock too.
	got, err := scanPcap(tx.QueryRow(ctx, `SELECT `+pcapCols+` FROM runtime_pcap_captures WHERE id=$1 AND org_id=$2 AND cluster_id=$3 FOR UPDATE`, id, org, cluster))
	if err != nil {
		return nil, &pcapUploadFailure{http.StatusNotFound, "not found"}
	}
	if got.Status != PcapStatusRunning {
		return nil, &pcapUploadFailure{http.StatusConflict, "capture not running (status=" + string(got.Status) + ")"}
	}
	if err = capturePlatformRolesWith(ctx, tx, org, []*PcapCapture{got}); err != nil {
		return nil, &pcapUploadFailure{http.StatusInternalServerError, "capture metadata unavailable"}
	}
	role := got.PlatformRole
	root, err := securefiles.OpenPrivateDir(pcapDataDir())
	if err != nil {
		return nil, &pcapUploadFailure{http.StatusInternalServerError, "pcap store unavailable"}
	}
	defer func() { _ = root.Close() }()
	staged, err := stagePcapUpload(root, id, body)
	if err != nil {
		return nil, pcapCopyFailure(err)
	}
	defer func() { _ = root.Remove(staged.name) }()
	// Required metadata is written before publication; failure preserves both the
	// prior complete file and the original running row.
	got, err = scanPcap(tx.QueryRow(ctx, `UPDATE runtime_pcap_captures SET status='completed',file_path=$1,file_size_bytes=$2,sha256=$3,completed_at=NOW() WHERE id=$4 AND org_id=$5 AND cluster_id=$6 RETURNING `+pcapCols, pcapFilePath(id), staged.size, staged.sha256, id, org, cluster))
	if err != nil {
		return nil, &pcapUploadFailure{http.StatusInternalServerError, "capture completion unavailable"}
	}
	if err = publishPcapUpload(root, staged, id); err != nil {
		return nil, &pcapUploadFailure{http.StatusInternalServerError, "pcap publication failed"}
	}
	if err = tx.Commit(ctx); err != nil {
		// A lost commit receipt may still have committed. Keep complete private bytes
		// rather than deleting an authoritative artifact; never return success.
		return nil, &pcapUploadFailure{http.StatusInternalServerError, "pcap completion could not be confirmed"}
	}
	got.PlatformRole = role
	return got, nil
}
func pcapCopyFailure(err error) *pcapUploadFailure {
	if errors.Is(err, errPcapTooLarge) {
		return &pcapUploadFailure{http.StatusRequestEntityTooLarge, "pcap exceeds upload limit"}
	}
	return &pcapUploadFailure{http.StatusBadRequest, "pcap upload could not be written"}
}
