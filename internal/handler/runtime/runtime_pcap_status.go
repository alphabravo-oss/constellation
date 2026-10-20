package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/google/uuid"
)

var errPcapTerminalStatus = errors.New("capture is terminal")

func (h *PcapHTTP) setPcapStatus(ctx context.Context, org, cluster, id uuid.UUID, req AgentStatusUpdate) (*PcapCapture, error) {
	if req.Status != PcapStatusRunning && req.Status != PcapStatusFailed {
		return nil, errPcapTerminalStatus
	}
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	got, err := scanPcap(tx.QueryRow(ctx, `SELECT `+pcapCols+` FROM runtime_pcap_captures WHERE id=$1 AND org_id=$2 AND cluster_id=$3 FOR UPDATE`, id, org, cluster))
	if err != nil {
		return nil, err
	}
	// An upload can have committed even when its HTTP response was lost. The
	// worker's failure notification must not downgrade that durable receipt.
	if got.Status == PcapStatusCompleted {
		return nil, errPcapTerminalStatus
	}
	if (got.Status == PcapStatusFailed || got.Status == PcapStatusExpired) && req.Status == PcapStatusRunning {
		return nil, errPcapTerminalStatus
	}
	if err = capturePlatformRolesWith(ctx, tx, org, []*PcapCapture{got}); err != nil {
		return nil, err
	}
	if got.Status == PcapStatusFailed || got.Status == PcapStatusExpired {
		return got, nil
	}
	role := got.PlatformRole
	got, err = scanPcap(tx.QueryRow(ctx, `UPDATE runtime_pcap_captures SET status=$1,error_message=$2,packet_count=COALESCE(NULLIF($3,0::bigint),packet_count),completed_at=CASE WHEN $1='failed' THEN NOW() ELSE completed_at END WHERE id=$4 AND org_id=$5 AND cluster_id=$6 RETURNING `+pcapCols, string(req.Status), req.ErrorMessage, req.PacketCount, id, org, cluster))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	got.PlatformRole = role
	return got, nil
}

// Old completed rows could be authored by status-only calls. A completed label
// alone is not proof of a file: check the actual private bytes against the
// upload's stored size and SHA256 before writing any download headers/body.
func openVerifiedPcap(root *os.Root, capture *PcapCapture) (*os.File, error) {
	expected, err := hex.DecodeString(capture.SHA256)
	if err != nil || len(expected) != sha256.Size {
		return nil, errors.New("capture has no verified upload digest")
	}
	file, err := openPcapFile(root, capture.ID)
	if err != nil {
		return nil, err
	}
	if err = verifyPcapBytes(file, capture); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
func verifyPcapBytes(file *os.File, capture *PcapCapture) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() != capture.FileSizeBytes || info.Size() > maxPcapBytes {
		return errors.New("capture size does not match upload receipt")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, io.LimitReader(file, maxPcapBytes+1))
	if copyErr != nil {
		return copyErr
	}
	if written != capture.FileSizeBytes {
		return errors.New("capture bytes changed during verification")
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), capture.SHA256) {
		return errors.New("capture digest does not match upload receipt")
	}
	_, err = file.Seek(0, io.SeekStart)
	return err
}
