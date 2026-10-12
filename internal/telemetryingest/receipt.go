// Package telemetryingest implements ordered producer replay protection.
package telemetryingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const ProducerHeader = "X-Constellation-Producer"
const SequenceHeader = "X-Constellation-Sequence"
const AckHeader = "X-Constellation-Ack"

var ErrIdentity = errors.New("invalid telemetry producer identity or sequence")
var ErrConflict = errors.New("producer sequence reused with a different payload")
var ErrStale = errors.New("producer sequence is older than the durable cursor")

// Receipt belongs to the same transaction as the data rows. A producer must
// serialize delivery within each stream and keep its identity across restarts.
type Receipt struct {
	org, cluster, producer uuid.UUID
	stream                 string
	sequence               int64
	hash                   [32]byte
	enabled                bool
}

// Begin locks only this producer's cursor. Legacy agents without either header
// remain supported, without replay protection. Never derive scope from headers.
func Begin(ctx context.Context, tx pgx.Tx, r *http.Request, org, cluster uuid.UUID, stream string, payload any) (*Receipt, []byte, error) {
	p, s := r.Header.Get(ProducerHeader), r.Header.Get(SequenceHeader)
	receipt := &Receipt{org: org, cluster: cluster, stream: stream}
	if p == "" && s == "" {
		return receipt, nil, nil
	}
	id, err := uuid.Parse(p)
	if err != nil || id == uuid.Nil {
		return nil, nil, ErrIdentity
	}
	seq, err := strconv.ParseInt(s, 10, 64)
	if err != nil || seq <= 0 {
		return nil, nil, ErrIdentity
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	receipt.producer, receipt.sequence, receipt.hash, receipt.enabled = id, seq, sha256.Sum256(body), true
	// An insertion and the first batch commit together. Concurrent first uploads
	// wait on the unique constraint, then read the committed cursor below.
	tag, err := tx.Exec(ctx, `INSERT INTO telemetry_producers
 (org_id,cluster_id,stream,producer_id,sequence,payload_hash,response)
 VALUES ($1,$2,$3,$4,$5,$6,'{}') ON CONFLICT DO NOTHING`, org, cluster, stream, id, seq, receipt.hash[:])
	if err != nil {
		return nil, nil, err
	}
	if tag.RowsAffected() == 1 {
		return receipt, nil, nil
	}
	var previous int64
	var hash, response []byte
	err = tx.QueryRow(ctx, `SELECT sequence,payload_hash,response FROM telemetry_producers
 WHERE org_id=$1 AND cluster_id=$2 AND stream=$3 AND producer_id=$4 FOR UPDATE`, org, cluster, stream, id).Scan(&previous, &hash, &response)
	if err != nil {
		return nil, nil, err
	}
	if seq == previous && !bytes.Equal(hash, receipt.hash[:]) {
		return nil, nil, ErrConflict
	}
	if seq < previous {
		// Ordered workers can replay the latest batch only. Older sequences
		// indicate cloned/rolled-back producer state; without its old hash we
		// cannot safely acknowledge newly captured data under a reused sequence.
		return nil, nil, ErrStale
	}
	if seq == previous {
		return receipt, response, nil
	}
	return receipt, nil, nil
}

// Complete must precede tx.Commit. HTTP acknowledgement must follow commit.
func (r *Receipt) Complete(ctx context.Context, tx pgx.Tx, response any) error {
	if !r.enabled {
		return nil
	}
	body, err := json.Marshal(response)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE telemetry_producers SET sequence=$5,payload_hash=$6,response=$7,updated_at=now()
 WHERE org_id=$1 AND cluster_id=$2 AND stream=$3 AND producer_id=$4`, r.org, r.cluster, r.stream, r.producer, r.sequence, r.hash[:], body)
	return err
}

// Acknowledge proves the server supports durable receipts. Older servers returning
// 2xx without this header must not cause an upgraded agent to delete its spool.
func (r *Receipt) Acknowledge(w http.ResponseWriter) {
	if r.enabled {
		w.Header().Set(AckHeader, strconv.FormatInt(r.sequence, 10))
	}
}

// WriteError deliberately hides database errors from an agent.
func WriteError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, ErrIdentity) {
		status = http.StatusBadRequest
	}
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrStale) {
		status = http.StatusConflict
	}
	http.Error(w, http.StatusText(status), status)
}
