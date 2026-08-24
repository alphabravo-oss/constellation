// Wave C3: PCAP capture orchestration.
//
// Three audiences, three endpoint groups:
//
//	Operator (user JWT):
//	  POST   /api/v1/runtime-pcap/start          start a capture
//	  GET    /api/v1/runtime-pcap                list captures
//	  GET    /api/v1/runtime-pcap/{id}           get one
//	  GET    /api/v1/runtime-pcap/{id}/download  download the .pcap (200/404)
//	  DELETE /api/v1/runtime-pcap/{id}           cancel/remove
//
//	Runtime-agent (runtime-agent token):
//	  GET    /api/v1/runtime-pcap/claim          claim the next pending
//	  POST   /api/v1/runtime-pcap/{id}/upload    multipart upload of the .pcap
//	  POST   /api/v1/runtime-pcap/{id}/status    report status (running|completed|failed)
//
// Storage: pcap files land in `<DataDir>/pcaps/<id>.pcap`. Default DataDir
// is /var/lib/constellation; override via CONSTELLATION_DATA_DIR (matches
// the existing convention used by exporter / sign paths).
//
// Size cap: 100 MB per pcap, enforced by http.MaxBytesReader on upload.
// Duration cap: 60s per capture, enforced server-side.
package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// PcapCaptureStatus mirrors the CHECK constraint.
type PcapCaptureStatus string

const (
	PcapStatusPending   PcapCaptureStatus = "pending"
	PcapStatusRunning   PcapCaptureStatus = "running"
	PcapStatusCompleted PcapCaptureStatus = "completed"
	PcapStatusFailed    PcapCaptureStatus = "failed"
	PcapStatusExpired   PcapCaptureStatus = "expired"
)

const (
	// minPcapDuration avoids effectively-empty captures while still letting
	// threat drilldowns request short samples.
	minPcapDuration = 5
	// maxPcapDuration is the cap on a single capture's tcpdump runtime.
	// 300s exposes the agent's existing rolling/sniffer capability without
	// turning the worker into a long-running packet collector.
	maxPcapDuration = 300
	// maxPcapBytes caps the uploaded file. 100 MB is generous for 60s of
	// a busy pod's traffic; oversize uploads return 413.
	maxPcapBytes = 100 << 20
	// maxPcapFiles and maxPcapFileSizeMB mirror the runtime-agent's rolling
	// capture guardrails so queued requests reflect what the agent can run.
	maxPcapFiles        = 20
	maxPcapFileSizeMB   = 100
	defaultPcapFileMB   = 10
	maxPcapBPFFilterLen = 1024
)

// PcapCapture is one row in runtime_pcap_captures.
type PcapCapture struct {
	ID            uuid.UUID         `json:"id"`
	OrgID         uuid.UUID         `json:"org_id"`
	ClusterID     uuid.UUID         `json:"cluster_id"`
	Workload      string            `json:"workload"`
	Namespace     string            `json:"namespace"`
	RequestedBy   uuid.UUID         `json:"requested_by"`
	RequestedAt   time.Time         `json:"requested_at"`
	DurationS     int16             `json:"duration_s"`
	SrcIP         string            `json:"src_ip,omitempty"`
	DstIP         string            `json:"dst_ip,omitempty"`
	DstPort       int               `json:"dst_port,omitempty"`
	Protocol      string            `json:"protocol,omitempty"`
	BPFFilter     string            `json:"bpf_filter,omitempty"`
	Interface     string            `json:"interface,omitempty"`
	FileCount     int               `json:"file_count,omitempty"`
	FileSizeMB    int               `json:"file_size_mb,omitempty"`
	Status        PcapCaptureStatus `json:"status"`
	ClaimedByNode string            `json:"claimed_by_node,omitempty"`
	ClaimedAt     *time.Time        `json:"claimed_at,omitempty"`
	CompletedAt   *time.Time        `json:"completed_at,omitempty"`
	ErrorMessage  string            `json:"error_message,omitempty"`
	FileSizeBytes int64             `json:"file_size_bytes,omitempty"`
	SHA256        string            `json:"sha256,omitempty"`
	PacketCount   int64             `json:"packet_count,omitempty"`
	ExpiresAt     time.Time         `json:"expires_at"`
}

// pcapDataDir is the on-disk root for stored .pcap files. Read at first
// use; defaults to /var/lib/constellation/pcaps. The directory is created
// lazily on the first successful upload.
func pcapDataDir() string {
	root := strings.TrimSpace(os.Getenv("CONSTELLATION_DATA_DIR"))
	if root == "" {
		root = "/var/lib/constellation"
	}
	return filepath.Join(root, "pcaps")
}

// pcapFilePath is the canonical on-disk path for one capture id.
func pcapFilePath(id uuid.UUID) string {
	return filepath.Join(pcapDataDir(), id.String()+".pcap")
}

// PcapHTTP wraps the DB + the on-disk store with HTTP handlers.
type PcapHTTP struct {
	db *db.DB
}

func NewPcapHTTP(d *db.DB) *PcapHTTP { return &PcapHTTP{db: d} }

// StartCaptureRequest is the operator's POST body. The 5-tuple fields are
// optional — leave them empty for a "capture everything on the workload's
// veth for N seconds" sample.
type StartCaptureRequest struct {
	ClusterID  uuid.UUID `json:"cluster_id"`
	Workload   string    `json:"workload"`
	Namespace  string    `json:"namespace,omitempty"`
	DurationS  int       `json:"duration_s,omitempty"`
	SrcIP      string    `json:"src_ip,omitempty"`
	DstIP      string    `json:"dst_ip,omitempty"`
	DstPort    int       `json:"dst_port,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	BPFFilter  string    `json:"bpf_filter,omitempty"`
	Interface  string    `json:"interface,omitempty"`
	FileCount  int       `json:"file_count,omitempty"`
	FileSizeMB int       `json:"file_size_mb,omitempty"`
}

// Start handles POST /api/v1/runtime-pcap/start.
func (h *PcapHTTP) Start(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var req StartCaptureRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	req, err := normalizeStartCaptureRequest(req)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ClusterID == uuid.Nil || req.Workload == "" {
		jsonError(w, http.StatusBadRequest, "cluster_id and workload are required")
		return
	}
	ns := req.Namespace
	if ns == "" {
		ns = namespaceOf(req.Workload)
	}
	var id uuid.UUID
	err = h.db.Pool().QueryRow(r.Context(), `
INSERT INTO runtime_pcap_captures
  (org_id, cluster_id, workload, namespace, requested_by, duration_s,
   src_ip, dst_ip, dst_port, protocol, bpf_filter, capture_interface, file_count, file_size_mb)
VALUES ($1,$2,$3,$4,$5,$6,
        NULLIF($7,'')::inet, NULLIF($8,'')::inet, NULLIF($9,0), NULLIF($10,''),
        NULLIF($11,''), NULLIF($12,''), NULLIF($13,0), NULLIF($14,0))
RETURNING id`,
		sub.OrgID, req.ClusterID, req.Workload, ns, sub.UserID, int16(req.DurationS),
		req.SrcIP, req.DstIP, req.DstPort, req.Protocol,
		req.BPFFilter, req.Interface, req.FileCount, req.FileSizeMB).Scan(&id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	got, _ := h.getByID(r.Context(), sub.OrgID, id)
	httpx.WriteJSON(w, http.StatusCreated, got)
}

// List handles GET /api/v1/runtime-pcap.
// Filter by ?cluster_id=&workload=&group=&status=&protocol=&src_ip=&dst_ip=&dst_port=
// (any field optional).
func (h *PcapHTTP) List(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	q := r.URL.Query()
	clusterID := strings.TrimSpace(q.Get("cluster_id"))
	workload := strings.TrimSpace(q.Get("workload"))
	status, err := normalizePcapStatus(q.Get("status"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	protocol, err := normalizePcapProtocol(q.Get("protocol"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	srcIP, err := normalizeOptionalPcapIP("src_ip", q.Get("src_ip"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	dstIP, err := normalizeOptionalPcapIP("dst_ip", q.Get("dst_ip"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	dstPort, err := parsePcapPortQuery(q.Get("dst_port"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var clusterUUID *uuid.UUID
	if clusterID != "" {
		if parsed, err := uuid.Parse(clusterID); err == nil {
			clusterUUID = &parsed
		}
	}
	groupMembers, groupName, groupActive, err := handler.ResolveGroupFilterMembers(r.Context(), h.db.Pool(), sub.OrgID, clusterUUID, q.Get("group"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT `+pcapCols+` FROM runtime_pcap_captures
 WHERE org_id = $1
   AND ($2::text = '' OR cluster_id::text = $2)
   AND ($3::text = '' OR workload = $3)
   AND ($4::text = '' OR status = $4)
   AND ($5::text = '' OR protocol = $5)
	   AND ($6::text = '' OR host(src_ip) = $6)
	   AND ($7::text = '' OR host(dst_ip) = $7)
	   AND ($8::int = 0 OR dst_port = $8)
	   AND (NOT $9::boolean OR workload = ANY($10::text[]))
 ORDER BY requested_at DESC
 LIMIT 200`,
		sub.OrgID, clusterID, workload, status, protocol, srcIP, dstIP, dstPort, groupActive, groupMembers)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := make([]*PcapCapture, 0, 16)
	for rows.Next() {
		c, err := scanPcap(rows)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, c)
	}
	response := map[string]any{"captures": out}
	if groupActive {
		response["selected_group"] = groupName
		response["selected_group_members"] = len(groupMembers)
	}
	httpx.WriteJSON(w, http.StatusOK, response)
}

// Get handles GET /api/v1/runtime-pcap/{id}.
func (h *PcapHTTP) Get(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id, err := uuid.Parse(pathTail(r.URL.Path))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	got, err := h.getByID(r.Context(), sub.OrgID, id)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, got)
}

// Download streams the .pcap file. The caller's browser tags it with the
// capture id as the filename so a user with multiple downloads doesn't
// get a folder full of "pcap.pcap".
func (h *PcapHTTP) Download(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[len(parts)-1] != "download" {
		jsonError(w, http.StatusBadRequest, "invalid path")
		return
	}
	id, err := uuid.Parse(parts[len(parts)-2])
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	got, err := h.getByID(r.Context(), sub.OrgID, id)
	if err != nil || got == nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if got.Status != PcapStatusCompleted {
		jsonError(w, http.StatusConflict, "capture not completed yet (status="+string(got.Status)+")")
		return
	}
	f, err := os.Open(pcapFilePath(id))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "pcap file missing on server: "+err.Error())
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="`+id.String()+`.pcap"`)
	if got.FileSizeBytes > 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", got.FileSizeBytes))
	}
	_, _ = io.Copy(w, f)
}

// Delete handles DELETE /api/v1/runtime-pcap/{id}. Removes both row and file.
func (h *PcapHTTP) Delete(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id, err := uuid.Parse(pathTail(r.URL.Path))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	tag, err := h.db.Pool().Exec(r.Context(),
		`DELETE FROM runtime_pcap_captures WHERE id=$1 AND org_id=$2`, id, sub.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	// Best-effort file removal — log if it fails, don't break the row delete.
	if rmErr := os.Remove(pcapFilePath(id)); rmErr != nil && !os.IsNotExist(rmErr) {
		slog.Default().Warn("pcap file remove",
			slog.String("id", id.String()), slog.String("err", rmErr.Error()))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// ----- agent endpoints -------------------------------------------------------

// Claim handles GET /api/v1/runtime-pcap/claim?cluster_id=... — the agent
// asks for the next pending capture in its cluster, atomically marks it
// running. Returns 204 (no content) when there's nothing to do.
//
// Race safety: SELECT … FOR UPDATE SKIP LOCKED so two agents on the same
// cluster don't claim the same row. The handler's caller is the agent
// itself (runtime-agent token); we record claimed_by_node + claimed_at.
func (h *PcapHTTP) Claim(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	clusterID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "cluster_id required")
		return
	}
	node := strings.TrimSpace(r.URL.Query().Get("node"))
	if node == "" {
		jsonError(w, http.StatusBadRequest, "node required")
		return
	}
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var id uuid.UUID
	err = tx.QueryRow(r.Context(), `
SELECT id FROM runtime_pcap_captures
 WHERE org_id = $1 AND cluster_id = $2 AND status = 'pending'
 ORDER BY requested_at
 LIMIT 1
   FOR UPDATE SKIP LOCKED`,
		tok.OrgID, clusterID).Scan(&id)
	if err != nil {
		// pgx returns ErrNoRows when no pending row is available — that's
		// the empty-queue case, not an error.
		if strings.Contains(err.Error(), "no rows") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := tx.Exec(r.Context(), `
UPDATE runtime_pcap_captures
   SET status = 'running', claimed_by_node = $1, claimed_at = NOW()
 WHERE id = $2`,
		node, id); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	got, _ := h.getByID(r.Context(), tok.OrgID, id)
	httpx.WriteJSON(w, http.StatusOK, got)
}

// Upload accepts the multipart .pcap body from the runtime-agent. Caps at
// maxPcapBytes via http.MaxBytesReader; writes to <DataDir>/pcaps/<id>.pcap
// atomically (write to <id>.pcap.partial, then rename).
func (h *PcapHTTP) Upload(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[len(parts)-1] != "upload" {
		jsonError(w, http.StatusBadRequest, "invalid path")
		return
	}
	id, err := uuid.Parse(parts[len(parts)-2])
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPcapBytes+1024)

	// Verify the capture belongs to this org + is in running state.
	got, err := h.getByID(r.Context(), tok.OrgID, id)
	if err != nil || got == nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if got.Status != PcapStatusRunning {
		jsonError(w, http.StatusConflict,
			"capture not running (status="+string(got.Status)+")")
		return
	}

	if err := os.MkdirAll(pcapDataDir(), 0o755); err != nil {
		jsonError(w, http.StatusInternalServerError, "mkdir: "+err.Error())
		return
	}
	path := pcapFilePath(id)
	tmp := path + ".partial"
	f, err := os.Create(tmp)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "create: "+err.Error())
		return
	}
	hasher := sha256.New()
	mw := io.MultiWriter(f, hasher)
	written, copyErr := io.Copy(mw, r.Body)
	_ = f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		jsonError(w, http.StatusBadRequest, "upload: "+copyErr.Error())
		return
	}
	if written > maxPcapBytes {
		_ = os.Remove(tmp)
		jsonError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("pcap %d bytes > limit %d", written, maxPcapBytes))
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		jsonError(w, http.StatusInternalServerError, "rename: "+err.Error())
		return
	}
	sum := hex.EncodeToString(hasher.Sum(nil))

	// Stamp the row.
	if _, err := h.db.Pool().Exec(r.Context(), `
UPDATE runtime_pcap_captures
   SET status = 'completed',
       file_path = $1,
       file_size_bytes = $2,
       sha256 = $3,
       completed_at = NOW()
 WHERE id = $4 AND org_id = $5`,
		path, written, sum, id, tok.OrgID); err != nil {
		jsonError(w, http.StatusInternalServerError, "update: "+err.Error())
		return
	}
	got, _ = h.getByID(r.Context(), tok.OrgID, id)
	httpx.WriteJSON(w, http.StatusOK, got)
}

// StatusUpdate accepts agent-side status changes other than upload (eg.
// "I started running" → running stamped via claim; "I failed" → failed
// with error_message).
type AgentStatusUpdate struct {
	Status       PcapCaptureStatus `json:"status"`
	ErrorMessage string            `json:"error_message,omitempty"`
	PacketCount  int64             `json:"packet_count,omitempty"`
}

// UpdateStatus handles POST /api/v1/runtime-pcap/{id}/status.
func (h *PcapHTTP) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[len(parts)-1] != "status" {
		jsonError(w, http.StatusBadRequest, "invalid path")
		return
	}
	id, err := uuid.Parse(parts[len(parts)-2])
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req AgentStatusUpdate
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	switch req.Status {
	case PcapStatusRunning, PcapStatusFailed, PcapStatusCompleted:
		// fine — note completed-via-status is rare (upload sets it
		// automatically); we allow it for agents that complete with zero bytes.
	default:
		jsonError(w, http.StatusBadRequest, "invalid status: "+string(req.Status))
		return
	}
	completedAtClause := ""
	if req.Status == PcapStatusCompleted || req.Status == PcapStatusFailed {
		completedAtClause = ", completed_at = NOW()"
	}
	if _, err := h.db.Pool().Exec(r.Context(), `
UPDATE runtime_pcap_captures
   SET status = $1, error_message = $2, packet_count = COALESCE(NULLIF($3,0::bigint), packet_count)`+completedAtClause+`
 WHERE id = $4 AND org_id = $5`,
		string(req.Status), req.ErrorMessage, req.PacketCount, id, tok.OrgID); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	got, _ := h.getByID(r.Context(), tok.OrgID, id)
	httpx.WriteJSON(w, http.StatusOK, got)
}

// ----- shared helpers --------------------------------------------------------

const pcapCols = `id, org_id, cluster_id, workload, namespace, requested_by,
                  requested_at, duration_s,
                  COALESCE(host(src_ip),''), COALESCE(host(dst_ip),''),
                  COALESCE(dst_port,0), COALESCE(protocol,''),
                  COALESCE(bpf_filter,''), COALESCE(capture_interface,''),
                  COALESCE(file_count,0), COALESCE(file_size_mb,0),
                  status, COALESCE(claimed_by_node,''), claimed_at,
                  completed_at, COALESCE(error_message,''),
                  COALESCE(file_size_bytes,0), COALESCE(file_path,''),
                  COALESCE(sha256,''), COALESCE(packet_count,0),
                  expires_at`

func scanPcap(s rowScanner) (*PcapCapture, error) {
	var c PcapCapture
	var status string
	if err := s.Scan(
		&c.ID, &c.OrgID, &c.ClusterID, &c.Workload, &c.Namespace, &c.RequestedBy,
		&c.RequestedAt, &c.DurationS,
		&c.SrcIP, &c.DstIP, &c.DstPort, &c.Protocol,
		&c.BPFFilter, &c.Interface, &c.FileCount, &c.FileSizeMB,
		&status, &c.ClaimedByNode, &c.ClaimedAt,
		&c.CompletedAt, &c.ErrorMessage,
		&c.FileSizeBytes, ignoreField(),
		&c.SHA256, &c.PacketCount,
		&c.ExpiresAt,
	); err != nil {
		return nil, err
	}
	c.Status = PcapCaptureStatus(status)
	return &c, nil
}

// ignoreField returns a discard pointer so we can SELECT file_path for the
// completeness of the column list without exposing the server's local path
// to the JSON response.
func ignoreField() any {
	var s string
	return &s
}

func (h *PcapHTTP) getByID(ctx context.Context, orgID, id uuid.UUID) (*PcapCapture, error) {
	row := h.db.Pool().QueryRow(ctx,
		`SELECT `+pcapCols+` FROM runtime_pcap_captures WHERE id = $1 AND org_id = $2`,
		id, orgID)
	return scanPcap(row)
}

// SweepExpired removes captures past their expires_at + the on-disk file.
// Called by the server's background reaper (set up next to the rollback
// watcher). Errors logged + counted; one bad row doesn't stop the sweep.
func (h *PcapHTTP) SweepExpired(ctx context.Context, logger *slog.Logger) (int, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT id FROM runtime_pcap_captures WHERE expires_at < NOW()`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	ids := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		_ = os.Remove(pcapFilePath(id))
	}
	if len(ids) == 0 {
		return 0, nil
	}
	if _, err := h.db.Pool().Exec(ctx,
		`DELETE FROM runtime_pcap_captures WHERE id = ANY($1::uuid[])`,
		ids); err != nil {
		return 0, err
	}
	if logger != nil {
		logger.Info("pcap sweep", slog.Int("removed", len(ids)))
	}
	return len(ids), nil
}

func normalizeStartCaptureRequest(req StartCaptureRequest) (StartCaptureRequest, error) {
	req.Workload = strings.TrimSpace(req.Workload)
	req.Namespace = strings.TrimSpace(req.Namespace)
	if req.ClusterID == uuid.Nil || req.Workload == "" {
		return req, nil
	}
	if req.DurationS <= 0 {
		req.DurationS = 30
	}
	if req.DurationS < minPcapDuration {
		req.DurationS = minPcapDuration
	}
	if req.DurationS > maxPcapDuration {
		req.DurationS = maxPcapDuration
	}
	protocol, err := normalizePcapProtocol(req.Protocol)
	if err != nil {
		return req, err
	}
	req.Protocol = protocol
	if req.SrcIP, err = normalizeOptionalPcapIP("src_ip", req.SrcIP); err != nil {
		return req, err
	}
	if req.DstIP, err = normalizeOptionalPcapIP("dst_ip", req.DstIP); err != nil {
		return req, err
	}
	if req.DstPort < 0 || req.DstPort > 65535 {
		return req, fmt.Errorf("dst_port must be between 1 and 65535")
	}
	req.BPFFilter = strings.TrimSpace(req.BPFFilter)
	if err := validatePcapBPFFilterForStorage(req.BPFFilter); err != nil {
		return req, err
	}
	req.Interface = strings.TrimSpace(req.Interface)
	if req.Interface != "" && !validPcapInterfaceName(req.Interface) {
		return req, fmt.Errorf("interface must be a Linux interface name up to 15 characters")
	}
	if req.FileCount <= 0 {
		req.FileCount = 1
	}
	if req.FileCount > maxPcapFiles {
		req.FileCount = maxPcapFiles
	}
	if req.FileCount <= 1 {
		req.FileCount = 1
		req.FileSizeMB = 0
		return req, nil
	}
	if req.FileSizeMB <= 0 {
		req.FileSizeMB = defaultPcapFileMB
	}
	if req.FileSizeMB > maxPcapFileSizeMB {
		req.FileSizeMB = maxPcapFileSizeMB
	}
	if req.FileSizeMB*req.FileCount > maxPcapFileSizeMB {
		req.FileSizeMB = maxPcapFileSizeMB / req.FileCount
		if req.FileSizeMB < 1 {
			req.FileSizeMB = 1
		}
	}
	return req, nil
}

func normalizePcapStatus(value string) (string, error) {
	status := strings.TrimSpace(strings.ToLower(value))
	switch PcapCaptureStatus(status) {
	case "", PcapStatusPending, PcapStatusRunning, PcapStatusCompleted, PcapStatusFailed, PcapStatusExpired:
		return status, nil
	default:
		return "", fmt.Errorf("status must be pending, running, completed, failed, or expired")
	}
}

func normalizePcapProtocol(value string) (string, error) {
	protocol := strings.TrimSpace(strings.ToLower(value))
	switch protocol {
	case "", "tcp", "udp", "icmp":
		return protocol, nil
	default:
		return "", fmt.Errorf("protocol must be tcp, udp, or icmp")
	}
}

func normalizeOptionalPcapIP(field, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	normalized, ok := normalizeIP(value)
	if !ok {
		return "", fmt.Errorf("%s must be a valid IP address", field)
	}
	return normalized, nil
}

func parsePcapPortQuery(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("dst_port must be between 1 and 65535")
	}
	return port, nil
}

func validatePcapBPFFilterForStorage(filter string) error {
	if filter == "" {
		return nil
	}
	if len(filter) > maxPcapBPFFilterLen {
		return fmt.Errorf("bpf_filter is too long (%d bytes, max %d)", len(filter), maxPcapBPFFilterLen)
	}
	for _, r := range filter {
		if !isPcapBPFRune(r) {
			return fmt.Errorf("bpf_filter contains illegal character %q", r)
		}
	}
	return nil
}

func isPcapBPFRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == ' ' || r == '\t':
		return true
	}
	return strings.ContainsRune(".:/()[]<>=!&|+-*%", r)
}

func validPcapInterfaceName(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == '@':
		default:
			return false
		}
	}
	return true
}
