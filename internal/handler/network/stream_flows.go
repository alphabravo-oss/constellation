package network

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/livegraph"
)

// StreamFlows is the streaming-HTTP fallback for the unimplemented gRPC
// StreamFlows server (plan B5). It emits each newly-ingested network flow for
// the caller's org as a Server-Sent Event so the network map can live-update
// without polling. Backed by the same in-memory pipeline that feeds the hot
// conversation graph; lossy under backpressure (the durable Postgres path
// remains the source of truth for anything dropped here).
type StreamFlows struct {
	live *livegraph.Store
}

// NewStreamFlows constructs the handler. live must be non-nil; the route is
// only registered when the live graph is enabled.
func NewStreamFlows(live *livegraph.Store) *StreamFlows { return &StreamFlows{live: live} }

// Stream handles GET /network/flows:stream as text/event-stream.
func (h *StreamFlows) Stream(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch, cancel := h.live.Subscribe(subj.OrgID)
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering (nginx)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Heartbeat keeps the connection (and any intermediary idle timeouts) alive
	// when no flows arrive.
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case f, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(f)
			if err != nil {
				continue
			}
			if _, err := w.Write([]byte("event: flow\ndata: ")); err != nil {
				return
			}
			if _, err := w.Write(b); err != nil {
				return
			}
			if _, err := w.Write([]byte("\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
