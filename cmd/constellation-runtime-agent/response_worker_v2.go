package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type processResponseWorker struct {
	APIBaseURL, Token, ClusterID, Node string
	Client                             *http.Client
	Logger                             *slog.Logger
	Responder                          *responder
	Journal                            *responseJournal
}

func newProcessResponseWorker(base, token, cluster, node string, r *responder, logger *slog.Logger) (*processResponseWorker, error) {
	origin, err := processControlPlaneOrigin(base)
	if err != nil {
		return nil, err
	}
	base = origin.String()
	directory := os.Getenv("CONSTELLATION_TELEMETRY_SPOOL_DIR")
	if directory == "" {
		directory = "/var/lib/constellation/telemetry"
	}
	tokenID := sha256.Sum256([]byte(token))
	scope := strings.TrimRight(base, "/") + "|" + cluster + "|" + node + "|" + hex.EncodeToString(tokenID[:])
	journal, err := openResponseJournal(filepath.Join(directory, "response-actions-v2"), scope)
	if err != nil {
		return nil, err
	}
	return &processResponseWorker{APIBaseURL: strings.TrimRight(base, "/"), Token: token, ClusterID: cluster, Node: node, Client: &http.Client{Timeout: 10 * time.Second}, Logger: logger, Responder: r, Journal: journal}, nil
}

func (w *processResponseWorker) Run(ctx context.Context) {
	defer func() { _ = w.Journal.Close() }()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			w.pollOnce(ctx)
			timer.Reset(15 * time.Second)
		}
	}
}

func (w *processResponseWorker) pollOnce(ctx context.Context) {
	// Persisted results always drain before new effects. Prepared intent after a
	// crash means unknown outcome; never risk signaling the same request again.
	if err := w.drain(ctx); err != nil {
		w.Logger.Warn("process response delivery deferred", "error", err.Error())
		return
	}
	actions, err := w.fetch(ctx)
	if err != nil {
		w.Logger.Debug("process response fetch deferred", "error", err.Error())
		return
	}
	for _, a := range actions {
		if ctx.Err() != nil {
			return
		}
		fresh, err := w.Journal.Prepare(a)
		if err != nil {
			w.Logger.Error("process response preparation failed", "error", err.Error())
			return
		}
		if !fresh {
			continue
		}
		if ctx.Err() != nil {
			return // Durable intent remains uncertain; never signal after cancellation.
		}
		result := w.Responder.ExecuteProcessV2(a)
		if err := w.Journal.Complete(a, result); err != nil {
			w.Logger.Error("process response outcome persistence failed; no retry of effect", "error", err.Error())
			return
		}
	}
	if err := w.drain(ctx); err != nil {
		w.Logger.Warn("process response delivery deferred", "error", err.Error())
	}
}

func (w *processResponseWorker) drain(ctx context.Context) error {
	for _, entry := range w.Journal.Entries() {
		result := entry.Result
		if result == nil {
			uncertain := processResultV2{Version: 2, ID: entry.Action.ID, ActionToken: entry.Action.ActionToken, Type: entry.Action.Type, Node: entry.Action.Node, Outcome: "uncertain", Reason: "execution outcome unknown after interrupted execution; effect not retried", At: time.Now().UTC()}
			if err := w.Journal.Complete(entry.Action, uncertain); err != nil {
				return err
			}
			result = &uncertain
		}
		if err := w.report(ctx, entry.Action, *result); err != nil {
			return err
		}
		if err := w.Journal.Forget(entry.Action.ID); err != nil {
			return err
		}
	}
	return nil
}

func (w *processResponseWorker) request(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	origin, err := processControlPlaneOrigin(w.APIBaseURL)
	if err != nil {
		return nil, err
	}
	relative, err := url.ParseRequestURI(path)
	if err != nil || relative.IsAbs() || !strings.HasPrefix(relative.Path, "/api/v1/runtime/response-actions/v2/") {
		return nil, errors.New("invalid process control-plane path")
	}
	req, err := http.NewRequestWithContext(ctx, method, origin.ResolveReference(relative).String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := *w.Client
	// An authenticated process request never follows an origin-changing redirect.
	// Treat all redirects as responses; fixed API routes require no redirect.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client.Do(req)
}

func (w *processResponseWorker) fetch(ctx context.Context) ([]processActionV2, error) {
	query := url.Values{"cluster_id": {w.ClusterID}, "node": {w.Node}}
	response, err := w.request(ctx, http.MethodGet, "/api/v1/runtime/response-actions/v2/pending?"+query.Encode(), nil)
	if err != nil {
		return nil, errors.New("process request unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("process request HTTP %d", response.StatusCode)
	}
	var envelope struct {
		Version   int               `json:"protocol_version"`
		ClusterID string            `json:"cluster_id"`
		Node      string            `json:"node"`
		Actions   []processActionV2 `json:"actions"`
	}
	if err := decodeProcessResponse(response.Body, 1<<20, &envelope); err != nil {
		return nil, err
	}
	if envelope.Version != 2 || envelope.ClusterID != w.ClusterID || envelope.Node != w.Node || envelope.Actions == nil || len(envelope.Actions) > 100 {
		return nil, errors.New("process request scope mismatch")
	}
	seen := map[string]bool{}
	for _, a := range envelope.Actions {
		if validateProcessAction(a) != nil || a.Node != w.Node || seen[a.ID] {
			return nil, errors.New("invalid process action envelope")
		}
		seen[a.ID] = true
	}
	return envelope.Actions, nil
}

func (w *processResponseWorker) report(ctx context.Context, a processActionV2, result processResultV2) error {
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	response, err := w.request(ctx, http.MethodPost, "/api/v1/runtime/response-actions/v2/result", body)
	if err != nil {
		return errors.New("process result unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != 200 {
		return fmt.Errorf("process result HTTP %d", response.StatusCode)
	}
	var receipt struct {
		Acknowledged bool   `json:"acknowledged"`
		Version      int    `json:"protocol_version"`
		ID           string `json:"id"`
		ActionToken  string `json:"action_token"`
		Node         string `json:"node"`
		Outcome      string `json:"outcome"`
		State        string `json:"state"`
	}
	if err := decodeProcessResponse(response.Body, 1<<16, &receipt); err != nil {
		return err
	}
	state := "failed"
	if result.Outcome == "applied" {
		state = "done"
	}
	if result.Outcome == "uncertain" {
		state = "uncertain"
	}
	if !receipt.Acknowledged || receipt.Version != 2 || receipt.ID != a.ID || receipt.ActionToken != a.ActionToken || receipt.Node != a.Node || receipt.Outcome != result.Outcome || receipt.State != state {
		return errors.New("process result has no matching durable acknowledgement")
	}
	return nil
}

func processControlPlaneOrigin(raw string) (*url.URL, error) {
	origin, err := url.Parse(raw)
	if err != nil || origin.Hostname() == "" || (origin.Scheme != "http" && origin.Scheme != "https") || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Opaque != "" || (origin.Path != "" && origin.Path != "/") {
		return nil, errors.New("process responder requires a configured HTTP(S) origin without credentials")
	}
	origin.Path = ""
	return origin, nil
}

func decodeProcessResponse(reader io.Reader, limit int64, target any) error {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return errors.New("process response exceeds byte limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return errors.New("process response must contain exactly one envelope")
	}
	return nil
}
