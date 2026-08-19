// Package webhook is the GitHub App webhook handler.
//
// It receives pull_request and push events, runs constellationctl against the
// changed image/IaC, and posts the result back as a PR review comment using
// the installation token.
//
// The implementation here is intentionally dependency-light:
//   - HMAC-SHA256 webhook verification with X-Hub-Signature-256.
//   - App JWT minted with golang-jwt and exchanged for an installation token.
//   - Plain net/http calls to the GitHub REST API (no go-github dependency to
//     keep the binary small enough to ship in the CLI image).
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

// Config is the runtime configuration read from env.
type Config struct {
	AppID               string
	PrivateKeyPath      string
	WebhookSecret       string
	ConstellationServer string
	ConstellationToken  string
	CLIBinary           string // path to constellationctl, default "constellationctl"
	WorkDir             string // scratch dir for scan outputs
}

// FromEnv loads config from environment variables.
func FromEnv() (Config, error) {
	c := Config{
		AppID:               os.Getenv("GITHUB_APP_ID"),
		PrivateKeyPath:      os.Getenv("GITHUB_APP_PRIVATE_KEY_PATH"),
		WebhookSecret:       os.Getenv("GITHUB_WEBHOOK_SECRET"),
		ConstellationServer: os.Getenv("CONSTELLATION_SERVER"),
		ConstellationToken:  os.Getenv("CONSTELLATION_TOKEN"),
		CLIBinary:           envOr("CONSTELLATIONCTL_BIN", "constellationctl"),
		WorkDir:             envOr("WORKDIR", os.TempDir()),
	}
	var missing []string
	if c.AppID == "" {
		missing = append(missing, "GITHUB_APP_ID")
	}
	if c.PrivateKeyPath == "" {
		missing = append(missing, "GITHUB_APP_PRIVATE_KEY_PATH")
	}
	if c.WebhookSecret == "" {
		missing = append(missing, "GITHUB_WEBHOOK_SECRET")
	}
	if c.ConstellationServer == "" {
		missing = append(missing, "CONSTELLATION_SERVER")
	}
	if c.ConstellationToken == "" {
		missing = append(missing, "CONSTELLATION_TOKEN")
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required env: %s", strings.Join(missing, ", "))
	}
	return c, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Server is the webhook HTTP server.
type Server struct {
	cfg    Config
	log    *slog.Logger
	privPEM []byte
	client *http.Client
}

// New constructs the server, validating the private key on the way through.
func New(cfg Config, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	pem, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	if _, err := parseRSAKey(pem); err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return &Server{
		cfg:     cfg,
		log:     log,
		privPEM: pem,
		client:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Router builds the chi router exposed by the binary.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", s.handleHealth)
	r.Get("/readyz", s.handleHealth)
	r.Post("/webhook", s.handleWebhook)
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "constellation-github-app\n")
	})
	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok","service":"constellation-github-app"}`))
}

// handleWebhook is the main webhook endpoint.
func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 5<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	sig := r.Header.Get("X-Hub-Signature-256")
	if !verifySignature(body, sig, s.cfg.WebhookSecret) {
		s.log.Warn("webhook signature mismatch", "delivery", r.Header.Get("X-GitHub-Delivery"))
		http.Error(w, "signature mismatch", http.StatusUnauthorized)
		return
	}
	event := r.Header.Get("X-GitHub-Event")
	delivery := r.Header.Get("X-GitHub-Delivery")
	s.log.Info("webhook received", "event", event, "delivery", delivery, "bytes", len(body))

	switch event {
	case "ping":
		_, _ = w.Write([]byte(`{"pong":true}`))
		return
	case "pull_request":
		var ev pullRequestEvent
		if err := json.Unmarshal(body, &ev); err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		// Acknowledge fast; process async so GitHub doesn't retry on long scans.
		go s.handlePullRequest(context.Background(), ev)
		w.WriteHeader(http.StatusAccepted)
		return
	case "push":
		// No-op for now; the example workflows handle push themselves.
		w.WriteHeader(http.StatusAccepted)
		return
	default:
		w.WriteHeader(http.StatusNoContent)
		return
	}
}

// --------------------------- core PR handler ---------------------------

func (s *Server) handlePullRequest(ctx context.Context, ev pullRequestEvent) {
	if ev.Action != "opened" && ev.Action != "synchronize" && ev.Action != "reopened" {
		return
	}
	log := s.log.With(
		"action", ev.Action,
		"repo", ev.Repository.FullName,
		"pr", ev.PullRequest.Number,
		"installation", ev.Installation.ID,
	)
	log.Info("processing pull_request")

	token, err := s.installationToken(ctx, ev.Installation.ID)
	if err != nil {
		log.Error("installation token", "err", err)
		return
	}

	// Image scan: derive an image ref by convention. Users can override via
	// repo variable later; for now we use `<repo>:pr-<num>`.
	imageRef := fmt.Sprintf("%s:pr-%d", ev.Repository.Name, ev.PullRequest.Number)
	imageSummary, imageFailed := s.runImageCheck(ctx, imageRef)
	iacSummary, iacFailed := s.runIaCCheck(ctx)

	body := renderComment(commentInput{
		ImageRef:     imageRef,
		ImageSummary: imageSummary,
		ImageFailed:  imageFailed,
		IaCSummary:   iacSummary,
		IaCFailed:    iacFailed,
		Sha:          ev.PullRequest.Head.SHA,
	})

	if err := s.postIssueComment(ctx, token, ev.Repository.FullName, ev.PullRequest.Number, body); err != nil {
		log.Error("post comment", "err", err)
		return
	}

	state := "success"
	desc := "Constellation: clean"
	if imageFailed || iacFailed {
		state = "failure"
		desc = "Constellation: blocking findings"
	}
	if err := s.postStatus(ctx, token, ev.Repository.FullName, ev.PullRequest.Head.SHA, state, desc); err != nil {
		log.Error("post status", "err", err)
	}
}

func (s *Server) runImageCheck(ctx context.Context, imageRef string) (summary string, failed bool) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	tmp, err := os.MkdirTemp(s.cfg.WorkDir, "constellation-img-")
	if err != nil {
		return fmt.Sprintf("could not create workdir: %v", err), true
	}
	defer os.RemoveAll(tmp)
	sarifPath := filepath.Join(tmp, "image.sarif")

	cmd := exec.CommandContext(ctx, s.cfg.CLIBinary, "image-check", imageRef,
		"--fail-on", "critical",
		"--sarif", sarifPath,
		"--quiet",
	)
	cmd.Env = append(os.Environ(),
		"CONSTELLATION_SERVER="+s.cfg.ConstellationServer,
		"CONSTELLATION_TOKEN="+s.cfg.ConstellationToken,
	)
	out, err := cmd.CombinedOutput()
	failed = err != nil
	return string(out), failed
}

func (s *Server) runIaCCheck(ctx context.Context) (summary string, failed bool) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.cfg.CLIBinary, "iac-check", ".",
		"--fail-on", "high",
	)
	cmd.Env = append(os.Environ(),
		"CONSTELLATION_SERVER="+s.cfg.ConstellationServer,
		"CONSTELLATION_TOKEN="+s.cfg.ConstellationToken,
	)
	out, err := cmd.CombinedOutput()
	failed = err != nil
	return string(out), failed
}

// --------------------------- GitHub API helpers ---------------------------

func (s *Server) installationToken(ctx context.Context, installID int64) (string, error) {
	appJWT, err := s.signAppJWT()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installID)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("installation_token: http %d: %s", resp.StatusCode, string(b))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Token, nil
}

func (s *Server) signAppJWT() (string, error) {
	key, err := parseRSAKey(s.privPEM)
	if err != nil {
		return "", err
	}
	now := time.Now().Add(-30 * time.Second)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": s.cfg.AppID,
	})
	return tok.SignedString(key)
}

func parseRSAKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rsaKey, nil
}

func (s *Server) postIssueComment(ctx context.Context, token, repo string, prNum int, body string) error {
	payload, _ := json.Marshal(map[string]string{"body": body})
	url := fmt.Sprintf("https://api.github.com/repos/%s/issues/%d/comments", repo, prNum)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("issue comment: http %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func (s *Server) postStatus(ctx context.Context, token, repo, sha, state, desc string) error {
	payload, _ := json.Marshal(map[string]string{
		"state":       state,       // "success" | "failure" | "pending" | "error"
		"description": desc,
		"context":     "constellation/security",
	})
	url := fmt.Sprintf("https://api.github.com/repos/%s/statuses/%s", repo, sha)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("statuses: http %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// --------------------------- helpers ---------------------------

func verifySignature(body []byte, sigHeader, secret string) bool {
	if !strings.HasPrefix(sigHeader, "sha256=") || secret == "" {
		return false
	}
	want, err := hex.DecodeString(strings.TrimPrefix(sigHeader, "sha256="))
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return hmac.Equal(m.Sum(nil), want)
}

type commentInput struct {
	ImageRef     string
	ImageSummary string
	ImageFailed  bool
	IaCSummary   string
	IaCFailed    bool
	Sha          string
}

func renderComment(in commentInput) string {
	icon := func(failed bool) string {
		if failed {
			return "FAIL"
		}
		return "OK"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "## Constellation security scan\n\n")
	fmt.Fprintf(&b, "Commit: `%s`\n\n", short(in.Sha))
	fmt.Fprintf(&b, "| Check | Status |\n|---|---|\n")
	fmt.Fprintf(&b, "| Image (`%s`) | %s |\n", in.ImageRef, icon(in.ImageFailed))
	fmt.Fprintf(&b, "| IaC | %s |\n\n", icon(in.IaCFailed))
	if strings.TrimSpace(in.ImageSummary) != "" {
		fmt.Fprintf(&b, "<details><summary>Image scan output</summary>\n\n```\n%s\n```\n</details>\n\n", clip(in.ImageSummary, 50000))
	}
	if strings.TrimSpace(in.IaCSummary) != "" {
		fmt.Fprintf(&b, "<details><summary>IaC scan output</summary>\n\n```\n%s\n```\n</details>\n\n", clip(in.IaCSummary, 50000))
	}
	b.WriteString("<sub>Posted by the Constellation GitHub App.</sub>")
	return b.String()
}

func short(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n…(truncated)"
}

// --------------------------- payload types ---------------------------

type pullRequestEvent struct {
	Action      string `json:"action"`
	PullRequest struct {
		Number int `json:"number"`
		Head   struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
		Base struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
	Repository struct {
		FullName string `json:"full_name"`
		Name     string `json:"name"`
	} `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}
