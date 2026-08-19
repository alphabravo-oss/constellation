package gitops

// GitHub push connector — commits a file via the GitHub Contents API. Modeled on
// NeuVector's controller/remote_repository/github.go (GET existing SHA, then PUT content
// with that SHA so updates don't 409). Rewritten to Constellation style: context-aware
// requests, structured errors, and a stdlib blob-SHA short-circuit that skips the PUT when
// the remote content is already identical.

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	githubAPIVersion    = "2022-11-28"
	githubContentURLFmt = "https://api.github.com/repos/%s/%s/contents/%s"
)

// ErrGitHubRateLimited is returned when GitHub reports the token's rate limit is exhausted.
var ErrGitHubRateLimited = errors.New("gitops: github rate limit reached")

// defaultHTTPClient is shared by the connectors; 30s covers the small Contents API calls.
var defaultHTTPClient = &http.Client{Timeout: 30 * time.Second}

type githubCommitter struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type githubPutRequest struct {
	Message   string          `json:"message"`
	Branch    string          `json:"branch"`
	Committer githubCommitter `json:"committer"`
	Content   string          `json:"content"` // base64
	SHA       string          `json:"sha,omitempty"`
}

type githubGetResponse struct {
	SHA string `json:"sha"`
}

// pushGitHub creates-or-updates cfg.FilePath on cfg.Branch with fileContents.
func pushGitHub(ctx context.Context, cfg ConnectorConfig, fileContents []byte, message string) error {
	contentURL := fmt.Sprintf(githubContentURLFmt, cfg.GitHubOwner, cfg.GitHubRepo, cfg.FilePath)

	existingSHA, err := githubExistingSHA(ctx, cfg, contentURL)
	if err != nil {
		return fmt.Errorf("gitops: get existing sha for %s: %w", cfg.FilePath, err)
	}
	// Skip the write when the blob is byte-identical (matches NeuVector's github.v3 guard).
	if existingSHA != "" && existingSHA == gitBlobSHA1(fileContents) {
		return nil
	}

	body := githubPutRequest{
		Message:   message,
		Branch:    cfg.Branch,
		Committer: githubCommitter{Name: cfg.CommitterName, Email: cfg.CommitterEmail},
		Content:   base64.StdEncoding.EncodeToString(fileContents),
		SHA:       existingSHA,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("gitops: marshal github request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, contentURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	githubHeaders(req, cfg.PAT)
	resp, err := cfg.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("gitops: github put: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		return nil
	}
	if resp.Header.Get("x-ratelimit-remaining") == "0" {
		return ErrGitHubRateLimited
	}
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("gitops: github put returned %d: %s", resp.StatusCode, string(snippet))
}

// githubExistingSHA returns the current blob SHA for the file, or "" if it doesn't exist.
func githubExistingSHA(ctx context.Context, cfg ConnectorConfig, contentURL string) (string, error) {
	getURL := contentURL + "?ref=" + url.QueryEscape(cfg.Branch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return "", err
	}
	githubHeaders(req, cfg.PAT)
	resp, err := cfg.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil // new file
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, string(snippet))
	}
	var out githubGetResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode github response: %w", err)
	}
	return out.SHA, nil
}

func githubHeaders(req *http.Request, pat string) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+pat)
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
}

// gitBlobSHA1 computes the git blob object SHA-1 of content ("blob <len>\0<content>"),
// matching what the GitHub Contents API returns as a file's sha so we can short-circuit
// no-op pushes.
func gitBlobSHA1(content []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(content))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}
