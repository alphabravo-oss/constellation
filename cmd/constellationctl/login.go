package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func newAPIClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		// Login and mutation bodies must not be replayed to a redirect target.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func loginToken(ctx context.Context, client *http.Client, server, email, password string) (string, error) {
	body, err := json.Marshal(map[string]string{"email": email, "password": password})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(server, "/")+"/api/v1/auth/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login failed (HTTP %d)", resp.StatusCode)
	}
	const maxResponseBytes = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("read login response: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return "", fmt.Errorf("login response exceeds size limit")
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("decode login response: %w", err)
	}
	if strings.TrimSpace(out.Token) == "" {
		return "", fmt.Errorf("login response has no token")
	}
	return out.Token, nil
}
