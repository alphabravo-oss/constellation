// constellationctl tokens — Personal Access / API token CRUD against the
// /api/v1/api-tokens surface. Modeled after the receivers + access-control
// subcommands so the existing config/login flow drives auth here too.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// tokensCmd is the parent for `constellationctl tokens …`. Added in main.go's
// root.AddCommand call alongside the other top-level commands.
func tokensCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "tokens",
		Short: "Manage API tokens (PATs) for CI / scripts / integrations",
	}
	c.AddCommand(tokensCreateCmd(), tokensListCmd(), tokensRotateCmd(), tokensRevokeCmd())
	return c
}

func tokensCreateCmd() *cobra.Command {
	var (
		name        string
		scopes      []string
		expiresFlag string
		attachedTo  string
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Mint a new API token (raw value shown only once)",
		Long: `Mints a new API token bound to the calling user (or a specified service account)
with the given scope set. The raw token value is printed to stdout exactly once; the server
stores only sha256(raw) and cannot reveal it again. Use the printed value as a Bearer
token in the Authorization header.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if name == "" {
				return errors.New("--name required")
			}
			if len(scopes) == 0 {
				return errors.New("at least one --scope required")
			}
			expiresAt, err := parseExpiry(expiresFlag)
			if err != nil {
				return fmt.Errorf("expires: %w", err)
			}
			body := map[string]any{
				"name":   name,
				"scopes": scopes,
			}
			if attachedTo != "" {
				body["attached_to"] = attachedTo
			}
			if expiresAt != nil {
				body["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
			}
			resp, err := apiCall(cmd.Context(), http.MethodPost, "/api/v1/api-tokens", body)
			if err != nil {
				return err
			}
			var out struct {
				ID       string   `json:"id"`
				Name     string   `json:"name"`
				Scopes   []string `json:"scopes"`
				RawToken string   `json:"raw_token"`
				Hint     string   `json:"hint"`
			}
			if err := json.Unmarshal(resp, &out); err != nil {
				return fmt.Errorf("decode response: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Token created: %s (%s)\n", out.Name, out.ID)
			fmt.Fprintf(cmd.OutOrStdout(), "Scopes:        %s\n", strings.Join(out.Scopes, ", "))
			fmt.Fprintln(cmd.OutOrStdout(), "")
			fmt.Fprintln(cmd.OutOrStdout(), "Raw token (will not be shown again):")
			fmt.Fprintln(cmd.OutOrStdout(), out.RawToken)
			if out.Hint != "" {
				fmt.Fprintln(cmd.OutOrStdout(), "")
				fmt.Fprintln(cmd.OutOrStdout(), out.Hint)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Display name (e.g. jenkins-prod)")
	cmd.Flags().StringSliceVar(&scopes, "scope", nil, "Verb scope; repeatable (e.g. --scope read-findings --scope triage-findings)")
	cmd.Flags().StringVar(&expiresFlag, "expires", "", "Expiry: '24h', '7d', '90d', '1y', or RFC3339 timestamp. Empty = never")
	cmd.Flags().StringVar(&attachedTo, "attached-to", "", "'user' (default), or 'service-account-<uuid>'")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func tokensListCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List API tokens for the calling org",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resp, err := apiCall(cmd.Context(), http.MethodGet, "/api/v1/api-tokens", nil)
			if err != nil {
				return err
			}
			if jsonOut {
				fmt.Fprintln(cmd.OutOrStdout(), string(resp))
				return nil
			}
			var out struct {
				Tokens []struct {
					ID              string   `json:"id"`
					Name            string   `json:"name"`
					Scopes          []string `json:"scopes"`
					AttachedToKind  string   `json:"attached_to_kind"`
					AttachedToLabel string   `json:"attached_to_label"`
					Status          string   `json:"status"`
					ExpiresAt       string   `json:"expires_at"`
					LastUsedAt      string   `json:"last_used_at"`
				} `json:"tokens"`
			}
			if err := json.Unmarshal(resp, &out); err != nil {
				return fmt.Errorf("decode response: %w", err)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tATTACHED\tSCOPES\tSTATUS\tEXPIRES\tLAST USED")
			for _, t := range out.Tokens {
				attached := t.AttachedToKind
				if t.AttachedToLabel != "" {
					attached = fmt.Sprintf("%s (%s)", t.AttachedToKind, t.AttachedToLabel)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					t.ID, t.Name, attached, strings.Join(t.Scopes, ","), t.Status,
					ifEmpty(t.ExpiresAt, "never"), ifEmpty(t.LastUsedAt, "-"))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit raw JSON response")
	return cmd
}

func tokensRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate <id>",
		Short: "Rotate an API token: revoke old, mint new with same scopes/expiry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			resp, err := apiCall(cmd.Context(), http.MethodPost, "/api/v1/api-tokens/"+id+"/rotate", map[string]any{})
			if err != nil {
				return err
			}
			var out struct {
				ID       string   `json:"id"`
				Name     string   `json:"name"`
				Scopes   []string `json:"scopes"`
				RawToken string   `json:"raw_token"`
				Hint     string   `json:"hint"`
			}
			if err := json.Unmarshal(resp, &out); err != nil {
				return fmt.Errorf("decode response: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Token rotated. New id: %s (replaces %s)\n", out.ID, id)
			fmt.Fprintf(cmd.OutOrStdout(), "Scopes: %s\n", strings.Join(out.Scopes, ", "))
			fmt.Fprintln(cmd.OutOrStdout(), "")
			fmt.Fprintln(cmd.OutOrStdout(), "New raw token (the previous token is revoked):")
			fmt.Fprintln(cmd.OutOrStdout(), out.RawToken)
			if out.Hint != "" {
				fmt.Fprintln(cmd.OutOrStdout(), "")
				fmt.Fprintln(cmd.OutOrStdout(), out.Hint)
			}
			return nil
		},
	}
}

func tokensRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke an API token (sets revoked_at)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			if _, err := apiCall(cmd.Context(), http.MethodDelete, "/api/v1/api-tokens/"+id, nil); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Token %s revoked.\n", id)
			return nil
		},
	}
}

// ---------------- helpers ----------------

// parseExpiry accepts "24h", "7d", "30d", "90d", "1y", "never", "", or an RFC3339 timestamp.
// Returns nil if no expiry is requested.
func parseExpiry(s string) (*time.Time, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "never" {
		return nil, nil
	}
	// Convenience suffix forms — Go's time.ParseDuration doesn't accept "d" or "y".
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil {
			return nil, fmt.Errorf("invalid days: %w", err)
		}
		t := time.Now().Add(time.Duration(days) * 24 * time.Hour)
		return &t, nil
	}
	if n, ok := strings.CutSuffix(s, "y"); ok {
		years, err := strconv.Atoi(n)
		if err != nil {
			return nil, fmt.Errorf("invalid years: %w", err)
		}
		t := time.Now().Add(time.Duration(years) * 365 * 24 * time.Hour)
		return &t, nil
	}
	// Try Go duration ("24h", "30m").
	if d, err := time.ParseDuration(s); err == nil {
		t := time.Now().Add(d)
		return &t, nil
	}
	// Fall back to RFC3339.
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, fmt.Errorf("expected duration (90d, 24h, 1y) or RFC3339, got %q", s)
	}
	return &t, nil
}

// apiCall posts (or gets/deletes) against the configured Constellation server and returns
// the raw response body. Non-2xx responses bubble up as errors so RunE can return them.
func apiCall(ctx context.Context, method, path string, body any) ([]byte, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	if cfg.Server == "" || cfg.Token == "" {
		return nil, errors.New("not logged in; run `constellationctl login` first (or set CONSTELLATION_SERVER + CONSTELLATION_TOKEN)")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, cfg.Server+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	if rdr != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s %s -> %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	return rb, nil
}

