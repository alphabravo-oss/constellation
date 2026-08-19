package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// vulndbCmd is the parent of `constellationctl vulndb …`.
//
//	constellationctl vulndb status
//	constellationctl vulndb import --dir   <dir-with-manifest+bundle>
//	constellationctl vulndb import --manifest path --payload path
func vulndbCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vulndb",
		Short: "Manage the host-vulnerability bundle (CVE database)",
		Long: `Inspect and import the constellation-vulndb bundle that backs
host-package CVE matching. The "import" subcommand uploads a bundle to the
constellation-api server; the server materializes a fresh bbolt store and
atomically replaces the live one — no api restart required.`,
	}
	cmd.AddCommand(vulndbStatusCmd(), vulndbImportCmd())
	return cmd
}

func vulndbStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Print the current bundle metadata + file stat",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" {
				return fmt.Errorf("not logged in; run `constellationctl login` first")
			}
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet,
				strings.TrimRight(cfg.Server, "/")+"/api/v1/vulndb/status", nil)
			if err != nil {
				return err
			}
			if cfg.Token != "" {
				req.Header.Set("Authorization", "Bearer "+cfg.Token)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if resp.StatusCode >= 400 {
				return fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, b, "", "  "); err != nil {
				cmd.OutOrStdout().Write(b)
				return nil
			}
			cmd.OutOrStdout().Write(pretty.Bytes())
			fmt.Fprintln(cmd.OutOrStdout())
			return nil
		},
	}
}

func vulndbImportCmd() *cobra.Command {
	var (
		dir          string
		manifestPath string
		payloadPath  string
	)
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Upload a vulndb bundle to the server",
		Long: `Streams (manifest.json, bundle.jsonl.gz) to /api/v1/vulndb:import.
The server verifies the bundle, materializes a fresh bbolt store, and atomically
replaces the live one. Use --dir to point at a vulndb-bundle export directory,
or --manifest + --payload for explicit paths.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dir != "" {
				if manifestPath == "" {
					manifestPath = filepath.Join(dir, "manifest.json")
				}
				if payloadPath == "" {
					payloadPath = filepath.Join(dir, "bundle.jsonl.gz")
				}
			}
			if manifestPath == "" || payloadPath == "" {
				return fmt.Errorf("provide --dir OR (--manifest AND --payload)")
			}

			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" {
				return fmt.Errorf("not logged in; run `constellationctl login` first")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
			defer cancel()
			return uploadVulnDBBundle(ctx, cmd.OutOrStdout(), cfg, manifestPath, payloadPath)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "Directory holding manifest.json + bundle.jsonl.gz")
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "Path to manifest.json")
	cmd.Flags().StringVar(&payloadPath, "payload", "", "Path to bundle.jsonl.gz")
	return cmd
}

func uploadVulnDBBundle(ctx context.Context, out io.Writer, cfg *config, manifestPath, payloadPath string) error {
	// Stream the multipart body via an io.Pipe so we don't buffer the
	// whole payload (bundles can be hundreds of MiB).
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)

	errCh := make(chan error, 1)
	go func() {
		defer pw.Close()
		defer mw.Close()
		if err := writePart(mw, "manifest", "manifest.json", manifestPath); err != nil {
			errCh <- err
			return
		}
		if err := writePart(mw, "payload", "bundle.jsonl.gz", payloadPath); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(cfg.Server, "/")+"/api/v1/vulndb:import", pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if uploadErr := <-errCh; uploadErr != nil {
		return fmt.Errorf("upload: %w", uploadErr)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("import failed (status %d): %s", resp.StatusCode, string(body))
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err != nil {
		out.Write(body)
	} else {
		out.Write(pretty.Bytes())
	}
	fmt.Fprintln(out)
	return nil
}

func writePart(mw *multipart.Writer, field, filename, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	w, err := mw.CreateFormFile(field, filename)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, f); err != nil {
		return fmt.Errorf("stream %s: %w", path, err)
	}
	return nil
}
