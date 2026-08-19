// `constellationctl cluster ...` subcommands (Wave N1).
//
// Manages cluster init-bundles — Constellation's analogue of StackRox's
// `roxctl central init-bundles generate`. The control plane mints a sealed YAML
// that an operator installs on a remote cluster to register it with the right
// per-cluster TLS material + scoped service-principal credentials.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// clusterCmd builds the parent `cluster` command + its subcommands.
func clusterCmd() *cobra.Command {
	var serverFlag string
	c := &cobra.Command{
		Use:   "cluster",
		Short: "Manage Constellation cluster registrations and init-bundles",
		Long: `Mint, list, rotate, and revoke cluster init-bundles.

A cluster init-bundle is a sealed YAML containing:
  - scanner_token + runtime_agent_token (fresh, tied to a clusters row)
  - admission webhook TLS material (CA + server cert/key)
  - audit HMAC secret
  - control-plane URL + cluster_id + org_id + expires_at

The bundle is shown to the admin exactly once at mint time; subsequent retrievals
mark the bundle as downloaded and audit-log the read. Rotating mints a replacement
and revokes the prior bundle's tokens; revoking cascades to the underlying tokens
so a leaked bundle can be killed instantly.`,
	}
	c.PersistentFlags().StringVar(&serverFlag, "server", "", "Override server URL (otherwise read from config)")
	c.AddCommand(
		clusterCreateCmd(&serverFlag),
		clusterListCmd(&serverFlag),
		clusterRotateCmd(&serverFlag),
		clusterRevokeCmd(&serverFlag),
	)
	return c
}

func clusterCreateCmd(serverFlag *string) *cobra.Command {
	var (
		distro, region, expiry, output string
		email                          string
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Mint a cluster init-bundle and write it to a YAML file",
		Args:  cobra.ExactArgs(1),
		Example: `  constellationctl --server https://constellation.example.com cluster create prod-us-east-1 \
    --distro=k3s --region=us-east-1 --expiry=720h \
    --output cluster-init.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			cli, err := resolveClient(*serverFlag, email)
			if err != nil {
				return err
			}
			body := map[string]any{"name": name}
			if distro != "" {
				body["distro"] = distro
			}
			if region != "" {
				body["region"] = region
			}
			if expiry != "" {
				body["ttl"] = expiry
			}
			var resp mintResponse
			if err := cli.postJSON("/api/v1/cluster-init-bundles", body, &resp); err != nil {
				return err
			}
			if output != "" {
				if err := os.WriteFile(output, []byte(resp.YAML), 0o600); err != nil {
					return fmt.Errorf("write %s: %w", output, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s (cluster_id=%s, expires_at=%s)\n",
					output, resp.ClusterID, resp.ExpiresAt.Format(time.RFC3339))
				fmt.Fprintln(cmd.OutOrStdout(), "Install on the target cluster with:")
				fmt.Fprintf(cmd.OutOrStdout(),
					"  kubectl create ns constellation-system\n"+
						"  kubectl -n constellation-system create secret generic constellation-init-bundle \\\n"+
						"    --from-file=bundle.yaml=%s\n"+
						"  helm install constellation deploy/charts/constellation -n constellation-system \\\n"+
						"    --set initBundle.secretName=constellation-init-bundle\n", output)
				return nil
			}
			// No --output: print to stdout.
			fmt.Fprintln(cmd.OutOrStdout(), resp.YAML)
			return nil
		},
	}
	cmd.Flags().StringVar(&distro, "distro", "kubernetes", "Cluster distro (kubernetes|k3s|eks|gke|aks|openshift)")
	cmd.Flags().StringVar(&region, "region", "", "Cluster region (e.g. us-east-1)")
	cmd.Flags().StringVar(&expiry, "expiry", "720h", "Bundle TTL (Go duration: 24h, 720h, 7d, 30d, 90d)")
	cmd.Flags().StringVar(&output, "output", "", "Write the rendered YAML here (otherwise print to stdout)")
	cmd.Flags().StringVar(&email, "email", "", "Email to log into if not already authenticated")
	return cmd
}

func clusterListCmd(serverFlag *string) *cobra.Command {
	var email string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List cluster init-bundles",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cli, err := resolveClient(*serverFlag, email)
			if err != nil {
				return err
			}
			var resp struct {
				Bundles []bundleSummary `json:"bundles"`
			}
			if err := cli.getJSON("/api/v1/cluster-init-bundles", &resp); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%-36s  %-24s  %-10s  %-25s\n", "ID", "NAME", "STATUS", "EXPIRES")
			for _, b := range resp.Bundles {
				fmt.Fprintf(cmd.OutOrStdout(), "%-36s  %-24s  %-10s  %-25s\n",
					b.ID, truncateStr(b.Name, 24), b.Status, b.ExpiresAt.Format(time.RFC3339))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "Email to log into if not already authenticated")
	return cmd
}

func clusterRotateCmd(serverFlag *string) *cobra.Command {
	var (
		output string
		email  string
	)
	cmd := &cobra.Command{
		Use:   "rotate <bundle-id>",
		Short: "Rotate a cluster init-bundle (revokes prior tokens, mints replacement)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := resolveClient(*serverFlag, email)
			if err != nil {
				return err
			}
			var resp mintResponse
			if err := cli.postJSON("/api/v1/cluster-init-bundles/"+args[0]+"/rotate", nil, &resp); err != nil {
				return err
			}
			if output != "" {
				if err := os.WriteFile(output, []byte(resp.YAML), 0o600); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Rotated. New bundle id=%s; wrote %s\n", resp.ID, output)
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), resp.YAML)
			return nil
		},
	}
	cmd.Flags().StringVar(&output, "output", "", "Write replacement YAML here")
	cmd.Flags().StringVar(&email, "email", "", "Email to log into if not already authenticated")
	return cmd
}

func clusterRevokeCmd(serverFlag *string) *cobra.Command {
	var email string
	cmd := &cobra.Command{
		Use:   "revoke <bundle-id>",
		Short: "Revoke a cluster init-bundle (cascades to its scanner + runtime-agent tokens)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := resolveClient(*serverFlag, email)
			if err != nil {
				return err
			}
			var resp map[string]any
			if err := cli.deleteJSON("/api/v1/cluster-init-bundles/"+args[0], &resp); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Revoked bundle %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "Email to log into if not already authenticated")
	return cmd
}

// ---------------- shared HTTP client + auth ----------------

// authedClient holds the resolved server + bearer token; pulled together by
// resolveClient(), which transparently runs an interactive login if no token is
// cached but email+password (from $CONSTELLATION_PASSWORD or stdin) are available.
type authedClient struct {
	server string
	token  string
	http   *http.Client
}

func resolveClient(serverOverride, email string) (*authedClient, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	server := strings.TrimRight(cfg.Server, "/")
	if serverOverride != "" {
		server = strings.TrimRight(serverOverride, "/")
	}
	if server == "" {
		return nil, errors.New("server URL not set; pass --server or run `constellationctl login` first")
	}
	cli := &authedClient{server: server, token: cfg.Token, http: &http.Client{Timeout: 30 * time.Second}}
	if cli.token == "" {
		if email == "" {
			return nil, errors.New("no cached token; pass --email to authenticate")
		}
		pw := os.Getenv("CONSTELLATION_PASSWORD")
		if pw == "" {
			fmt.Fprint(os.Stderr, "Password: ")
			if _, err := fmt.Fscan(os.Stdin, &pw); err != nil {
				return nil, fmt.Errorf("read password: %w", err)
			}
		}
		payload := map[string]string{"email": email, "password": pw}
		body, _ := json.Marshal(payload)
		resp, err := http.Post(server+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("login: %w", err)
		}
		defer resp.Body.Close()
		rb, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("login failed (%d): %s", resp.StatusCode, rb)
		}
		var out struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rb, &out); err != nil {
			return nil, err
		}
		cli.token = out.Token
		_ = saveConfig(&config{Server: server, Token: out.Token})
	}
	return cli, nil
}

func (c *authedClient) postJSON(path string, body any, out any) error {
	return c.do(http.MethodPost, path, body, out)
}

func (c *authedClient) getJSON(path string, out any) error {
	return c.do(http.MethodGet, path, nil, out)
}

func (c *authedClient) deleteJSON(path string, out any) error {
	return c.do(http.MethodDelete, path, nil, out)
}

func (c *authedClient) do(method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, c.server+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s %s -> %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	if out != nil && len(rb) > 0 {
		return json.Unmarshal(rb, out)
	}
	return nil
}

// ---------------- response types (mirror handler DTOs) ----------------

type bundleSummary struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	ClusterID string    `json:"cluster_id"`
	Name      string    `json:"name"`
	Distro    string    `json:"distro"`
	Region    string    `json:"region,omitempty"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type mintResponse struct {
	bundleSummary
	YAML      string `json:"yaml"`
	ServerURL string `json:"server_url"`
}

// Cobra struct embedding plays poorly with JSON tag inheritance via custom
// UnmarshalJSON; instead we field-by-field rely on the embedded struct's tags
// being picked up by encoding/json, which works because Go promotes tagged
// fields from embedded anonymous structs.

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
