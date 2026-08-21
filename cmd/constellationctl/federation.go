// `constellationctl federation ...` subcommands (FED-JOIN-25).
//
// Joint-side counterpart to the master's join-token minting: `federation join`
// drives this controller to join a remote federation master over mTLS. It calls
// the new POST /federation/join-remote endpoint, which exchanges the join token for
// a per-cluster sync ticket (+ per-joint client cert/key + master CA when the master
// runs mTLS), persists them encrypted at rest, and flips local state to joint.
package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// federationCmd builds the parent `federation` command + its subcommands.
func federationCmd() *cobra.Command {
	var serverFlag string
	c := &cobra.Command{
		Use:     "federation",
		Aliases: []string{"fed"},
		Short:   "Manage this controller's federation membership",
		Long: `Join (or manage) a Constellation federation from the JOINT side.

A federation has one master and many joints. The master mints a short-lived join
token (` + "`constellationctl` on the master, or the /federation/join-tokens API" + `);
an operator hands that token to a joint and runs:

  constellationctl federation join --master-url https://master.example.com --token <join-token>

The joint calls the master, receives a per-cluster sync ticket (plus a per-joint
client certificate + the master CA when the master enforces mTLS), stores them
encrypted at rest, and begins polling the master for federated rules.`,
	}
	c.PersistentFlags().StringVar(&serverFlag, "server", "", "Override server URL (otherwise read from config)")
	c.AddCommand(federationJoinCmd(&serverFlag))
	return c
}

func federationJoinCmd(serverFlag *string) *cobra.Command {
	var (
		masterURL, token       string
		clusterID, clusterName string
		email                  string
	)
	cmd := &cobra.Command{
		Use:   "join",
		Short: "Join a remote federation master (mTLS-capable)",
		Example: `  constellationctl --server https://joint.example.com federation join \
    --master-url https://master.example.com --token <join-token>`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cli, err := resolveClient(*serverFlag, email)
			if err != nil {
				return err
			}
			// master_url/token may be omitted here to let the server fall back to its
			// CONSTELLATION_FED_MASTER_URL / CONSTELLATION_FED_MASTER_TOKEN env (the chart
			// knobs) — but the CLI's whole purpose is an explicit join, so require them.
			if masterURL == "" || token == "" {
				return fmt.Errorf("--master-url and --token are required")
			}
			body := map[string]any{"master_url": masterURL, "token": token}
			if clusterID != "" {
				body["cluster_id"] = clusterID
			}
			if clusterName != "" {
				body["cluster_name"] = clusterName
			}
			var resp struct {
				ClusterID string `json:"cluster_id"`
				State     string `json:"state"`
				MasterURL string `json:"master_url"`
				MTLS      bool   `json:"mtls"`
			}
			if err := cli.postJSON("/api/v1/federation/join-remote", body, &resp); err != nil {
				return err
			}
			mode := "bearer-only"
			if resp.MTLS {
				mode = "mTLS (per-joint client cert issued)"
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"Joined federation master %s as cluster_id=%s (state=%s, auth=%s)\n",
				resp.MasterURL, resp.ClusterID, resp.State, mode)
			return nil
		},
	}
	cmd.Flags().StringVar(&masterURL, "master-url", "", "Federation master base URL (e.g. https://master.example.com)")
	cmd.Flags().StringVar(&token, "token", "", "Join token minted by the master")
	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "This joint's cluster id (optional; a stable id is derived when omitted)")
	cmd.Flags().StringVar(&clusterName, "cluster-name", "", "This joint's display name (optional; defaults to cluster id)")
	cmd.Flags().StringVar(&email, "email", "", "Email to log into if not already authenticated")
	return cmd
}
