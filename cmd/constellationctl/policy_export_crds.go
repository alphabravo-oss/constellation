// `constellationctl policy export-crds` — the minimum-viable GitOps bridge.
//
// It reads an org's admission policies and response rules straight out of the Constellation
// policy store and emits the equivalent ConstellationAdmissionRule / ConstellationResponseRule
// CR documents as a kubectl-applyable multi-doc YAML stream. Re-applying that stream to a cluster
// running the constellation-operator round-trips: the B2b reconciler upserts the identical rows
// (source='declarative'), so the exported file is a faithful, committable source of truth.
//
// It reads the DB directly (not the REST API) for the same reasons the operator does (policydb
// package doc): the REST auth model derives org from the authenticated subject with no act-as-org
// affordance, and there is no name-keyed list/export route to add without tripping the I1 OpenAPI
// gate. The DSN comes from --database-url or CONSTELLATION_DATABASE_URL / DATABASE_URL.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/alphabravocompany/constellation/deploy/operator/policydb"
)

func policyExportCRDsCmd() *cobra.Command {
	var (
		databaseURL string
		org         string
		output      string
		kind        string
	)
	cmd := &cobra.Command{
		Use:   "export-crds",
		Short: "Export an org's admission/response policies as kubectl-applyable Constellation CRs",
		Long: `Export the Constellation policies stored for an org as the equivalent
ConstellationAdmissionRule / ConstellationResponseRule custom resources, emitted as a
kubectl-applyable multi-document YAML stream — the minimum-viable GitOps bridge.

The output round-trips with the constellation-operator: applying it to a cluster running the
operator upserts the identical rows (tagged source='declarative'), so the file is a faithful,
committable source of truth for the org's policy.

Reads the policy store directly; supply the DSN via --database-url or
CONSTELLATION_DATABASE_URL / DATABASE_URL.`,
		Example: `  constellationctl policy export-crds --org 5b9f... > policies.yaml
  kubectl apply -f policies.yaml
  constellationctl policy export-crds --org 5b9f... --kind response --output rr.yaml`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			orgID, err := uuid.Parse(strings.TrimSpace(org))
			if err != nil {
				return fmt.Errorf("invalid --org %q: %w", org, err)
			}
			dsn := firstNonEmptyStr(databaseURL,
				os.Getenv("CONSTELLATION_DATABASE_URL"), os.Getenv("DATABASE_URL"))
			if dsn == "" {
				return fmt.Errorf("no database DSN; pass --database-url or set CONSTELLATION_DATABASE_URL / DATABASE_URL")
			}
			switch kind {
			case "all", "admission", "response", "group", "networkrule":
			default:
				return fmt.Errorf("invalid --kind %q: want all|admission|response|group|networkrule", kind)
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			pool, err := pgxpool.New(ctx, dsn)
			if err != nil {
				return fmt.Errorf("connect policy store: %w", err)
			}
			defer pool.Close()
			store := policydb.New(pool)

			var docs [][]byte
			if kind == "all" || kind == "admission" {
				rules, err := store.ListAdmissionRules(ctx, orgID)
				if err != nil {
					return err
				}
				for _, row := range rules {
					b, err := yaml.Marshal(policydb.AdmissionCR(row))
					if err != nil {
						return fmt.Errorf("marshal admission rule %q: %w", row.Name, err)
					}
					docs = append(docs, b)
				}
			}
			if kind == "all" || kind == "response" {
				rules, err := store.ListResponseRules(ctx, orgID)
				if err != nil {
					return err
				}
				for _, rule := range rules {
					b, err := yaml.Marshal(policydb.ResponseCR(rule))
					if err != nil {
						return fmt.Errorf("marshal response rule %q: %w", rule.Name, err)
					}
					docs = append(docs, b)
				}
			}
			if kind == "all" || kind == "group" {
				groups, err := store.ListGroups(ctx, orgID)
				if err != nil {
					return err
				}
				for _, g := range groups {
					b, err := yaml.Marshal(policydb.GroupCR(g))
					if err != nil {
						return fmt.Errorf("marshal group %q: %w", g.Name, err)
					}
					docs = append(docs, b)
				}
			}
			if kind == "all" || kind == "networkrule" {
				edges, err := store.ListNetworkRules(ctx, orgID)
				if err != nil {
					return err
				}
				for _, e := range edges {
					b, err := yaml.Marshal(policydb.NetworkRuleCR(e))
					if err != nil {
						return fmt.Errorf("marshal network rule %s->%s: %w", e.FromGroup, e.ToGroup, err)
					}
					docs = append(docs, b)
				}
			}

			var buf bytes.Buffer
			for i, d := range docs {
				if i > 0 {
					buf.WriteString("---\n")
				}
				buf.Write(d)
			}

			if output != "" {
				if err := os.WriteFile(output, buf.Bytes(), 0o644); err != nil {
					return fmt.Errorf("write %s: %w", output, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %d CR document(s) to %s\n", len(docs), output)
				return nil
			}
			_, err = cmd.OutOrStdout().Write(buf.Bytes())
			return err
		},
	}
	cmd.Flags().StringVar(&databaseURL, "database-url", "", "Policy store DSN (else CONSTELLATION_DATABASE_URL / DATABASE_URL)")
	cmd.Flags().StringVar(&org, "org", "", "Org ID (UUID) whose policies to export")
	cmd.Flags().StringVar(&output, "output", "", "Write the YAML stream here (otherwise print to stdout)")
	cmd.Flags().StringVar(&kind, "kind", "all", "Which policies to export: all|admission|response|group|networkrule")
	_ = cmd.MarkFlagRequired("org")
	return cmd
}

// firstNonEmptyStr returns the first non-empty, trimmed string.
func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}
