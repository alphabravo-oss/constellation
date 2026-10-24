package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/alphabravocompany/constellation/internal/archiveio"
	"github.com/alphabravocompany/constellation/internal/k8sauditarchive"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

type k8sArchiveOptions struct {
	action, org, cluster, from, through, afterAt, afterID, private, public, input, output, database string
	limit                                                                                           int
}

func k8sAuditArchiveCommand(action string) *cobra.Command {
	a := &k8sArchiveOptions{action: action}
	cmd := &cobra.Command{Use: action, Args: cobra.NoArgs, RunE: a.run}
	cmd.Flags().StringVar(&a.public, "verify-key", "", "Independently trusted Ed25519 public key PEM")
	if action == "export-k8s-audit" {
		cmd.Flags().StringVar(&a.private, "sign-key", "", "Ed25519 private key PEM")
		cmd.Flags().StringVar(&a.output, "out-dir", "", "Dedicated private archive directory")
		cmd.Flags().StringVar(&a.from, "from", "", "Inclusive receipt time, RFC3339 with at most microsecond precision")
		cmd.Flags().StringVar(&a.through, "through", "", "Exclusive receipt time, RFC3339 with at most microsecond precision")
		cmd.Flags().StringVar(&a.afterAt, "after-at", "", "Exclusive previous page receipt time")
		cmd.Flags().StringVar(&a.afterID, "after-id", "", "Exclusive previous page UUID (requires --after-at)")
		cmd.Flags().IntVar(&a.limit, "limit", 1000, "Maximum rows per page (1..1000)")
	} else {
		cmd.Flags().StringVar(&a.input, "in", "", "Signed Kubernetes audit archive file")
	}
	if action != "verify-k8s-audit" {
		cmd.Flags().StringVar(&a.org, "org-id", "", "Explicit source/export or destination/restore organization UUID")
		cmd.Flags().StringVar(&a.cluster, "cluster-id", "", "Explicit source/export or destination/restore cluster UUID")
		cmd.Flags().StringVar(&a.database, "database-url", "", "Postgres URL (or DATABASE_URL)")
	}
	return cmd
}

func (a *k8sArchiveOptions) run(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
	defer cancel()
	if a.public == "" {
		return errors.New("--verify-key required")
	}
	if a.action == "verify-k8s-audit" {
		return a.verify(ctx, cmd)
	}
	org, err := uuid.Parse(a.org)
	if err != nil || org == uuid.Nil {
		return errors.New("nonzero --org-id required")
	}
	cluster, err := uuid.Parse(a.cluster)
	if err != nil || cluster == uuid.Nil {
		return errors.New("nonzero --cluster-id required")
	}
	if a.database == "" {
		a.database = os.Getenv("DATABASE_URL")
	}
	if a.database == "" {
		return errors.New("--database-url or DATABASE_URL required")
	}
	pool, err := pgxpool.New(ctx, a.database)
	if err != nil {
		return backup.CLIFailure("database configuration", err)
	}
	defer pool.Close()
	if a.action == "export-k8s-audit" {
		return a.export(ctx, cmd, pool, org, cluster)
	}
	file, err := backup.OpenArtifact(a.input)
	if err != nil {
		return backup.CLIFailure("audit archive open", err)
	}
	defer func() { _ = file.Close() }()
	result, err := k8sauditarchive.Restore(ctx, pool, file, a.public, org, cluster)
	if err != nil {
		return backup.CLIFailure("audit archive restore", err)
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
}

func (a *k8sArchiveOptions) verify(ctx context.Context, cmd *cobra.Command) error {
	file, err := backup.OpenArtifact(a.input)
	if err != nil {
		return backup.CLIFailure("audit archive open", err)
	}
	defer func() { _ = file.Close() }()
	result, err := k8sauditarchive.Verify(ctx, file, a.public)
	if err != nil {
		return backup.CLIFailure("audit archive verification", err)
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
}

func (a *k8sArchiveOptions) window(org, cluster uuid.UUID) (k8sauditarchive.Window, error) {
	w := k8sauditarchive.Window{OrgID: org, ClusterID: cluster}
	var err error
	if w.From, err = time.Parse(time.RFC3339Nano, a.from); err != nil {
		return w, errors.New("valid --from timestamp required")
	}
	if w.Through, err = time.Parse(time.RFC3339Nano, a.through); err != nil {
		return w, errors.New("valid --through timestamp required")
	}
	if a.afterAt != "" || a.afterID != "" {
		if w.After.At, err = time.Parse(time.RFC3339Nano, a.afterAt); err != nil {
			return w, errors.New("valid --after-at required with --after-id")
		}
		if w.After.ID, err = uuid.Parse(a.afterID); err != nil || w.After.ID == uuid.Nil {
			return w, errors.New("nonzero --after-id required with --after-at")
		}
	}
	return w, nil
}

func (a *k8sArchiveOptions) export(ctx context.Context, cmd *cobra.Command, pool *pgxpool.Pool, org, cluster uuid.UUID) error {
	if a.private == "" || a.output == "" {
		return errors.New("--sign-key and --out-dir required")
	}
	w, err := a.window(org, cluster)
	if err != nil {
		return err
	}
	data, report, err := k8sauditarchive.Export(ctx, pool, w, a.limit, a.private, a.public)
	if err != nil {
		return backup.CLIFailure("audit archive export", err)
	}
	path, err := archiveio.WriteVerified(ctx, a.output, ".k8s-audit.json", data, func(input io.Reader) error {
		_, err := k8sauditarchive.Verify(ctx, input, a.public)
		return err
	})
	if err != nil {
		return backup.CLIFailure("audit archive read-back", err)
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
		Path   string                 `json:"path"`
		Report k8sauditarchive.Report `json:"archive"`
	}{path, report})
}
