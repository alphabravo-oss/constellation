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
	"github.com/alphabravocompany/constellation/internal/inventoryarchive"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

func evidenceCmd() *cobra.Command {
	root := &cobra.Command{Use: "evidence", Short: "Signed evidence export, offline verification, and scoped restore"}
	for _, action := range []string{"export-inventory", "verify-inventory", "restore-inventory"} {
		root.AddCommand(inventoryCommand(action))
	}
	for _, action := range []string{"export-k8s-audit", "verify-k8s-audit", "restore-k8s-audit"} {
		root.AddCommand(k8sAuditArchiveCommand(action))
	}
	for _, action := range []string{"export-runtime-threat", "verify-runtime-threat", "restore-runtime-threat"} {
		root.AddCommand(threatArchiveCommand(action))
	}
	return root
}

type inventoryOptions struct{ action, org, target, evidence, private, public, input, output, database string }

func inventoryCommand(action string) *cobra.Command {
	a := inventoryOptions{action: action}
	cmd := &cobra.Command{Use: action, Args: cobra.NoArgs, RunE: a.run}
	cmd.Flags().StringVar(&a.public, "verify-key", "", "Trusted Ed25519 public key PEM (required)")
	if action == "export-inventory" {
		cmd.Flags().StringVar(&a.evidence, "evidence-id", "", "Source inventory UUID")
		cmd.Flags().StringVar(&a.private, "sign-key", "", "Ed25519 private key PEM")
		cmd.Flags().StringVar(&a.output, "out-dir", "", "Dedicated private archive directory")
	} else {
		cmd.Flags().StringVar(&a.input, "in", "", "Signed inventory archive file")
	}
	if action != "verify-inventory" {
		cmd.Flags().StringVar(&a.org, "org-id", "", "Explicit organization UUID")
		cmd.Flags().StringVar(&a.database, "database-url", "", "Postgres URL (or DATABASE_URL)")
	}
	if action == "restore-inventory" {
		cmd.Flags().StringVar(&a.target, "target-id", "", "Existing destination target UUID")
	}
	return cmd
}

func (a *inventoryOptions) run(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
	defer cancel()
	if a.public == "" {
		return errors.New("--verify-key required")
	}
	if a.action == "verify-inventory" {
		file, err := backup.OpenArtifact(a.input)
		if err != nil {
			return backup.CLIFailure("inventory open", err)
		}
		defer func() { _ = file.Close() }()
		report, err := inventoryarchive.Verify(ctx, file, a.public)
		if err != nil {
			return backup.CLIFailure("inventory verification", err)
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(report)
	}
	org, err := uuid.Parse(a.org)
	if err != nil || org == uuid.Nil {
		return errors.New("nonzero --org-id required")
	}
	var id uuid.UUID
	if a.action == "export-inventory" {
		id, err = uuid.Parse(a.evidence)
		if err != nil || id == uuid.Nil || a.private == "" || a.output == "" {
			return errors.New("--evidence-id, --sign-key, and --out-dir required")
		}
	} else {
		id, err = uuid.Parse(a.target)
		if err != nil || id == uuid.Nil || a.input == "" {
			return errors.New("--target-id and --in required")
		}
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
	if a.action == "export-inventory" {
		return a.export(ctx, cmd, pool, org, id)
	}
	file, err := backup.OpenArtifact(a.input)
	if err != nil {
		return backup.CLIFailure("inventory open", err)
	}
	defer func() { _ = file.Close() }()
	result, err := inventoryarchive.Restore(ctx, pool, file, a.public, org, id)
	if err != nil {
		return backup.CLIFailure("inventory restore", err)
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
}

func (a *inventoryOptions) export(ctx context.Context, cmd *cobra.Command, pool *pgxpool.Pool, org, id uuid.UUID) error {
	data, report, err := inventoryarchive.Export(ctx, pool, org, id, a.private, a.public)
	if err != nil {
		return backup.CLIFailure("inventory export", err)
	}
	path, err := archiveio.WriteVerified(ctx, a.output, ".inventory.json", data, func(input io.Reader) error {
		_, err := inventoryarchive.Verify(ctx, input, a.public)
		return err
	})
	if err != nil {
		return backup.CLIFailure("inventory read-back", err)
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
		Path   string                  `json:"path"`
		Report inventoryarchive.Report `json:"archive"`
	}{path, report})
}
