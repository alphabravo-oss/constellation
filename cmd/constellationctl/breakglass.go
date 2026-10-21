package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/alphabravocompany/constellation/internal/identity"
)

func breakGlassCmd() *cobra.Command {
	return &cobra.Command{Use: "break-glass-hash", Short: "Hash an emergency administrator password read from stdin", RunE: func(cmd *cobra.Command, _ []string) error {
		raw, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 4097))
		if err != nil {
			return err
		}
		password := strings.TrimSuffix(string(raw), "\n")
		if len(password) < 16 || len(password) > 4096 {
			return fmt.Errorf("emergency password must contain 16–4096 bytes")
		}
		hash, err := identity.HashPassword(password)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), hash)
		return err
	}}
}
