package main

import (
	"crypto/ecdsa"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/alphabravocompany/constellation/internal/bundle"
	pkgversion "github.com/alphabravocompany/constellation/pkg/version"
)

// bundleCmd builds, verifies and loads signed air-gap bundles (guide ch.09).
func bundleCmd() *cobra.Command {
	c := &cobra.Command{Use: "bundle", Short: "Build, verify and load signed air-gap deployment bundles"}
	c.AddCommand(bundleBuildCmd(), bundleVerifyCmd(), bundleLoadCmd(), bundleResolveCmd())
	return c
}

func bundleBuildCmd() *cobra.Command {
	var (
		out, chartDir, signKeyPath, ver string
		images                          []string
		fromDaemon                      bool
	)
	c := &cobra.Command{
		Use:   "build",
		Short: "Write an OCI layout of every image, the chart, and a cosign-compatible signed BOM",
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := bundle.BuildOptions{Out: out, Name: "constellation", Version: ver, Images: images, FromDaemon: fromDaemon, ChartDir: chartDir, Logger: slog.Default()}
			if signKeyPath != "" {
				pemBytes, err := os.ReadFile(signKeyPath)
				if err != nil {
					return err
				}
				key, err := bundle.ParsePrivateKey(pemBytes)
				if err != nil {
					return err
				}
				opts.SignKey = key
			} else {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: --sign-key not set; the bundle will be rejected by `bundle load`")
			}
			m, err := bundle.Build(cmd.Context(), opts)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "bundle %s %s: %d images, %d files -> %s\n", m.Name, m.Version, len(m.Images), len(m.Files), out)
			return nil
		},
	}
	c.Flags().StringVar(&out, "out", "", "output directory (required)")
	c.Flags().StringArrayVar(&images, "image", nil, "image reference to include (repeatable)")
	c.Flags().StringVar(&chartDir, "chart", "", "chart directory to include")
	c.Flags().StringVar(&signKeyPath, "sign-key", "", "ECDSA P-256 private key (PEM; cosign.key format without encryption)")
	c.Flags().StringVar(&ver, "version", pkgversion.Version, "bundle version")
	c.Flags().BoolVar(&fromDaemon, "from-daemon", false, "read images from the local Docker daemon instead of pulling")
	_ = c.MarkFlagRequired("out")
	_ = c.MarkFlagRequired("image")
	return c
}

func bundleVerifyCmd() *cobra.Command {
	var trustKeyPath string
	c := &cobra.Command{
		Use:   "verify <dir>",
		Short: "Verify the BOM signature (embedded vendor key or --trust-key) and every payload digest",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, err := trustKey(trustKeyPath)
			if err != nil {
				return err
			}
			m, err := bundle.Verify(args[0], pub)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "verified %s %s: %d images, %d files, created %s\n", m.Name, m.Version, len(m.Images), len(m.Files), m.CreatedAt.Format("2006-01-02T15:04:05Z"))
			for _, im := range m.Images {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s  %s\n", im.Digest, im.Ref)
			}
			return nil
		},
	}
	c.Flags().StringVar(&trustKeyPath, "trust-key", "", "public key PEM overriding the embedded vendor key")
	return c
}

func bundleLoadCmd() *cobra.Command {
	var (
		trustKeyPath, reg, fallback, valuesOut, ctrCmd string
		insecure, containerd, dryRun                   bool
	)
	c := &cobra.Command{
		Use:   "load <dir>",
		Short: "Verify, then push every image into the cluster-local registry (or import into containerd)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, err := trustKey(trustKeyPath)
			if err != nil {
				return err
			}
			opts := bundle.LoadOptions{Dir: args[0], TrustKey: pub, Registry: reg, Insecure: insecure, Fallback: fallback,
				Containerd: containerd, ValuesOut: valuesOut, DryRun: dryRun, Logger: slog.Default()}
			if ctrCmd != "" {
				opts.ContainerdCmd = strings.Fields(ctrCmd)
			}
			rep, err := bundle.Load(cmd.Context(), opts)
			if err != nil {
				return err
			}
			for _, li := range rep.Loaded {
				fmt.Fprintf(cmd.OutOrStdout(), "%-9s %s -> %s (%s)\n", li.Layer, li.Source, li.Target, li.Digest)
			}
			return nil
		},
	}
	c.Flags().StringVar(&trustKeyPath, "trust-key", "", "public key PEM overriding the embedded vendor key")
	c.Flags().StringVar(&reg, "registry", "", "cluster-local registry host[:port] to push into")
	c.Flags().BoolVar(&insecure, "insecure", false, "plain-HTTP registry")
	c.Flags().StringVar(&fallback, "fallback", "", "fallback registry consulted by the resolver after local (empty = fail closed)")
	c.Flags().BoolVar(&containerd, "containerd", false, "import into the node's containerd image store (k3s) instead of a registry")
	c.Flags().StringVar(&ctrCmd, "ctr", "", "containerd client command (default \"k3s ctr\")")
	c.Flags().StringVar(&valuesOut, "values-out", "", "write a Helm values file pinning every image to the loaded digest")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "verify and plan without pushing")
	return c
}

func bundleResolveCmd() *cobra.Command {
	var reg, fallback string
	var insecure bool
	c := &cobra.Command{
		Use:   "resolve <image-ref>",
		Short: "Show which registry layer (local, fallback) serves an image; exits non-zero when none does",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := &bundle.Resolver{Local: reg, Fallback: fallback, Insecure: insecure, Logger: slog.Default()}
			ref, layer, err := r.Resolve(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", layer, ref)
			return nil
		},
	}
	c.Flags().StringVar(&reg, "registry", "", "cluster-local registry host[:port]")
	c.Flags().StringVar(&fallback, "fallback", "", "fallback registry host[:port]")
	c.Flags().BoolVar(&insecure, "insecure", false, "plain-HTTP registries")
	_ = c.MarkFlagRequired("registry")
	return c
}

func trustKey(path string) (*ecdsa.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bundle.ParsePublicKey(pemBytes)
}
