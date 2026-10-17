package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
)

type claimedBenchRun struct {
	ID        string `json:"id"`
	ClusterID string `json:"cluster_id"`
	Profile   string `json:"profile"`
	Benchmark string `json:"benchmark"`
	Status    string `json:"status"`
}

func claimedBenchmarkConfig(cfg config, claim claimedBenchRun) (config, error) {
	id, err := uuid.Parse(claim.ID)
	cluster, clusterErr := uuid.Parse(claim.ClusterID)
	profile, ok := compliancepkg.NormalizeBenchProfile(claim.Profile)
	configured, configuredOK := compliancepkg.NormalizeBenchProfile(cfg.profile)
	if err != nil || id == uuid.Nil || clusterErr != nil || cluster == uuid.Nil || claim.Status != "claimed" || claim.Profile == "" || !ok || !configuredOK || profile != configured || !compliancepkg.ValidBenchmarkID(claim.Benchmark) {
		return config{}, errors.New("invalid benchmark claim receipt")
	}
	if cfg.clusterID != "" {
		expected, err := uuid.Parse(cfg.clusterID)
		if err != nil || expected != cluster {
			return config{}, errors.New("benchmark claim cluster mismatch")
		}
	}
	out := cfg
	out.profile, out.clusterID, out.benchmark = profile, cluster.String(), claim.Benchmark
	out.args = nil
	for index := 0; index < len(cfg.args); index++ {
		argument := cfg.args[index]
		if argument == "--benchmark" {
			index++
			continue
		}
		if strings.HasPrefix(argument, "--benchmark=") {
			continue
		}
		out.args = append(out.args, argument)
	}
	if claim.Benchmark != "" {
		out.args = append(out.args, "--benchmark", claim.Benchmark)
	}
	return out, nil
}

func decodeBenchmarkReceipt(reader io.Reader, value any) error {
	raw, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		return errors.New("invalid benchmark receipt")
	}
	if err := json.Unmarshal(raw, value); err != nil {
		return errors.New("invalid benchmark receipt")
	}
	return nil
}

// The control plane is configured/trusted (including private origins). Fixed
// API paths need no redirects, and must not forward the service credential.
func benchmarkClient(client *http.Client) *http.Client {
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copy
}

func runClaimedBenchmark(ctx context.Context, client *http.Client, cfg config, claim claimedBenchRun, logger *slog.Logger) error {
	invocation, err := claimedBenchmarkConfig(cfg, claim)
	if err != nil {
		return err
	}
	return runAndIngest(ctx, client, invocation, logger)
}
