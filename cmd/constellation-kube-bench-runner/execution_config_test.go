package main

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/yaml"
)

func TestExecutionWorkerConfigRequiresExplicitDurabilityAndIdentity(t *testing.T) {
	t.Setenv("BENCH_EXECUTION_WORKER", "true")
	t.Setenv("BENCH_STATE_DIR", t.TempDir()+"/private")
	t.Setenv("POD_UID", uuid.NewString())
	cfg := config{apiURL: "http://private-control-plane:8080", profile: "kube-bench", node: "node-1"}
	if err := configureExecutionWorker(&cfg); err != nil || !cfg.durableWorker || cfg.watchInterval != 30*time.Second {
		t.Fatalf("explicit worker rejected trusted private origin: %v", err)
	}
	for _, origin := range []string{"file:///tmp/api", "http://user:password@host", "https://host/api", "https://host?token=secret"} {
		copy := cfg
		copy.apiURL = origin
		if err := configureExecutionWorker(&copy); err == nil {
			t.Fatal("invalid worker origin accepted")
		}
	}
	cfg.profile = "docker-bench"
	if err := configureExecutionWorker(&cfg); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatal("unbundled docker benchmark worker advertised")
	}
}

func TestExecutionWorkerExecutableFailureIsRedacted(t *testing.T) {
	_, outcome := executeDurableBenchmark(t.Context(), config{binary: "/bin/sh", args: []string{"-c", "printf private-error >&2; exit 2"}})
	if outcome != "exec_failed" {
		t.Fatal("failed execution reported success")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, outcome = executeDurableBenchmark(ctx, config{binary: "/bin/true"})
	if outcome != "interrupted" {
		t.Fatal("canceled execution reported success")
	}
	deadline, stop := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer stop()
	_, outcome = executeDurableBenchmark(deadline, config{binary: "/bin/sleep", args: []string{"10"}})
	if outcome != "timeout" {
		t.Fatal("timed-out execution reported success")
	}
	raw, outcome := executeDurableBenchmark(t.Context(), config{binary: "/bin/printf", args: []string{"%s", durableReport}})
	if outcome != "report_ingested" || string(raw) != durableReport {
		t.Fatal("valid report output lost")
	}
}

func TestChartDurableBenchmarkWorkerRequiresPersistentState(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("Helm required for actual chart rendering")
	}
	args := []string{"template", "bench-contract", "../../deploy/charts/constellation", "--set", "kubeBenchWorker.enabled=true", "--set", "kubeBenchWorker.image.repository=example.invalid/qualified-runner", "--set", "kubeBenchWorker.state.existingClaim=private-bench-state", "--set", "kubeBenchWorker.benchmark=eks-1.4.0", "--show-only", "templates/kube-bench-worker-deployment.yaml"}
	raw, err := exec.CommandContext(t.Context(), "helm", args...).Output()
	if err != nil {
		t.Fatalf("worker chart could not render: %v", err)
	}
	var deployment appsv1.Deployment
	if err := yaml.Unmarshal(raw, &deployment); err != nil {
		t.Fatal(err)
	}
	assertBenchmarkWorkerDeployment(t, deployment)
	args = []string{"template", "bench-contract", "../../deploy/charts/constellation", "--set", "kubeBenchWorker.enabled=true", "--set", "kubeBenchWorker.image.repository=example.invalid/qualified-runner"}
	if _, err := exec.CommandContext(t.Context(), "helm", args...).Output(); err == nil {
		t.Fatal("worker rendered without a durable claim")
	}
	args = []string{"template", "bench-contract", "../../deploy/charts/constellation", "--set", "dockerBenchWorker.enabled=true"}
	if _, err := exec.CommandContext(t.Context(), "helm", args...).Output(); err == nil {
		t.Fatal("unsupported docker worker silently rendered")
	}
}

func assertBenchmarkWorkerDeployment(t *testing.T, deployment appsv1.Deployment) {
	t.Helper()
	spec := deployment.Spec.Template.Spec
	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType || !spec.HostPID {
		t.Fatal("worker lifecycle changed")
	}
	container := spec.Containers[0]
	values := map[string]string{}
	fields := map[string]string{}
	for _, env := range container.Env {
		values[env.Name] = env.Value
		if env.ValueFrom != nil && env.ValueFrom.FieldRef != nil {
			fields[env.Name] = env.ValueFrom.FieldRef.FieldPath
		}
	}
	if values["BENCH_EXECUTION_WORKER"] != "true" || values["BENCH_STATE_DIR"] != "/var/lib/constellation-bench/state" || values["BENCH_VERSION"] != "eks-1.4.0" || values["RUNTIME_AGENT_TOKEN_FILE"] == "" || fields["NODE_NAME"] != "spec.nodeName" || fields["POD_UID"] != "metadata.uid" || container.WorkingDir != "/opt/kube-bench" {
		t.Fatal("worker lost configured pin, node/runner identity, or durable token/state contract")
	}
	for _, volume := range spec.Volumes {
		if volume.Name == "execution-state" && (volume.PersistentVolumeClaim == nil || volume.PersistentVolumeClaim.ClaimName != "private-bench-state") {
			t.Fatal("worker state became ephemeral")
		}
	}
}
