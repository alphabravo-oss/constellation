// constellation-operator reconciles ConstellationCluster CRs into in-cluster components
// (scanner aggregator, admission webhook, runtime agent DaemonSet, audit/vulndb CronJobs).
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cv1alpha1 "github.com/alphabravocompany/constellation/deploy/operator/api/v1alpha1"
	"github.com/alphabravocompany/constellation/deploy/operator/controllers"
	"github.com/alphabravocompany/constellation/deploy/operator/policydb"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/obslog"
	"github.com/alphabravocompany/constellation/pkg/version"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cv1alpha1.AddToScheme(scheme))
}

func main() {
	defaultManagedNamespace := firstNonEmpty(os.Getenv("OPERATOR_NAMESPACE"), os.Getenv("WATCH_NAMESPACE"), "constellation-system")
	defaultWatchNamespace := strings.TrimSpace(os.Getenv("WATCH_NAMESPACE"))

	addr := flag.String("metrics-bind-address", ":8081", "Operator /metrics address")
	probe := flag.String("health-probe-bind-address", ":8082", "Operator probe address")
	leader := flag.Bool("leader-elect", false, "Enable leader election")
	namespace := flag.String("namespace", defaultManagedNamespace, "Namespace where managed workloads are created")
	watchNamespace := flag.String("watch-namespace", defaultWatchNamespace, "Namespace to watch for namespaced resources; empty watches all namespaces")
	agentImage := flag.String("agent-image", "ghcr.io/alphabravocompany/constellation-agent:latest", "Default agent image")
	databaseURL := flag.String("database-url", firstNonEmpty(os.Getenv("CONSTELLATION_DATABASE_URL"), os.Getenv("DATABASE_URL")), "Constellation DB DSN for policy-CR reconciliation; when empty the policy controllers are not started")
	flag.Parse()
	*namespace = strings.TrimSpace(*namespace)
	*watchNamespace = strings.TrimSpace(*watchNamespace)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: obslog.Level()})).With("svc", "constellation-operator")
	logger.Info("operator starting",
		slog.String("metrics", *addr),
		slog.String("probe", *probe),
		slog.Bool("leader", *leader),
		slog.String("namespace", *namespace),
		slog.String("watch_namespace", *watchNamespace))
	version.LogStartup(logger, "operator")

	// Wave N6: operator heartbeat goroutine. Bound to the manager's signal
	// context so it stops cleanly when controller-runtime tears down. Env
	// vars mirror the other components: CONSTELLATION_API_URL +
	// CONSTELLATION_OPERATOR_TOKEN (a scanner-token or runtime-agent-token).
	hbCtx, hbCancel := context.WithCancel(context.Background())
	defer hbCancel()
	go version.HeartbeatLoop(hbCtx, version.HeartbeatConfigFromEnv("operator", version.HeartbeatEnvOptions{
		TokenEnv:     []string{"CONSTELLATION_OPERATOR_TOKEN", "RUNTIME_AGENT_TOKEN", "SCANNER_TOKEN"},
		TokenFileEnv: []string{"CONSTELLATION_OPERATOR_TOKEN_FILE", "RUNTIME_AGENT_TOKEN_FILE"},
		Logger:       logger,
		MetadataFn: func() any {
			return map[string]any{
				"managed_namespace": *namespace,
				"watch_namespace":   *watchNamespace,
				"leader_election":   *leader,
			}
		},
	}))

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	opts := manager.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: *addr,
		},
		HealthProbeBindAddress: *probe,
		LeaderElection:         *leader,
		LeaderElectionID:       "constellation-operator.alphabravo.io",
	}
	if *namespace != "" {
		opts.LeaderElectionNamespace = *namespace
	}
	if *watchNamespace != "" {
		opts.Cache.DefaultNamespaces = map[string]cache.Config{*watchNamespace: {}}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), opts)
	if err != nil {
		logger.Error("unable to start manager", slog.String("err", err.Error()))
		os.Exit(1)
	}

	if err := (&controllers.Reconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		OperatorNamespace: *namespace,
		DefaultAgentImage: *agentImage,
	}).SetupWithManager(mgr); err != nil {
		logger.Error("unable to create controller", slog.String("err", err.Error()))
		os.Exit(1)
	}

	// Policy-CR reconcilers bridge ConstellationAdmissionRule / ConstellationResponseRule
	// CRs into the Constellation policy store. They require a DB DSN; when none is provided
	// the operator runs cluster reconciliation only (e.g. data-plane-only deployments).
	if dsn := strings.TrimSpace(*databaseURL); dsn != "" {
		database, err := db.Connect(context.Background(), dsn)
		if err != nil {
			logger.Error("unable to connect policy store", slog.String("err", err.Error()))
			os.Exit(1)
		}
		defer database.Close()
		store := policydb.New(database.Pool())

		if err := (&controllers.AdmissionRuleReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
			Store:  store,
		}).SetupWithManager(mgr); err != nil {
			logger.Error("unable to create admission-rule controller", slog.String("err", err.Error()))
			os.Exit(1)
		}
		if err := (&controllers.ResponseRuleReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
			Store:  store,
		}).SetupWithManager(mgr); err != nil {
			logger.Error("unable to create response-rule controller", slog.String("err", err.Error()))
			os.Exit(1)
		}
		// P0-08 — policy-groups reconcilers (ConstellationGroup + ConstellationNetworkRule):
		// GitOps for NeuVector-style workload groups and group→group network segmentation edges.
		if err := controllers.SetupGroupControllers(mgr, store); err != nil {
			logger.Error("unable to create policy-groups controllers", slog.String("err", err.Error()))
			os.Exit(1)
		}
		logger.Info("policy-CR reconcilers enabled")
	} else {
		logger.Info("policy-CR reconcilers disabled (no database-url)")
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		logger.Error("unable to set up health check", slog.String("err", err.Error()))
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		logger.Error("unable to set up readyz check", slog.String("err", err.Error()))
		os.Exit(1)
	}

	logger.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error("manager exited", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
