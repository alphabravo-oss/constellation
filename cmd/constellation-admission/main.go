// constellation-admission is the Kubernetes admission webhook service.
//
// It serves /validate over HTTPS, evaluating AdmissionReview requests through the
// pkg/admission engine. The Helm chart wires a ValidatingWebhookConfiguration that points
// here; cert material is mounted at /etc/webhook/certs (cert-manager-issued or
// operator-bootstrapped).
//
// Scaling: 2-3 replicas behind a Service. Each replica is stateless; optional
// DB-backed policy rows are refreshed on a ticker and swapped into the engine atomically.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	admissionv1 "k8s.io/api/admission/v1"

	"github.com/alphabravocompany/constellation/internal/admissionevidence"
	rtquar "github.com/alphabravocompany/constellation/internal/runtime/quarantine"
	"github.com/alphabravocompany/constellation/pkg/admission"
	"github.com/alphabravocompany/constellation/pkg/observability"
	"github.com/alphabravocompany/constellation/pkg/quarantine"
	"github.com/alphabravocompany/constellation/pkg/version"
)

func main() {
	addr := flag.String("listen", ":8443", "HTTPS listen address")
	certFile := flag.String("tls-cert", "/etc/webhook/certs/tls.crt", "TLS cert")
	keyFile := flag.String("tls-key", "/etc/webhook/certs/tls.key", "TLS key")
	insecure := flag.Bool("insecure", false, "Listen plain HTTP (dev/test only)")
	// E4: quarantine source. The webhook polls the DB every refreshInterval
	// and applies the resulting snapshot in-process. dsn empty = feature off;
	// the engine then behaves identically to pre-E4 builds.
	quarantineDSN := flag.String("quarantine-dsn", os.Getenv("CONSTELLATION_QUARANTINE_DSN"), "Postgres DSN for the quarantine table (empty = feature disabled)")
	quarantineCluster := flag.String("quarantine-cluster-id", os.Getenv("CONSTELLATION_CLUSTER_ID"), "Cluster UUID this webhook scopes to")
	quarantineRefresh := flag.Duration("quarantine-refresh", 5*time.Second, "Poll interval for quarantine table")
	quarantineMaxStale := flag.Duration("quarantine-max-stale", 60*time.Second, "Mark /readyz unhealthy if the snapshot age exceeds this")
	policyDSN := flag.String("policy-dsn", os.Getenv("CONSTELLATION_ADMISSION_POLICY_DSN"), "Postgres DSN for admission policy rows (empty = built-ins only)")
	policyCluster := flag.String("policy-cluster-id", os.Getenv("CONSTELLATION_CLUSTER_ID"), "Cluster UUID used to scope admission policy rows")
	policyRefresh := flag.Duration("policy-refresh", 10*time.Second, "Poll interval for admission policy rows")
	auditDSN := flag.String("audit-dsn", os.Getenv("CONSTELLATION_ADMISSION_AUDIT_DSN"), "Postgres DSN for admission deny audit events (empty = disabled)")
	auditCluster := flag.String("audit-cluster-id", os.Getenv("CONSTELLATION_CLUSTER_ID"), "Cluster UUID used to attach admission deny audit events to an org")
	// C3: RBAC resolver for the saBindRiskyRole criterion. Enabled by default
	// (in-cluster); set --rbac-enabled=false to disable when the webhook has no
	// RBAC read access. --rbac-kubeconfig overrides in-cluster config for dev.
	rbacEnabled := flag.Bool("rbac-enabled", true, "Resolve pod ServiceAccount RBAC for the saBindRiskyRole admission criterion")
	rbacKubeconfig := flag.String("rbac-kubeconfig", os.Getenv("KUBECONFIG"), "kubeconfig for the RBAC resolver (empty = in-cluster)")
	rbacRefresh := flag.Duration("rbac-refresh", 30*time.Second, "Poll interval for the RBAC snapshot")
	// A5: namespace label resolver for per-rule match.namespaceSelector. Enabled
	// by default (in-cluster informer/lister); set --nslabels-enabled=false to
	// disable when the webhook has no namespaces list/watch grant. Unwired, a rule
	// carrying a namespaceSelector safely never fires (name-based Namespaces work).
	nsLabelsEnabled := flag.Bool("nslabels-enabled", true, "Resolve namespace labels for per-rule match.namespaceSelector scoping (A5)")
	nsLabelsKubeconfig := flag.String("nslabels-kubeconfig", os.Getenv("KUBECONFIG"), "kubeconfig for the namespace label resolver (empty = in-cluster)")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	tel, err := observability.Init(ctx, "constellation-admission")
	if err != nil {
		_, _ = os.Stderr.WriteString("observability init: " + err.Error() + "\n")
		os.Exit(1)
	}
	version.LogStartup(tel.Logger, "admission")
	defer func() {
		sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = tel.Shutdown(sctx)
	}()

	policyEngine := admission.NewEngine()
	// Composite engine: the built-in PolicyEngine plus the (optional) Rego and
	// CEL engines loaded from engine='opa'/'cel' policy rows. Without the chain
	// those rows would never be evaluated (silent fail-open). Quarantine,
	// evidence and OnDeny stay wired on the built-in engine below.
	chain := admission.NewChainEngine(policyEngine)
	engine := policyEngine

	// Wire up quarantine if configured. We deliberately don't gate on
	// "engine has rules" — quarantine is a runtime-driven deny list and
	// works whether or not custom policies exist.
	var qsrc *quarantine.Source
	if *quarantineDSN != "" && *quarantineCluster != "" {
		clusterID, err := uuid.Parse(*quarantineCluster)
		if err != nil {
			_, _ = os.Stderr.WriteString("invalid --quarantine-cluster-id: " + err.Error() + "\n")
			os.Exit(1)
		}
		pool, err := pgxpool.New(ctx, *quarantineDSN)
		if err != nil {
			_, _ = os.Stderr.WriteString("quarantine pool: " + err.Error() + "\n")
			os.Exit(1)
		}
		defer pool.Close()
		qsrc = quarantine.NewSource(&rtquar.PgLoader{Pool: pool}, clusterID, *quarantineRefresh)
		// Initial fetch in the foreground so the first admission request
		// after readiness sees a populated snapshot. Fail-open on initial
		// error (matches the architectural choice that a control-plane
		// outage must not block pod creation).
		if err := qsrc.Refresh(ctx); err != nil {
			tel.Logger.Warn("quarantine initial fetch failed; serving empty snapshot",
				"err", err)
		}
		go qsrc.Run(ctx)
		engine.SetQuarantine(qsrc)
		tel.Logger.Info("quarantine source enabled",
			"cluster_id", clusterID, "refresh", *quarantineRefresh)
	}

	if *policyDSN != "" {
		if *policyCluster == "" {
			_, _ = os.Stderr.WriteString("--policy-cluster-id is required when --policy-dsn is set\n")
			os.Exit(1)
		}
		clusterID, err := uuid.Parse(*policyCluster)
		if err != nil {
			_, _ = os.Stderr.WriteString("invalid --policy-cluster-id: " + err.Error() + "\n")
			os.Exit(1)
		}
		pool, err := pgxpool.New(ctx, *policyDSN)
		if err != nil {
			_, _ = os.Stderr.WriteString("admission policy pool: " + err.Error() + "\n")
			os.Exit(1)
		}
		defer pool.Close()
		orgID, err := waitForClusterOrgID(ctx, pool, clusterID, 2*time.Minute, tel.Logger)
		if err != nil {
			_, _ = os.Stderr.WriteString("admission evidence source: " + err.Error() + "\n")
			os.Exit(1)
		}
		evidence := admissionevidence.New(pool, orgID)
		engine.SetEvidenceSource(evidence)
		if n, err := refreshAdmissionPolicies(ctx, chain, pool, clusterID, tel.Logger); err != nil {
			tel.Logger.Warn("admission policy initial refresh failed; serving built-in rules",
				"err", err)
		} else {
			tel.Logger.Info("admission policy source enabled",
				"cluster_id", clusterID, "org_id", orgID, "refresh", *policyRefresh, "db_rules", n)
		}
		go runAdmissionPolicyRefresh(ctx, chain, pool, clusterID, *policyRefresh, tel.Logger)
	}

	// Always emit the admission_decisions_total Prometheus counter on the real
	// deny/monitor path, keyed by rule id, independent of whether DB audit is
	// enabled. Allows are counted in validateHandler (an allowed request that hit
	// no rule fires no hook). Set on both
	// the PolicyEngine (built-in / quarantine / PVC denies) and the ChainEngine
	// (Rego/CEL denies) so every deny type is counted; when audit is enabled the
	// block below wraps this hook via chainDenyHooks so both still run.
	metricsDeny := func(_ context.Context, ev admission.DenyEvent) {
		// Monitor-mode matches admit the request but still count as a distinct
		// decision keyed by rule id, so operators can see monitor-rule activity in
		// admission_decisions_total before flipping the rule to enforce.
		decision := "deny"
		if ev.Monitor {
			decision = "monitor"
		}
		tel.RecordAdmissionDecision(decision, ev.RuleID)
	}
	engine.OnDeny = metricsDeny
	chain.SetOnDeny(metricsDeny)

	if *auditDSN != "" {
		if *auditCluster == "" {
			_, _ = os.Stderr.WriteString("--audit-cluster-id is required when --audit-dsn is set\n")
			os.Exit(1)
		}
		clusterID, err := uuid.Parse(*auditCluster)
		if err != nil {
			_, _ = os.Stderr.WriteString("invalid --audit-cluster-id: " + err.Error() + "\n")
			os.Exit(1)
		}
		pool, err := pgxpool.New(ctx, *auditDSN)
		if err != nil {
			_, _ = os.Stderr.WriteString("admission audit pool: " + err.Error() + "\n")
			os.Exit(1)
		}
		defer pool.Close()
		hook, orgID, err := newAdmissionAuditHook(ctx, pool, clusterID, tel.Logger)
		if err != nil {
			_, _ = os.Stderr.WriteString("admission audit hook: " + err.Error() + "\n")
			os.Exit(1)
		}
		// Offload the deny-path DB writes (audit INSERT + response-rule SELECT +
		// quarantine INSERTs) to a background worker so the deny verdict returns
		// immediately and a slow DB can't push the webhook past the API server
		// timeout (which, under failurePolicy: Ignore, would turn a deny into an
		// admit). Close() on shutdown drains the queue so no audit is lost.
		async := admission.NewAsyncDenyHook(context.Background(), chainDenyHooks(engine.OnDeny, hook), 2048)
		defer func() {
			dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer dcancel()
			async.Close(dctx)
		}()
		asyncHook := async.Hook()
		// Built-in/quarantine/PVC denies fire through the PolicyEngine; Rego/CEL
		// denies fire through the ChainEngine. Wire the same async hook to both so
		// every enforce deny is audited and runs its response rules off-path.
		engine.OnDeny = asyncHook
		chain.SetOnDeny(asyncHook)
		tel.Logger.Info("admission audit enabled", "cluster_id", clusterID, "org_id", orgID)
	}

	// C3: wire the RBAC resolver so the saBindRiskyRole criterion can resolve a
	// pod ServiceAccount's bound (Cluster)Roles. Fail-open on setup error — a
	// missing RBAC read grant must not take the whole webhook down; rules using
	// saBindRiskyRole simply won't fire (the resolver stays nil).
	rbacOn := false
	if *rbacEnabled {
		resolver, err := newClusterRBACResolver(ctx, *rbacKubeconfig, tel.Logger)
		if err != nil {
			tel.Logger.Warn("admission RBAC resolver disabled; saBindRiskyRole rules will not fire", "err", err)
		} else {
			engine.SetRBAC(resolver)
			go resolver.run(ctx, *rbacRefresh)
			rbacOn = true
			tel.Logger.Info("admission RBAC resolver enabled", "refresh", *rbacRefresh)
		}
	}

	// A5: wire the namespace label resolver so per-rule match.namespaceSelector
	// rules can fire. Fail-open on setup error — a missing namespaces list/watch
	// grant (or unavailable in-cluster config) must not take the webhook down;
	// selector rules simply keep safely no-firing (the labeler stays nil).
	nsLabelsOn := false
	if *nsLabelsEnabled {
		resolver, err := newNamespaceLabelResolver(ctx, *nsLabelsKubeconfig, tel.Logger)
		if err != nil {
			tel.Logger.Warn("admission namespace label resolver disabled; namespaceSelector rules will not fire", "err", err)
		} else {
			engine.SetNamespaceLabeler(resolver)
			nsLabelsOn = true
			tel.Logger.Info("admission namespace label resolver enabled")
		}
	}

	go version.HeartbeatLoop(ctx, version.HeartbeatConfigFromEnv("admission", version.HeartbeatEnvOptions{
		TokenEnv:     []string{"CONSTELLATION_ADMISSION_TOKEN", "RUNTIME_AGENT_TOKEN", "SCANNER_TOKEN"},
		TokenFileEnv: []string{"CONSTELLATION_ADMISSION_TOKEN_FILE", "RUNTIME_AGENT_TOKEN_FILE"},
		Logger:       tel.Logger,
		MetadataFn: func() any {
			return map[string]any{
				"tls_enabled":           !*insecure,
				"quarantine_enabled":    qsrc != nil,
				"policy_source_enabled": strings.TrimSpace(*policyDSN) != "",
				"audit_enabled":         strings.TrimSpace(*auditDSN) != "",
				"rbac_enabled":          rbacOn,
				"nslabels_enabled":      nsLabelsOn,
			}
		},
	}))

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", validateHandler(chain, tel))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		// When the quarantine source is enabled, refuse to serve if the
		// snapshot is too stale. A stale snapshot means we'd be admitting
		// pods our control plane already wanted blocked.
		if qsrc != nil {
			h := qsrc.Health()
			if h.Age > *quarantineMaxStale {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprintf(w, "quarantine snapshot stale by %s (max %s; last error: %s)",
					h.Age.Round(time.Second), *quarantineMaxStale, h.LastError)
				return
			}
		}
		_, _ = w.Write([]byte("ready"))
	})
	mux.HandleFunc("/quarantine/health", func(w http.ResponseWriter, _ *http.Request) {
		if qsrc == nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"enabled":false}`))
			return
		}
		h := qsrc.Health()
		ns, wl, img := qsrc.Current().Stats()
		out := map[string]any{
			"enabled":         true,
			"last_refresh":    h.LastRefresh,
			"age_seconds":     h.Age.Seconds(),
			"successes":       h.Successes,
			"failures":        h.Failures,
			"last_error":      h.LastError,
			"namespace_count": ns,
			"workload_count":  wl,
			"image_count":     img,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.Handle("/metrics", tel.MetricsHandler())

	srv := &http.Server{
		Addr:              *addr,
		Handler:           tel.HTTPMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if *insecure {
			tel.Logger.Warn("admission webhook listening over plain HTTP (development only)", "addr", *addr)
			errCh <- srv.ListenAndServe()
			return
		}
		tel.Logger.Info("admission webhook listening", "addr", *addr)
		errCh <- srv.ListenAndServeTLS(*certFile, *keyFile)
	}()

	select {
	case <-ctx.Done():
		sctx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = srv.Shutdown(sctx)
		return
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return
		}
		tel.Logger.Error("admission server exited", "err", err.Error())
		os.Exit(1)
	}
}

func validateHandler(engine admission.Engine, tel *observability.Telemetry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var review admissionv1.AdmissionReview
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if review.Request == nil {
			http.Error(w, "missing request", http.StatusBadRequest)
			return
		}
		resp := engine.Evaluate(r.Context(), review.Request)
		// admission_decisions_total: count allows here (they fire no deny hook);
		// denies are counted per rule id by the metrics deny hook wired in run().
		// tel is nil-safe.
		if resp.Allowed {
			tel.RecordAdmissionDecision("allow", "")
		}
		out := admissionv1.AdmissionReview{
			TypeMeta: review.TypeMeta,
			Response: resp,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}
