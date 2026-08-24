// constellation-discoverer watches a single Kubernetes cluster's API server, projects every
// Deployment / StatefulSet / DaemonSet into the Constellation `deployments` table, and links
// each row to the matching `clusters` row by name.
//
// It also creates / refreshes a matching `assets` row (kind='deployment') so any future
// finding emitted by the scanner can attach to the workload by asset_id. After every
// reconciliation pass it rolls up findings per workload (joined via the matching asset row)
// and writes finding_count / critical_count / high_count / risk_score / risk_factors back to
// the deployment row.
//
// The discoverer is configured per-cluster via environment variables:
//
//   - DATABASE_URL          postgres://...                       (required)
//   - KUBECONFIG            path to a kubeconfig                 (required if not in-cluster)
//   - CLUSTER_NAME          must match a `clusters.name` row     (required)
//   - ORG_ID                uuid of the org the cluster belongs to (required)
//   - NAMESPACE_FILTER      csv globs of namespaces to include; default "*" (kube-system always excluded)
//   - RECONCILE_INTERVAL    default 30s
//   - ONE_SHOT              "true" runs a single reconcile pass then exits (used by integration tests)
//
// Three invocations cover the dev environment:
//
//	CLUSTER_NAME=prod-us-east-1 KUBECONFIG=/tmp/kubeconfig-constellation.yaml  ORG_ID=<dev-org> ./constellation-discoverer
//	CLUSTER_NAME=edge-eu-west-1 KUBECONFIG=/tmp/kubeconfig-edge.yaml            ORG_ID=<dev-org> ./constellation-discoverer
//	CLUSTER_NAME=dev-local      KUBECONFIG=/tmp/kubeconfig-k3s                  ORG_ID=<dev-org> ./constellation-discoverer
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/imageid"
	"github.com/alphabravocompany/constellation/internal/obslog"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	defaultInterval        = 30 * time.Second
	excludedSystem         = "kube-system"
	defaultPodIPsRetention = 24 * time.Hour
)

type config struct {
	databaseURL     string
	kubeconfig      string
	clusterName     string
	orgID           uuid.UUID
	orgIDSet        bool
	nsGlobs         []string
	interval        time.Duration
	oneShot         bool
	podIPsRetention time.Duration
}

func loadConfig() (config, error) {
	c := config{}
	c.databaseURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if c.databaseURL == "" {
		return c, errors.New("DATABASE_URL is required")
	}
	c.kubeconfig = strings.TrimSpace(os.Getenv("KUBECONFIG"))
	if c.kubeconfig == "" {
		home, _ := os.UserHomeDir()
		def := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(def); err == nil {
			c.kubeconfig = def
		}
	}
	c.clusterName = strings.TrimSpace(os.Getenv("CLUSTER_NAME"))
	if c.clusterName == "" {
		return c, errors.New("CLUSTER_NAME is required")
	}
	rawOrg := strings.TrimSpace(os.Getenv("ORG_ID"))
	if rawOrg != "" {
		id, err := uuid.Parse(rawOrg)
		if err != nil {
			return c, fmt.Errorf("ORG_ID is not a valid uuid: %w", err)
		}
		c.orgID = id
		c.orgIDSet = true
	}

	rawNs := strings.TrimSpace(os.Getenv("NAMESPACE_FILTER"))
	if rawNs == "" {
		rawNs = "*"
	}
	for _, part := range strings.Split(rawNs, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			c.nsGlobs = append(c.nsGlobs, part)
		}
	}

	c.interval = defaultInterval
	if v := strings.TrimSpace(os.Getenv("RECONCILE_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.interval = d
		}
	}
	c.oneShot = strings.EqualFold(os.Getenv("ONE_SHOT"), "true")

	// pod_ips now retains history (one row per pod-generation+ip) so late/backfill
	// resolution works; keep rows for a long, configurable horizon rather than 2x
	// the poll interval. POD_IPS_RETENTION_HOURS is a whole number of hours.
	c.podIPsRetention = defaultPodIPsRetention
	if v := strings.TrimSpace(os.Getenv("POD_IPS_RETENTION_HOURS")); v != "" {
		if h, err := strconv.Atoi(v); err == nil && h > 0 {
			c.podIPsRetention = time.Duration(h) * time.Hour
		}
	}
	return c, nil
}

// namespaceAllowed implements glob matching for NAMESPACE_FILTER. kube-system is always
// excluded per spec. Empty filter or "*" matches everything else. A leading "!" negates.
func namespaceAllowed(ns string, globs []string) bool {
	if ns == excludedSystem {
		return false
	}
	if len(globs) == 0 {
		return true
	}
	allow := false
	hasInclude := false
	for _, g := range globs {
		neg := false
		if strings.HasPrefix(g, "!") {
			neg = true
			g = g[1:]
		}
		if !neg {
			hasInclude = true
		}
		if globMatch(g, ns) {
			if neg {
				return false
			}
			allow = true
		}
	}
	if !hasInclude {
		return true
	}
	return allow
}

func globMatch(pat, s string) bool {
	if pat == "*" || pat == s {
		return true
	}
	if strings.Contains(pat, "*") {
		parts := strings.SplitN(pat, "*", 2)
		left, right := parts[0], parts[1]
		return strings.HasPrefix(s, left) && strings.HasSuffix(s, right)
	}
	return false
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: obslog.Level()})).With("svc", "constellation-discoverer")
	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config", slog.String("err", err.Error()))
		os.Exit(2)
	}
	logger = logger.With("cluster", cfg.clusterName)
	if cfg.orgIDSet {
		logger = logger.With("org", cfg.orgID.String())
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	pool, err := openDB(ctx, cfg.databaseURL)
	if err != nil {
		logger.Error("db connect", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer pool.Close()

	clusterID, orgID, err := resolveCluster(ctx, pool, cfg.orgID, cfg.orgIDSet, cfg.clusterName)
	if err != nil {
		logger.Error("resolve cluster", slog.String("err", err.Error()))
		os.Exit(1)
	}
	cfg.orgID = orgID
	logger = logger.With("cluster_id", clusterID.String(), "org", orgID.String())
	logger.Info("resolved cluster row")
	// Wave N6: heartbeat side-car. Owned by cmd/.../heartbeat.go so this file
	// stays focused on the reconciler.
	startHeartbeat(ctx, logger, clusterID.String())

	cs, err := newKubeClient(cfg.kubeconfig)
	if err != nil {
		logger.Error("kube client", slog.String("err", err.Error()))
		os.Exit(1)
	}

	r := &reconciler{
		log:             logger,
		pool:            pool,
		cs:              cs,
		orgID:           orgID,
		clusterID:       clusterID,
		clusterName:     cfg.clusterName,
		nsGlobs:         cfg.nsGlobs,
		staleAfter:      2 * cfg.interval,
		podIPsRetention: cfg.podIPsRetention,
	}

	if err := r.reconcile(ctx); err != nil {
		logger.Error("initial reconcile", slog.String("err", err.Error()))
		if cfg.oneShot {
			os.Exit(1)
		}
	}
	if cfg.oneShot {
		logger.Info("one-shot complete, exiting")
		return
	}

	// Phase C: real-time pod->IP capture. The SharedInformer mirrors pod IPs into
	// pod_ips within milliseconds so short-lived pods are recorded between polls.
	// It runs alongside (not instead of) the 30s poll, which still covers all
	// other resources and acts as a pod fallback. ctx-scoped: cancelled on signal.
	if err := r.startPodInformer(ctx); err != nil {
		logger.Warn("pod informer", slog.String("err", err.Error()))
	}

	t := time.NewTicker(cfg.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info("shutdown")
			return
		case <-t.C:
			if err := r.reconcile(ctx); err != nil {
				logger.Warn("reconcile", slog.String("err", err.Error()))
			}
		}
	}
}

func openDB(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 6
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

func resolveCluster(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, orgIDSet bool, name string) (uuid.UUID, uuid.UUID, error) {
	var id uuid.UUID
	if !orgIDSet {
		var matches int
		err := pool.QueryRow(ctx, `
SELECT id, org_id, COUNT(*) OVER ()
  FROM clusters
 WHERE name = $1
 LIMIT 1`, name).Scan(&id, &orgID, &matches)
		if err == nil {
			if matches > 1 {
				return uuid.Nil, uuid.Nil, errors.New("ORG_ID is required when cluster name is not unique")
			}
			return id, orgID, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, uuid.Nil, err
		}
		return uuid.Nil, uuid.Nil, errors.New("ORG_ID is required when the cluster row does not already exist")
	}

	err := pool.QueryRow(ctx,
		`SELECT id FROM clusters WHERE org_id = $1 AND name = $2 LIMIT 1`,
		orgID, name).Scan(&id)
	if err == nil {
		return id, orgID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, err
	}
	// Auto-create so the discoverer is usable in fresh environments.
	err = pool.QueryRow(ctx, `
INSERT INTO clusters (org_id, name, distro, state, last_heartbeat_at)
VALUES ($1, $2, 'kubernetes', 'connected', NOW())
ON CONFLICT (org_id, name) DO UPDATE SET state = 'connected', last_heartbeat_at = NOW()
RETURNING id`, orgID, name).Scan(&id)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("insert cluster: %w", err)
	}
	return id, orgID, nil
}

func newKubeClient(kubeconfig string) (*kubernetes.Clientset, error) {
	if kubeconfig == "" {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("KUBECONFIG not set and in-cluster config unavailable: %w", err)
		}
		cfg.QPS = 50
		cfg.Burst = 100
		return kubernetes.NewForConfig(cfg)
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	cfg.QPS = 50
	cfg.Burst = 100
	return kubernetes.NewForConfig(cfg)
}

type reconciler struct {
	log         *slog.Logger
	pool        *pgxpool.Pool
	cs          *kubernetes.Clientset
	orgID       uuid.UUID
	clusterID   uuid.UUID
	clusterName string
	nsGlobs     []string
	// staleAfter is the threshold for sweeping pod_workload_links / cluster_services
	// rows that haven't been touched in `2 * RECONCILE_INTERVAL`. Set from main().
	staleAfter time.Duration
	// podIPsRetention is the (much longer) horizon for sweeping pod_ips history so
	// past pod->IP mappings survive for late resolution/backfill. Set from main().
	podIPsRetention time.Duration

	// deploymentIDs caches the (namespace,name,kind)->deployment id map, refreshed
	// each poll pass and read by the pod informer so it can populate deployment_id
	// without a per-event DB query. Guarded by mu.
	mu            sync.RWMutex
	deploymentIDs map[workloadKey]uuid.UUID
}

func (r *reconciler) setDeploymentIDs(m map[workloadKey]uuid.UUID) {
	r.mu.Lock()
	r.deploymentIDs = m
	r.mu.Unlock()
}

func (r *reconciler) getDeploymentIDs() map[workloadKey]uuid.UUID {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.deploymentIDs
}

type workload struct {
	namespace string
	name      string
	kind      string
	labels    map[string]string
	hostNet   bool
	priv      bool
	rootRisk  bool
	aiFlag    bool
	images    []string // container + init container image refs, deduped
	// imageDigests maps a running image ref (the spec/status image, e.g.
	// "nginx:1.25") to the runtime-resolved content digest ("sha256:<hex>")
	// extracted from pod status.containerStatuses[].imageID. Spec refs carry a
	// tag (or nothing) and so have no digest of their own; this is what lets a
	// tag-keyed image scan target join to package-evidence the runtime-agent
	// collected off the running container keyed by digest (WS-F1).
	imageDigests map[string]string
}

// addImageDigest records ref -> digest, last-writer-wins. An image may appear
// under several pods (e.g. a DaemonSet); the last observed digest is fine.
func (w *workload) addImageDigest(ref, digest string) {
	ref = strings.TrimSpace(ref)
	digest = strings.TrimSpace(digest)
	if ref == "" || digest == "" {
		return
	}
	if w.imageDigests == nil {
		w.imageDigests = map[string]string{}
	}
	w.imageDigests[ref] = digest
}

type workloadKey struct {
	namespace string
	name      string
	kind      string
}

func (r *reconciler) reconcile(ctx context.Context) error {
	wls, err := r.list(ctx)
	if err != nil {
		return err
	}
	upserted := 0
	for _, w := range wls {
		if !namespaceAllowed(w.namespace, r.nsGlobs) {
			continue
		}
		if err := r.upsertWorkload(ctx, w); err != nil {
			r.log.Warn("upsert workload",
				slog.String("ns", w.namespace), slog.String("name", w.name),
				slog.String("err", err.Error()))
			continue
		}
		upserted++
	}
	if err := r.rollupRiskCounts(ctx); err != nil {
		r.log.Warn("rollup", slog.String("err", err.Error()))
	}
	if err := r.seedDefaultPolicyPosture(ctx); err != nil {
		r.log.Warn("seed default policy posture", slog.String("err", err.Error()))
	}

	// Wave M2: project pod IPs + Service ClusterIPs so the Network Map can resolve
	// raw IPs back to named workloads. Failures here are non-fatal — they just
	// degrade Network Map readability until the next pass.
	podsSeen, err := r.syncPods(ctx)
	if err != nil {
		r.log.Warn("sync pods", slog.String("err", err.Error()))
	}
	svcsSeen, err := r.syncServices(ctx)
	if err != nil {
		r.log.Warn("sync services", slog.String("err", err.Error()))
	}
	if err := r.sweepStaleNetworkRows(ctx); err != nil {
		r.log.Warn("sweep stale ip rows", slog.String("err", err.Error()))
	}
	if err := r.reportPlatformFacts(ctx); err != nil {
		r.log.Warn("platform facts", slog.String("err", err.Error()))
	}

	r.log.Info("reconcile pass complete",
		slog.Int("workloads_seen", len(wls)),
		slog.Int("workloads_upserted", upserted),
		slog.Int("pods_seen", podsSeen),
		slog.Int("services_seen", svcsSeen))
	return nil
}

func (r *reconciler) list(ctx context.Context) ([]workload, error) {
	out := []workload{}
	byKey := map[workloadKey]int{}
	addWorkload := func(w workload) {
		k := workloadKey{namespace: w.namespace, name: w.name, kind: w.kind}
		if idx, ok := byKey[k]; ok {
			out[idx].images = mergeImageRefs(out[idx].images, w.images...)
			for ref, digest := range w.imageDigests {
				out[idx].addImageDigest(ref, digest)
			}
			return
		}
		byKey[k] = len(out)
		out = append(out, w)
	}

	deps, err := r.cs.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	for i := range deps.Items {
		d := &deps.Items[i]
		ps := d.Spec.Template.Spec
		addWorkload(workload{
			namespace: d.Namespace,
			name:      d.Name,
			kind:      "Deployment",
			labels:    d.Labels,
			hostNet:   ps.HostNetwork,
			priv:      anyPrivileged(ps.Containers) || anyPrivileged(ps.InitContainers),
			rootRisk:  runsAsRoot(ps),
			images:    collectImages(ps),
			aiFlag:    labelTrue(d.Labels, "ai-workload"),
		})
	}

	sts, err := r.cs.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list statefulsets: %w", err)
	}
	for i := range sts.Items {
		s := &sts.Items[i]
		ps := s.Spec.Template.Spec
		addWorkload(workload{
			namespace: s.Namespace,
			name:      s.Name,
			kind:      "StatefulSet",
			labels:    s.Labels,
			hostNet:   ps.HostNetwork,
			priv:      anyPrivileged(ps.Containers) || anyPrivileged(ps.InitContainers),
			rootRisk:  runsAsRoot(ps),
			images:    collectImages(ps),
			aiFlag:    labelTrue(s.Labels, "ai-workload"),
		})
	}

	dsets, err := r.cs.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list daemonsets: %w", err)
	}
	for i := range dsets.Items {
		d := &dsets.Items[i]
		ps := d.Spec.Template.Spec
		addWorkload(workload{
			namespace: d.Namespace,
			name:      d.Name,
			kind:      "DaemonSet",
			labels:    d.Labels,
			hostNet:   ps.HostNetwork,
			priv:      anyPrivileged(ps.Containers) || anyPrivileged(ps.InitContainers),
			rootRisk:  runsAsRoot(ps),
			images:    collectImages(ps),
			aiFlag:    labelTrue(d.Labels, "ai-workload"),
		})
	}
	if err := r.mergePodStatusImages(ctx, out, byKey); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *reconciler) mergePodStatusImages(ctx context.Context, out []workload, byKey map[workloadKey]int) error {
	rsOwners, err := r.replicaSetOwners(ctx)
	if err != nil {
		return err
	}
	pods, err := r.cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list pods for image ids: %w", err)
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !namespaceAllowed(pod.Namespace, r.nsGlobs) {
			continue
		}
		key, ok := workloadKeyForPod(*pod, rsOwners)
		if !ok {
			continue
		}
		idx, ok := byKey[key]
		if !ok {
			continue
		}
		out[idx].images = mergeImageRefs(out[idx].images, podStatusImageRefs(*pod)...)
		for ref, digest := range podStatusImageDigests(*pod) {
			out[idx].addImageDigest(ref, digest)
		}
	}
	return nil
}

func (r *reconciler) replicaSetOwners(ctx context.Context) (map[string]workloadKey, error) {
	sets, err := r.cs.AppsV1().ReplicaSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list replicasets for image ids: %w", err)
	}
	out := map[string]workloadKey{}
	for i := range sets.Items {
		rs := &sets.Items[i]
		for _, owner := range rs.OwnerReferences {
			if owner.Kind == "Deployment" && owner.Name != "" {
				out[rs.Namespace+"/"+rs.Name] = workloadKey{namespace: rs.Namespace, name: owner.Name, kind: "Deployment"}
				break
			}
		}
	}
	return out, nil
}

func workloadKeyForPod(pod corev1.Pod, replicaSetOwners map[string]workloadKey) (workloadKey, bool) {
	for _, owner := range pod.OwnerReferences {
		switch owner.Kind {
		case "ReplicaSet":
			if key, ok := replicaSetOwners[pod.Namespace+"/"+owner.Name]; ok {
				return key, true
			}
		case "StatefulSet", "DaemonSet":
			if owner.Name != "" {
				return workloadKey{namespace: pod.Namespace, name: owner.Name, kind: owner.Kind}, true
			}
		}
	}
	return workloadKey{}, false
}

func labelTrue(labels map[string]string, key string) bool {
	if labels == nil {
		return false
	}
	v, ok := labels[key]
	if !ok {
		return false
	}
	return strings.EqualFold(v, "true")
}

func anyPrivileged(cs []corev1.Container) bool {
	for i := range cs {
		c := &cs[i]
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			return true
		}
	}
	return false
}

// runsAsRoot flags a workload as root-risk when nothing enforces non-root: neither the
// pod securityContext (RunAsNonRoot=true / RunAsUser>0) nor at least one app container.
// Mirrors NeuVector's run-as-root hardening signal (a WL that CAN run as uid 0).
func runsAsRoot(ps corev1.PodSpec) bool {
	nonRootSC := func(runAsNonRoot *bool, runAsUser *int64) bool {
		return (runAsNonRoot != nil && *runAsNonRoot) || (runAsUser != nil && *runAsUser > 0)
	}
	if ps.SecurityContext != nil && nonRootSC(ps.SecurityContext.RunAsNonRoot, ps.SecurityContext.RunAsUser) {
		return false
	}
	for i := range ps.Containers {
		sc := ps.Containers[i].SecurityContext
		if sc == nil || !nonRootSC(sc.RunAsNonRoot, sc.RunAsUser) {
			return true
		}
	}
	return false
}

func collectImages(ps corev1.PodSpec) []string {
	return mergeImageRefs(nil, podSpecImages(ps)...)
}

func podSpecImages(ps corev1.PodSpec) []string {
	out := []string{}
	for _, c := range ps.Containers {
		if c.Image != "" {
			out = append(out, c.Image)
		}
	}
	for _, c := range ps.InitContainers {
		if c.Image != "" {
			out = append(out, c.Image)
		}
	}
	for _, c := range ps.EphemeralContainers {
		if c.Image != "" {
			out = append(out, c.Image)
		}
	}
	return out
}

func podStatusImageRefs(pod corev1.Pod) []string {
	out := []string{}
	statuses := make([]corev1.ContainerStatus, 0, len(pod.Status.InitContainerStatuses)+len(pod.Status.ContainerStatuses)+len(pod.Status.EphemeralContainerStatuses))
	statuses = append(statuses, pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.ContainerStatuses...)
	statuses = append(statuses, pod.Status.EphemeralContainerStatuses...)
	for _, status := range statuses {
		if status.Image != "" {
			out = append(out, status.Image)
		}
	}
	return mergeImageRefs(nil, out...)
}

// imageRefRegistryVariants returns the ref plus the forms with Docker Hub's implicit
// registry/namespace stripped, so a digest resolved from the K8s-qualified status ref
// ("docker.io/constellation/api:gs17") also keys under the bare spec ref
// ("constellation/api:gs17") the scan targets use. Order: most-qualified first.
func imageRefRegistryVariants(ref string) []string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}
	out := []string{ref}
	seen := map[string]struct{}{ref: {}}
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	cur := ref
	for _, prefix := range []string{"index.docker.io/", "docker.io/"} {
		if strings.HasPrefix(cur, prefix) {
			cur = strings.TrimPrefix(cur, prefix)
			add(cur)
		}
	}
	// Official images: "library/postgres:16" is spec'd as "postgres:16".
	if strings.HasPrefix(cur, "library/") {
		add(strings.TrimPrefix(cur, "library/"))
	}
	return out
}

func normalizeKubeImageID(imageID string) string {
	imageID = strings.TrimSpace(imageID)
	if imageID == "" {
		return ""
	}
	for _, prefix := range []string{"docker-pullable://", "docker://", "containerd://", "cri-o://"} {
		imageID = strings.TrimPrefix(imageID, prefix)
	}
	if idx := strings.Index(imageID, "://"); idx >= 0 {
		imageID = imageID[idx+3:]
	}
	return strings.TrimSpace(imageID)
}

// podStatusImageDigests maps each running container's image ref (the
// status.Image, e.g. "ghcr.io/acme/api:dev") to its resolved content digest
// ("sha256:<hex>") taken from status.containerStatuses[].imageID. Containers
// that have not started yet (empty imageID) or whose imageID carries no digest
// are skipped, so the result only contains refs we could actually resolve.
func podStatusImageDigests(pod corev1.Pod) map[string]string {
	out := map[string]string{}
	statuses := make([]corev1.ContainerStatus, 0, len(pod.Status.InitContainerStatuses)+len(pod.Status.ContainerStatuses)+len(pod.Status.EphemeralContainerStatuses))
	statuses = append(statuses, pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.ContainerStatuses...)
	statuses = append(statuses, pod.Status.EphemeralContainerStatuses...)
	for _, status := range statuses {
		digest := digestFromKubeImageID(status.ImageID)
		if digest == "" {
			continue
		}
		// The spec ref (status.Image, e.g. a tag) is the ref we link/scan on, so
		// map it to the digest. Also map the normalized imageID ref itself so a
		// "repo@sha256:..." ref resolves to its own digest.
		//
		// K8s status.Image carries the FULLY-QUALIFIED ref (e.g.
		// "docker.io/constellation/api:gs17") even when the pod spec used a bare ref
		// ("constellation/api:gs17"). The scan target / image_workload_links key on the
		// SPEC ref, so also map the default-registry-stripped variants — otherwise a
		// locally-built image (spec omits the registry) never gets its digest and can't
		// join to the runtime-agent's digest-keyed local evidence (WS-F1).
		if ref := strings.TrimSpace(status.Image); ref != "" {
			for _, v := range imageRefRegistryVariants(ref) {
				out[v] = digest
			}
		}
		if ref := normalizeKubeImageID(status.ImageID); ref != "" {
			for _, v := range imageRefRegistryVariants(ref) {
				out[v] = digest
			}
		}
	}
	return out
}

// digestFromKubeImageID extracts the bare content digest ("sha256:<hex>") from a
// Kubernetes imageID. imageIDs come in several shapes depending on the runtime:
//
//	docker-pullable://docker.io/library/nginx@sha256:abc...
//	containerd://sha256:abc...
//	docker.io/library/nginx@sha256:abc...
//	sha256:abc...
//
// Any runtime scheme prefix and registry/repo@ prefix are stripped, leaving only
// the normalized "sha256:<hex>" form the runtime-agent keys evidence by. Returns
// "" when no sha256 digest is present (e.g. the container has not started).
func digestFromKubeImageID(imageID string) string {
	id := normalizeKubeImageID(imageID)
	if id == "" {
		return ""
	}
	if idx := strings.LastIndex(id, "@"); idx >= 0 {
		id = id[idx+1:]
	}
	id = strings.TrimSpace(id)
	if !strings.HasPrefix(id, "sha256:") {
		return ""
	}
	if id == "sha256:" {
		return ""
	}
	return id
}

func mergeImageRefs(existing []string, refs ...string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(existing)+len(refs))
	for _, ref := range existing {
		ref = strings.TrimSpace(ref)
		if ref != "" && !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref != "" && !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	return out
}

// imageLinkFieldsForRefs derives the per-ref columns persisted to
// image_workload_links. resolvedDigests carries runtime-resolved digests keyed
// by image ref (from pod containerStatuses[].imageID); when a ref does not embed
// its own digest, the resolved one is used so the right digest lands on the right
// target. This is what lets a tag-keyed image scan target connect to
// package-evidence the runtime-agent keyed by digest (WS-F1).
func imageLinkFieldsForRefs(refs []string, resolvedDigests map[string]string) (normalized, repositories, tags, digests []string) {
	normalized = make([]string, 0, len(refs))
	repositories = make([]string, 0, len(refs))
	tags = make([]string, 0, len(refs))
	digests = make([]string, 0, len(refs))
	for _, ref := range refs {
		identity := imageid.Parse(ref)
		digest := identity.Digest
		if digest == "" {
			digest = strings.TrimSpace(resolvedDigests[ref])
		}
		normalized = append(normalized, identity.Normalized)
		repositories = append(repositories, identity.Repository)
		tags = append(tags, identity.Tag)
		digests = append(digests, digest)
	}
	return normalized, repositories, tags, digests
}

// upsertWorkload writes both a `deployments` row and a paired `assets` row (kind='deployment')
// so future scanner findings can attach to the workload by asset_id.
func (r *reconciler) upsertWorkload(ctx context.Context, w workload) error {
	labelsJSON, err := json.Marshal(w.labels)
	if err != nil {
		labelsJSON = []byte("{}")
	}
	// Seed risk_factors with the structural facts we observed from the spec/PodSpec. Numeric
	// counts are overwritten by rollupRiskCounts() after every pass.
	factors := map[string]any{}
	if w.priv {
		factors["privileged"] = 15
	}
	if w.hostNet {
		factors["host_network"] = 10
	}
	if w.rootRisk {
		factors["run_as_root"] = 8
	}
	if w.aiFlag {
		factors["ai_workload"] = 5
	}
	factorsJSON, _ := json.Marshal(factors)

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Upsert deployment.
	images := w.images
	if images == nil {
		images = []string{}
	}
	var deploymentID uuid.UUID
	err = tx.QueryRow(ctx, `
INSERT INTO deployments
    (org_id, cluster_id, namespace, name, kind, labels, risk_factors, image_refs, last_seen_at)
VALUES
    ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, NOW())
ON CONFLICT (org_id, cluster_id, namespace, name, kind) DO UPDATE
   SET labels       = EXCLUDED.labels,
       -- Structural factors are recomputed from the current spec on every pass, so overwrite
       -- (not merge) them: drop the prior structural keys and re-apply only those observed now,
       -- otherwise a stale privileged=15 survives after the workload is redeployed unprivileged.
       -- Additive/computed factors (cvss, kev, net_exposure) written by rollupRiskCounts are
       -- preserved because they are not part of the stripped structural key set.
       risk_factors = (deployments.risk_factors - 'privileged' - 'host_network' - 'run_as_root' - 'ai_workload')
                      || EXCLUDED.risk_factors,
       image_refs   = EXCLUDED.image_refs,
       last_seen_at = NOW()
RETURNING id`,
		r.orgID, r.clusterID, w.namespace, w.name, w.kind,
		string(labelsJSON), string(factorsJSON), images).Scan(&deploymentID)
	if err != nil {
		return fmt.Errorf("upsert deployment: %w", err)
	}

	workloadID := w.namespace + "/" + w.name
	if _, err := tx.Exec(ctx, `
DELETE FROM image_workload_links
 WHERE org_id = $1
   AND cluster_id = $2
   AND deployment_id = $3
   AND NOT (image_ref = ANY($4::text[]))`,
		r.orgID, r.clusterID, deploymentID, images); err != nil {
		return fmt.Errorf("prune image workload links: %w", err)
	}
	if len(images) > 0 {
		normalized, repositories, tags, digests := imageLinkFieldsForRefs(images, w.imageDigests)
		if _, err := tx.Exec(ctx, `
WITH image_input AS (
  SELECT image_ref,
         image_ref_normalized,
         NULLIF(image_repository, '') AS image_repository,
         NULLIF(image_tag, '') AS image_tag,
         NULLIF(image_digest, '') AS image_digest
    FROM unnest($8::text[], $9::text[], $10::text[], $11::text[], $12::text[])
      AS fields(image_ref, image_ref_normalized, image_repository, image_tag, image_digest)
)
INSERT INTO image_workload_links (
    org_id, cluster_id, deployment_id, workload_id, namespace, name, kind,
    image_ref, image_ref_normalized, image_repository, image_tag, image_digest,
    last_seen_at
)
SELECT $1, $2, $3, $4, $5, $6, $7,
       image_ref, image_ref_normalized, image_repository, image_tag, image_digest,
       NOW()
  FROM image_input
 WHERE image_ref <> ''
ON CONFLICT (org_id, cluster_id, workload_id, image_ref) DO UPDATE SET
    deployment_id        = EXCLUDED.deployment_id,
    namespace            = EXCLUDED.namespace,
    name                 = EXCLUDED.name,
    kind                 = EXCLUDED.kind,
    image_ref_normalized = EXCLUDED.image_ref_normalized,
    image_repository     = EXCLUDED.image_repository,
    image_tag            = EXCLUDED.image_tag,
    image_digest         = EXCLUDED.image_digest,
    last_seen_at         = NOW()`,
			r.orgID, r.clusterID, deploymentID, workloadID, w.namespace, w.name, w.kind,
			images, normalized, repositories, tags, digests); err != nil {
			return fmt.Errorf("upsert image workload links: %w", err)
		}
	}

	// Upsert a paired asset so findings can attach. The assets table's UNIQUE constraint is
	// (org_id, kind, name, digest); we leave digest NULL for workloads.
	assetName := workloadID
	criticality := "medium"
	if w.priv || w.hostNet {
		criticality = "high"
	}
	// digest is part of the UNIQUE key on assets; with NULL digest the btree UNIQUE allows
	// duplicates (NULL != NULL), so we use a deterministic non-null sentinel for workload
	// assets that namespaces by cluster_id to keep them unique per cluster.
	assetDigest := "deployment:" + r.clusterID.String()
	_, err = tx.Exec(ctx, `
INSERT INTO assets (org_id, cluster_id, kind, name, digest, labels, ai_workload, criticality, last_seen_at)
VALUES ($1, $2, 'deployment', $3, $4, $5::jsonb, $6, $7, NOW())
ON CONFLICT (org_id, kind, name, digest) DO UPDATE
   SET cluster_id   = EXCLUDED.cluster_id,
       labels       = EXCLUDED.labels,
       ai_workload  = EXCLUDED.ai_workload,
       criticality  = EXCLUDED.criticality,
       last_seen_at = NOW()`,
		r.orgID, r.clusterID, assetName, assetDigest, string(labelsJSON), w.aiFlag, criticality)
	if err != nil {
		return fmt.Errorf("upsert asset: %w", err)
	}

	return tx.Commit(ctx)
}

// rollupRiskCounts joins workload-level findings and canonical image scan findings for
// every running image linked to a deployment, then writes finding_count / critical_count /
// high_count / risk_score for every deployment in this cluster. risk_score follows the
// spec formula:
//
//	risk_score = min(100, 5*critical + 2*high + medium)
//
// risk_factors keeps structural keys observed from the workload spec
// (privileged, host_network, ai_workload) and overlays measured subfactors
// from findings and runtime flows: max CVSS, KEV presence, and recent external
// network exposure.
func (r *reconciler) rollupRiskCounts(ctx context.Context) error {
	// Rollup joins each deployment to its findings via two parallel paths:
	//   (1) the paired deployment-kind asset (workload-level findings)
	//   (2) image_workload_links -> latest canonical image scan result by digest/ref.
	_, err := r.pool.Exec(ctx, `
WITH deployment_scope AS (
  SELECT d.id AS dep_id, (d.namespace || '/' || d.name) AS workload
  FROM deployments d
  WHERE d.org_id     = $1
    AND d.cluster_id = $2
),
dep_findings AS (
  SELECT ds.dep_id,
         f.id::text AS finding_id,
         f.severity,
         CASE WHEN jsonb_typeof(f.detail_json->'cvss_base') = 'number'
              THEN (f.detail_json->>'cvss_base')::numeric
              ELSE 0 END AS cvss_base,
         CASE WHEN jsonb_typeof(f.detail_json->'kev') = 'boolean'
              THEN (f.detail_json->>'kev')::boolean
              ELSE FALSE END AS kev_listed
  FROM deployment_scope ds
  LEFT JOIN assets a
    ON a.org_id = $1
   AND a.kind   = 'deployment'
   AND a.name   = ds.workload
   AND (a.cluster_id IS NULL OR a.cluster_id = $2)
  LEFT JOIN findings f
    ON f.org_id    = $1
   AND f.asset_id  = a.id
   AND f.lifecycle = 'open'
   AND (f.cluster_id IS NULL OR f.cluster_id = $2)
  WHERE f.id IS NOT NULL
  UNION ALL
  SELECT ds.dep_id,
         f.id::text AS finding_id,
         f.severity,
         CASE WHEN jsonb_typeof(f.detail_json->'cvss_base') = 'number'
              THEN (f.detail_json->>'cvss_base')::numeric
              ELSE 0 END AS cvss_base,
         CASE WHEN jsonb_typeof(f.detail_json->'kev') = 'boolean'
              THEN (f.detail_json->>'kev')::boolean
              ELSE FALSE END AS kev_listed
  FROM deployment_scope ds
  JOIN image_workload_links iwl
    ON iwl.org_id = $1
   AND iwl.cluster_id = $2
   AND iwl.workload_id = ds.workload
  JOIN LATERAL (
      SELECT r.id
        FROM image_scan_results r
       WHERE r.org_id = $1
         AND (
              (iwl.image_digest IS NOT NULL AND r.image_digest = iwl.image_digest)
           OR (iwl.image_ref <> '' AND r.image_ref = iwl.image_ref)
           OR (iwl.image_ref_normalized <> '' AND r.image_ref_normalized = iwl.image_ref_normalized)
           OR (iwl.image_repository IS NOT NULL AND r.image_repository = iwl.image_repository
               AND (iwl.image_tag IS NULL OR r.image_tag = iwl.image_tag))
         )
       ORDER BY r.last_scanned_at DESC
       LIMIT 1
  ) sr ON true
  JOIN image_scan_findings f
    ON f.org_id = $1
   AND f.image_scan_result_id = sr.id
),
deduped_findings AS (
  SELECT DISTINCT ON (dep_id, finding_id)
         dep_id, severity, cvss_base, kev_listed
    FROM dep_findings
   ORDER BY dep_id, finding_id
),
counts AS (
  SELECT
    ds.dep_id,
    COALESCE(SUM(CASE WHEN df.severity = 'critical' THEN 1 ELSE 0 END), 0)::int AS cc,
    COALESCE(SUM(CASE WHEN df.severity = 'high'     THEN 1 ELSE 0 END), 0)::int AS hc,
    COALESCE(SUM(CASE WHEN df.severity = 'medium'   THEN 1 ELSE 0 END), 0)::int AS mc,
    COALESCE(COUNT(df.severity), 0)::int AS fc,
    COALESCE(MAX(df.cvss_base), 0)::numeric AS max_cvss,
    COALESCE(BOOL_OR(df.kev_listed), FALSE) AS has_kev
  FROM deployment_scope ds
  LEFT JOIN deduped_findings df ON df.dep_id = ds.dep_id
  GROUP BY ds.dep_id
),
network_exposure AS (
  SELECT
    ds.dep_id,
    LEAST(15, COUNT(DISTINCT nf.protocol || '|' || nf.src_workload || '|' || nf.dst_workload || '|' || COALESCE(nf.dst_port::text, '')) * 3)::int AS score
  FROM deployment_scope ds
  JOIN network_flows nf
    ON nf.org_id = $1
   AND nf.cluster_id = $2
   AND nf.at >= NOW() - INTERVAL '24 hours'
   AND (
        (nf.src_workload = ds.workload AND nf.dst_workload LIKE 'external%')
     OR (nf.dst_workload = ds.workload AND nf.src_workload LIKE 'external%')
   )
  GROUP BY ds.dep_id
)
UPDATE deployments d
   SET critical_count = counts.cc,
       high_count     = counts.hc,
       finding_count  = counts.fc,
       risk_score     = LEAST(100, 5*counts.cc + 2*counts.hc + counts.mc),
       risk_factors   = d.risk_factors
                         || jsonb_build_object(
                              'cvss',         LEAST(40, ROUND(counts.max_cvss * 4)::int),
                              'kev',          CASE WHEN counts.has_kev THEN 20 ELSE 0 END,
                              'net_exposure', COALESCE(network_exposure.score, 0))
  FROM counts
  LEFT JOIN network_exposure ON network_exposure.dep_id = counts.dep_id
 WHERE d.id = counts.dep_id`,
		r.orgID, r.clusterID)
	return err
}

// ---------------------------------------------------------------------------
// Wave M2: pod-IP + Service-IP projection
//
// syncPods walks every running Pod, resolves it back to its top-level controller
// (Deployment via ReplicaSet, or StatefulSet / DaemonSet directly), and upserts
// one row per Pod IP into `pod_ips`. The Network Map resolver in
// internal/handler/network_flows_ingest.go uses this to rewrite raw IPs into
// "<ns>/<deployment>" labels.
//
// syncServices does the same for Service ClusterIPs (skipping headless
// Services, which have ClusterIP="None"). The map renders these as nodes
// distinct from Deployments (kind='Service' on the row).

// resolvePodOwner walks the owner-ref chain of a Pod up to a Deployment,
// StatefulSet, or DaemonSet. Standalone Pods (no owner) return their own
// name and kind="Pod". ReplicaSet owners are followed one more hop to their
// Deployment parent (the typical case).
func (r *reconciler) resolvePodOwner(ctx context.Context, pod *corev1.Pod) (name, kind, uid string) {
	ctrl := metav1.GetControllerOf(pod)
	if ctrl == nil {
		return pod.Name, "Pod", string(pod.UID)
	}
	switch ctrl.Kind {
	case "Deployment", "StatefulSet", "DaemonSet":
		return ctrl.Name, ctrl.Kind, string(ctrl.UID)
	case "ReplicaSet":
		rs, err := r.cs.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, ctrl.Name, metav1.GetOptions{})
		if err == nil {
			if rsCtrl := metav1.GetControllerOf(rs); rsCtrl != nil && rsCtrl.Kind == "Deployment" {
				return rsCtrl.Name, "Deployment", string(rsCtrl.UID)
			}
		}
		// Bare ReplicaSet (rare) — record its name so the row at least resolves.
		return ctrl.Name, "ReplicaSet", string(ctrl.UID)
	case "Job":
		// Jobs may be owned by a CronJob; collapse either way to the immediate
		// controller for now.
		return ctrl.Name, "Job", string(ctrl.UID)
	default:
		return ctrl.Name, ctrl.Kind, string(ctrl.UID)
	}
}

func (r *reconciler) deploymentIDsByKey(ctx context.Context) map[workloadKey]uuid.UUID {
	rows, err := r.pool.Query(ctx, `
SELECT id, namespace, name, kind
  FROM deployments
 WHERE org_id = $1
   AND cluster_id = $2`, r.orgID, r.clusterID)
	if err != nil {
		r.log.Warn("load deployment owner ids", slog.String("err", err.Error()))
		return nil
	}
	defer rows.Close()
	out := map[workloadKey]uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		var key workloadKey
		if err := rows.Scan(&id, &key.namespace, &key.name, &key.kind); err == nil {
			out[key] = id
		}
	}
	return out
}

func (r *reconciler) syncPods(ctx context.Context) (int, error) {
	pods, err := r.cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("list pods: %w", err)
	}
	ownerDeploymentIDs := r.deploymentIDsByKey(ctx)
	// Publish the fresh owner map for the pod informer (Phase C) to read without a
	// per-event DB query.
	r.setDeploymentIDs(ownerDeploymentIDs)
	seen := 0
	for i := range pods.Items {
		p := &pods.Items[i]
		// Record Running/Pending pods (their IP may still be forming) plus any
		// terminated/terminating pod that still carries an IP, so short-lived pods
		// land in pod_ips before they vanish.
		if !podIPRecordable(p) {
			continue
		}
		id := r.resolvePodIdentity(ctx, p, ownerDeploymentIDs)
		ownerWorkloadID := p.Namespace + "/" + id.workloadName
		if _, err := r.pool.Exec(ctx, `
INSERT INTO pod_workload_links (
    org_id, cluster_id, namespace, pod_name, pod_uid, pod_workload_id,
    owner_kind, owner_name, owner_uid, owner_workload_id,
    deployment_id, node_name, phase, first_seen_at, last_seen_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $11, NULLIF($12, ''), $13, NOW(), NOW())
ON CONFLICT (org_id, cluster_id, pod_uid) DO UPDATE
   SET namespace         = EXCLUDED.namespace,
       pod_name          = EXCLUDED.pod_name,
       pod_workload_id   = EXCLUDED.pod_workload_id,
       owner_kind        = EXCLUDED.owner_kind,
       owner_name        = EXCLUDED.owner_name,
       owner_uid         = EXCLUDED.owner_uid,
       owner_workload_id = EXCLUDED.owner_workload_id,
       deployment_id     = EXCLUDED.deployment_id,
       node_name         = EXCLUDED.node_name,
       phase             = EXCLUDED.phase,
       last_seen_at      = NOW()`,
			r.orgID, r.clusterID, p.Namespace, p.Name, id.podUID, id.podWorkloadID,
			id.workloadKind, id.workloadName, id.ownerUID, ownerWorkloadID, id.deploymentID, p.Spec.NodeName, string(p.Status.Phase)); err != nil {
			r.log.Warn("upsert pod workload link",
				slog.String("ns", p.Namespace), slog.String("pod", p.Name),
				slog.String("err", err.Error()))
			continue
		}
		seen++
		if err := r.upsertPodIPs(ctx, p, id); err != nil {
			r.log.Warn("upsert pod ip",
				slog.String("ns", p.Namespace), slog.String("pod", p.Name),
				slog.String("err", err.Error()))
		}
	}
	return seen, nil
}

// podIPs returns the distinct IPs a pod currently carries: the primary
// status.PodIP plus the dual-stack status.PodIPs list. Order-stable so callers
// (and tests) get deterministic output.
func podIPs(p *corev1.Pod) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	add(p.Status.PodIP)
	for _, ip := range p.Status.PodIPs {
		add(ip.IP)
	}
	return out
}

// podIPRecordable reports whether a pod should be projected into pod_ips.
// Running/Pending pods are always eligible (their IP may not be assigned yet).
// Terminated (Succeeded/Failed) or terminating pods are eligible only while they
// still carry an IP, so a short-lived pod's flows can still resolve to it.
func podIPRecordable(p *corev1.Pod) bool {
	switch p.Status.Phase {
	case corev1.PodRunning, corev1.PodPending:
		return true
	}
	return len(podIPs(p)) > 0
}

// podUIDKey is the stable identity for a pod: its UID, falling back to
// namespace/name for the (rare) case of a missing UID.
func podUIDKey(p *corev1.Pod) string {
	if uid := string(p.UID); uid != "" {
		return uid
	}
	return p.Namespace + "/" + p.Name
}

// podIdentity is the resolved workload identity for a pod, shared by the
// pod_workload_links + pod_ips writes in the poll path and the pod informer.
type podIdentity struct {
	workloadName  string
	workloadKind  string
	ownerUID      string
	podUID        string
	podWorkloadID string
	deploymentID  any
}

func (r *reconciler) resolvePodIdentity(ctx context.Context, p *corev1.Pod, ownerDeploymentIDs map[workloadKey]uuid.UUID) podIdentity {
	workloadName, workloadKind, ownerUID := r.resolvePodOwner(ctx, p)
	id := podIdentity{
		workloadName:  workloadName,
		workloadKind:  workloadKind,
		ownerUID:      ownerUID,
		podUID:        podUIDKey(p),
		podWorkloadID: p.Namespace + "/pod/" + p.Name,
	}
	if did, ok := ownerDeploymentIDs[workloadKey{namespace: p.Namespace, name: workloadName, kind: workloadKind}]; ok {
		id.deploymentID = did
	}
	return id
}

// upsertPodIPs writes one pod_ips row per IP the pod carries, keyed by
// (org, cluster, pod_uid, ip) so history is retained across pod churn and IP
// reuse. Shared by the 30s poll and the real-time pod informer.
func (r *reconciler) upsertPodIPs(ctx context.Context, p *corev1.Pod, id podIdentity) error {
	for _, ipStr := range podIPs(p) {
		if _, err := r.pool.Exec(ctx, `
INSERT INTO pod_ips (
    org_id, cluster_id, namespace, pod_name, deployment, kind, ip,
    pod_uid, owner_uid, deployment_id, workload_id, first_seen_at, last_seen_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7::inet, $8, NULLIF($9, ''), $10, $11, NOW(), NOW())
ON CONFLICT (org_id, cluster_id, pod_uid, ip) DO UPDATE
   SET namespace    = EXCLUDED.namespace,
       pod_name     = EXCLUDED.pod_name,
       deployment   = EXCLUDED.deployment,
       kind         = EXCLUDED.kind,
       owner_uid    = EXCLUDED.owner_uid,
       deployment_id = EXCLUDED.deployment_id,
       workload_id  = EXCLUDED.workload_id,
       last_seen_at = NOW()`,
			r.orgID, r.clusterID, p.Namespace, p.Name, id.workloadName, id.workloadKind, ipStr,
			id.podUID, id.ownerUID, id.deploymentID, id.podWorkloadID); err != nil {
			return fmt.Errorf("upsert pod ip %s: %w", ipStr, err)
		}
	}
	return nil
}

// stampPodIPsSeen bumps last_seen_at for every pod_ips row of a pod. Used by the
// informer on Delete: rather than removing the row (which would lose the
// mapping) we stamp it, so the retention sweep keeps it for the full horizon
// from the moment the pod actually went away.
func (r *reconciler) stampPodIPsSeen(ctx context.Context, podUID string) error {
	if podUID == "" {
		return nil
	}
	_, err := r.pool.Exec(ctx,
		`UPDATE pod_ips SET last_seen_at = NOW()
		  WHERE org_id = $1 AND cluster_id = $2 AND pod_uid = $3`,
		r.orgID, r.clusterID, podUID)
	return err
}

// startPodInformer runs a pod SharedInformer that mirrors pod IPs into pod_ips
// in near-real-time (Phase C). Add/Update upsert via the shared path; Delete
// stamps last_seen_at instead of deleting. It blocks until the cache syncs, then
// returns; the informer keeps running until ctx is cancelled (graceful shutdown).
func (r *reconciler) startPodInformer(ctx context.Context) error {
	factory := informers.NewSharedInformerFactory(r.cs, 0)
	podInformer := factory.Core().V1().Pods().Informer()

	upsert := func(obj any) {
		p, ok := obj.(*corev1.Pod)
		if !ok || !namespaceAllowed(p.Namespace, r.nsGlobs) || !podIPRecordable(p) {
			return
		}
		id := r.resolvePodIdentity(ctx, p, r.getDeploymentIDs())
		if err := r.upsertPodIPs(ctx, p, id); err != nil {
			r.log.Warn("informer upsert pod ip",
				slog.String("ns", p.Namespace), slog.String("pod", p.Name),
				slog.String("err", err.Error()))
		}
	}

	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { upsert(obj) },
		UpdateFunc: func(_, obj any) { upsert(obj) },
		DeleteFunc: func(obj any) {
			p := podFromDeleteObj(obj)
			if p == nil || !namespaceAllowed(p.Namespace, r.nsGlobs) {
				return
			}
			if err := r.stampPodIPsSeen(ctx, podUIDKey(p)); err != nil {
				r.log.Warn("informer stamp pod ip",
					slog.String("ns", p.Namespace), slog.String("pod", p.Name),
					slog.String("err", err.Error()))
			}
		},
	}); err != nil {
		return fmt.Errorf("add pod informer handler: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		return errors.New("pod informer cache did not sync")
	}
	r.log.Info("pod informer synced")
	return nil
}

// podFromDeleteObj extracts the *corev1.Pod from an informer Delete payload,
// which may be the object itself or a cache.DeletedFinalStateUnknown tombstone.
func podFromDeleteObj(obj any) *corev1.Pod {
	switch v := obj.(type) {
	case *corev1.Pod:
		return v
	case cache.DeletedFinalStateUnknown:
		if p, ok := v.Obj.(*corev1.Pod); ok {
			return p
		}
	}
	return nil
}

func (r *reconciler) syncServices(ctx context.Context) (int, error) {
	svcs, err := r.cs.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("list services: %w", err)
	}
	seen := 0
	for i := range svcs.Items {
		s := &svcs.Items[i]
		// Collect every ClusterIP we know about (None == headless, skip).
		ips := map[string]bool{}
		if s.Spec.ClusterIP != "" && !strings.EqualFold(s.Spec.ClusterIP, "None") {
			ips[s.Spec.ClusterIP] = true
		}
		for _, ip := range s.Spec.ClusterIPs {
			if ip != "" && !strings.EqualFold(ip, "None") {
				ips[ip] = true
			}
		}
		if len(ips) == 0 {
			continue
		}
		ports := make([]map[string]any, 0, len(s.Spec.Ports))
		for _, p := range s.Spec.Ports {
			ports = append(ports, map[string]any{
				"name":     p.Name,
				"port":     p.Port,
				"protocol": string(p.Protocol),
			})
		}
		portsJSON, err := json.Marshal(ports)
		if err != nil {
			portsJSON = []byte("[]")
		}
		for ipStr := range ips {
			if _, err := r.pool.Exec(ctx, `
INSERT INTO cluster_services (org_id, cluster_id, namespace, name, kind, cluster_ip, ports, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, $4, $5, $6::inet, $7::jsonb, NOW(), NOW())
ON CONFLICT (org_id, cluster_id, cluster_ip) DO UPDATE
   SET namespace    = EXCLUDED.namespace,
       name         = EXCLUDED.name,
       kind         = EXCLUDED.kind,
       ports        = EXCLUDED.ports,
       last_seen_at = NOW()`,
				r.orgID, r.clusterID, s.Namespace, s.Name, "Service", ipStr, string(portsJSON)); err != nil {
				r.log.Warn("upsert service",
					slog.String("ns", s.Namespace), slog.String("name", s.Name),
					slog.String("ip", ipStr), slog.String("err", err.Error()))
				continue
			}
			seen++
		}
	}
	return seen, nil
}

// seedDefaultPolicyPosture ensures every discovered workload has a network-policy
// lifecycle row in the DEFAULT posture: discover. Idempotent (ON CONFLICT DO
// NOTHING), so it seeds new workloads without ever disturbing one that's already
// been promoted/forced. This is what makes the discover→monitor→protect flow
// start from discover for everything — manual promotion, force, and the
// scheduled ATMO timer all advance from here.
func (r *reconciler) seedDefaultPolicyPosture(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, `
INSERT INTO network_policy_lifecycle_states
    (org_id, cluster_id, workload, namespace, current_mode, approval_status, reason, mode_since)
SELECT d.org_id, d.cluster_id, d.namespace || '/' || d.name, d.namespace,
       'discover', 'pending', 'auto-discovered (default posture)', NOW()
  FROM deployments d
 WHERE d.org_id = $1 AND d.cluster_id = $2
ON CONFLICT (org_id, cluster_id, workload) DO NOTHING`, r.orgID, r.clusterID)
	return err
}

// sweepStaleNetworkRows deletes pod owner/service rows that haven't been touched
// in `2 * RECONCILE_INTERVAL`. pod_ips is swept on a much longer, configurable
// horizon (POD_IPS_RETENTION_HOURS) because it now retains history so a flow can
// be resolved to its workload long after the pod is gone or its IP was reused;
// the resolver time-brackets on [first_seen_at, last_seen_at] to disambiguate.
func (r *reconciler) sweepStaleNetworkRows(ctx context.Context) error {
	after := r.staleAfter
	if after <= 0 {
		after = 2 * defaultInterval
	}
	podIPsAfter := r.podIPsRetention
	if podIPsAfter <= 0 {
		podIPsAfter = defaultPodIPsRetention
	}
	if _, err := r.pool.Exec(ctx,
		`DELETE FROM pod_workload_links
		  WHERE org_id = $1 AND cluster_id = $2
		    AND last_seen_at < NOW() - $3::interval`,
		r.orgID, r.clusterID, after.String()); err != nil {
		return fmt.Errorf("sweep pod_workload_links: %w", err)
	}
	if _, err := r.pool.Exec(ctx,
		`DELETE FROM pod_ips
		  WHERE org_id = $1 AND cluster_id = $2
		    AND last_seen_at < NOW() - $3::interval`,
		r.orgID, r.clusterID, podIPsAfter.String()); err != nil {
		return fmt.Errorf("sweep pod_ips: %w", err)
	}
	if _, err := r.pool.Exec(ctx,
		`DELETE FROM cluster_services
		  WHERE org_id = $1 AND cluster_id = $2
		    AND last_seen_at < NOW() - $3::interval`,
		r.orgID, r.clusterID, after.String()); err != nil {
		return fmt.Errorf("sweep cluster_services: %w", err)
	}
	return nil
}
