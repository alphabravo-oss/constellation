package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/alphabravocompany/constellation/pkg/admission"
)

// clusterRBACResolver is a client-go backed admission.RBACResolver. It keeps an
// in-memory snapshot of the cluster's Roles/ClusterRoles + their bindings,
// classified into risky-role flags, refreshed on a ticker. Reads are lock-free
// via an atomic pointer swap so the hot admission path never blocks on a list.
type clusterRBACResolver struct {
	client kubernetes.Interface
	log    *slog.Logger
	snap   atomic.Pointer[snapshotResolver]
}

// snapshotResolver wraps the immutable resolver built from one RBAC listing.
type snapshotResolver struct {
	resolver admission.RBACResolver
}

// newClusterRBACResolver builds a client (in-cluster or from kubeconfig) and
// performs an initial synchronous refresh so the first admission request after
// readiness sees a populated snapshot.
func newClusterRBACResolver(ctx context.Context, kubeconfig string, log *slog.Logger) (*clusterRBACResolver, error) {
	client, err := newAdmissionKubeClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	r := &clusterRBACResolver{client: client, log: log}
	// Seed with an empty resolver so reads before the first refresh fail open
	// (no risky role found) rather than nil-deref.
	r.snap.Store(&snapshotResolver{resolver: admission.NewStaticRBACResolver(nil, nil, nil, nil)})
	if err := r.refresh(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// RiskyRolesForServiceAccount delegates to the current snapshot.
func (r *clusterRBACResolver) RiskyRolesForServiceAccount(ctx context.Context, namespace, name string) (admission.RiskyRole, []string, error) {
	return r.snap.Load().resolver.RiskyRolesForServiceAccount(ctx, namespace, name)
}

// refresh lists all RBAC objects and atomically swaps in a freshly classified
// resolver.
func (r *clusterRBACResolver) refresh(ctx context.Context) error {
	roles, err := r.client.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list roles: %w", err)
	}
	clusterRoles, err := r.client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list clusterroles: %w", err)
	}
	roleBindings, err := r.client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list rolebindings: %w", err)
	}
	clusterRoleBindings, err := r.client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list clusterrolebindings: %w", err)
	}
	resolver := admission.NewStaticRBACResolver(
		roles.Items, clusterRoles.Items, roleBindings.Items, clusterRoleBindings.Items)
	r.snap.Store(&snapshotResolver{resolver: resolver})
	return nil
}

// run refreshes the RBAC snapshot on a ticker until ctx is cancelled.
func (r *clusterRBACResolver) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.refresh(ctx); err != nil {
				r.log.Warn("admission RBAC refresh failed; serving stale snapshot", "err", err)
			}
		}
	}
}

func newAdmissionKubeClient(kubeconfig string) (kubernetes.Interface, error) {
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
