package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/informers"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

// namespaceLabelResolver is a client-go informer/lister backed
// admission.NamespaceLabelResolver (A5). It serves per-rule namespaceSelector
// label lookups from a cached namespace list kept warm by a SharedInformer, so
// the hot admission path never issues a live API call. The informer keeps
// running until its ctx is cancelled (graceful shutdown via factory.Start).
type namespaceLabelResolver struct {
	lister corev1listers.NamespaceLister
	log    *slog.Logger
}

// newNamespaceLabelResolver builds a namespace SharedInformer (in-cluster or from
// kubeconfig), starts it, and blocks until the cache syncs so the first admission
// request after readiness resolves labels from a populated cache. Returns an error
// when config is unavailable; the caller then logs and skips (selector rules keep
// safely no-firing).
//
// RBAC: the webhook ServiceAccount needs cluster-scoped list+watch on the core
// "namespaces" resource for the informer to sync, e.g. a ClusterRole rule:
//
//	- apiGroups: [""]
//	  resources: ["namespaces"]
//	  verbs: ["list", "watch"]
//
// Without it WaitForCacheSync fails, this returns an error, and the caller falls
// back to leaving the labeler unwired (namespaceSelector rules simply do not fire).
func newNamespaceLabelResolver(ctx context.Context, kubeconfig string, log *slog.Logger) (*namespaceLabelResolver, error) {
	client, err := newAdmissionKubeClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	factory := informers.NewSharedInformerFactory(client, 0)
	nsInformer := factory.Core().V1().Namespaces()
	lister := nsInformer.Lister()
	// Instantiate the underlying informer before Start so the factory runs it.
	informer := nsInformer.Informer()
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return nil, errors.New("namespace informer cache did not sync")
	}
	log.Info("admission namespace label resolver synced")
	return &namespaceLabelResolver{lister: lister, log: log}, nil
}

// NamespaceLabels returns the cached labels of a namespace. A not-found namespace
// resolves to nil labels with no error so a namespaceSelector rule simply doesn't
// match (rather than failing admission) — matching the engine's safe no-fire.
func (r *namespaceLabelResolver) NamespaceLabels(_ context.Context, namespace string) (map[string]string, error) {
	ns, err := r.lister.Get(namespace)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get namespace %q: %w", namespace, err)
	}
	return ns.Labels, nil
}
