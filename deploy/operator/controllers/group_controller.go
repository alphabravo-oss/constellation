// group_controller.go wires the P0-08 "policy-groups" reconcilers: ConstellationGroup (workload
// selector → groups table) and ConstellationNetworkRule (group→group segmentation edge →
// group_rule_edges table) — the NeuVector NvSecurityRule/NvGroupDefinition GitOps parity surface.
//
// Each reconciler mirrors the AdmissionRule/SignatureRule pattern: finalizer-guarded
// upsert-as-source-of-truth into the operator policy store, drift resync, created_by-guarded delete.
// The CR is the source of truth for the AUTHORED columns; membership (groups.members) and edge
// expansion (runtime_policies) stay server-computed — the existing GroupMembershipReconciler
// recomputes them downstream, so a group/edge authored in GitOps follows future members exactly as a
// REST-authored one does.
//
// SAFETY: modes default to "monitor" (observe, never block) in the mapping; "protect" is honoured
// only when the CR spec explicitly asks for it.
package controllers

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cv1alpha1 "github.com/alphabravocompany/constellation/deploy/operator/api/v1alpha1"
	"github.com/alphabravocompany/constellation/deploy/operator/policydb"
	"github.com/alphabravocompany/constellation/pkg/group"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// GroupStore is the operator's data-access contract for ConstellationGroup reconciliation.
// *policydb.Store satisfies it; tests provide a fake.
type GroupStore interface {
	UpsertGroup(ctx context.Context, row policydb.GroupRow) error
	DeleteGroup(ctx context.Context, orgID uuid.UUID, name string) (bool, error)
}

// NetworkRuleStore is the operator's data-access contract for ConstellationNetworkRule
// reconciliation. *policydb.Store satisfies it; tests provide a fake.
type NetworkRuleStore interface {
	UpsertNetworkRule(ctx context.Context, row policydb.NetworkRuleRow) error
	DeleteNetworkRule(ctx context.Context, orgID, clusterID uuid.UUID, fromGroup, toGroup string) (bool, error)
}

// GroupsStore is the union of the P0-08 store contracts. *policydb.Store satisfies it, so a single
// store instance backs both reconcilers.
type GroupsStore interface {
	GroupStore
	NetworkRuleStore
}

// SetupGroupControllers registers the P0-08 policy-groups reconcilers (group + network-rule) with
// the manager, sharing one store. The operator main wires this alongside the AdmissionRule/
// ResponseRule reconcilers when a DB DSN is configured.
func SetupGroupControllers(mgr ctrl.Manager, store GroupsStore) error {
	if err := (&GroupReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), Store: store}).SetupWithManager(mgr); err != nil {
		return err
	}
	if err := (&NetworkRuleReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), Store: store}).SetupWithManager(mgr); err != nil {
		return err
	}
	return nil
}

// ------------------------------- ConstellationGroup -------------------------------

// GroupReconciler reconciles ConstellationGroup CRs.
type GroupReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Store  GroupStore
}

// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationgroups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationgroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationgroups/finalizers,verbs=update

// Reconcile drives a ConstellationGroup to its desired state in the policy store.
func (r *GroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	cr := &cv1alpha1.ConstellationGroup{}
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if cr.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(cr, policyFinalizer) {
			orgID, err := uuid.Parse(strings.TrimSpace(cr.Spec.OrgID))
			if err != nil {
				orgID, err = uuid.Parse(strings.TrimSpace(cr.Status.LastAppliedOrgID))
			}
			if err != nil {
				logger.Error(err, "delete: no valid orgID, releasing finalizer", "name", cr.Name)
			} else if _, derr := r.Store.DeleteGroup(ctx, orgID, cr.Name); derr != nil {
				return ctrl.Result{}, fmt.Errorf("delete group row: %w", derr)
			}
			controllerutil.RemoveFinalizer(cr, policyFinalizer)
			if err := r.Update(ctx, cr); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(cr, policyFinalizer) {
		controllerutil.AddFinalizer(cr, policyFinalizer)
		if err := r.Update(ctx, cr); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	row, verr := mapGroup(cr)
	if verr != nil {
		markError(&cr.Status, cr.Generation, "InvalidSpec", verr.Error(), true)
		if err := r.Status().Update(ctx, cr); err != nil {
			logger.Error(err, "status update")
		}
		return ctrl.Result{}, nil
	}

	if err := r.Store.UpsertGroup(ctx, row); err != nil {
		if errors.Is(err, policydb.ErrImperativeConflict) {
			markError(&cr.Status, cr.Generation, "Conflict", err.Error(), true)
			if serr := r.Status().Update(ctx, cr); serr != nil {
				logger.Error(serr, "status update")
			}
			return ctrl.Result{RequeueAfter: driftResyncInterval}, nil
		}
		markError(&cr.Status, cr.Generation, "StoreError", err.Error(), false)
		if serr := r.Status().Update(ctx, cr); serr != nil {
			logger.Error(serr, "status update")
		}
		return ctrl.Result{}, err
	}

	markSynced(&cr.Status, cr.Generation)
	cr.Status.LastAppliedOrgID = row.OrgID.String()
	if err := r.Status().Update(ctx, cr); err != nil {
		logger.Error(err, "status update")
	}
	logger.Info("reconciled group", "name", cr.Name, "org", row.OrgID)
	return ctrl.Result{RequeueAfter: driftResyncInterval}, nil
}

// mapGroup maps a ConstellationGroup CR to its groups-row representation, applying the documented
// defaults (kind "ground", modes "monitor") and validating org scope, kind, modes and criteria via
// the shared pkg/group.Validate gatekeeper — before any store write.
func mapGroup(cr *cv1alpha1.ConstellationGroup) (policydb.GroupRow, error) {
	orgID, err := uuid.Parse(strings.TrimSpace(cr.Spec.OrgID))
	if err != nil {
		return policydb.GroupRow{}, fmt.Errorf("invalid orgID %q: %w", cr.Spec.OrgID, err)
	}
	if strings.TrimSpace(cr.Name) == "" {
		return policydb.GroupRow{}, fmt.Errorf("metadata.name is required")
	}
	kind := group.Kind(strings.TrimSpace(cr.Spec.Kind))
	if kind == "" {
		kind = group.KindGround // a declaratively authored group is a user-defined ground-truth selector
	}
	crit := make([]group.Criterion, 0, len(cr.Spec.Criteria))
	for _, c := range cr.Spec.Criteria {
		crit = append(crit, group.Criterion{Key: c.Key, Value: c.Value, Op: group.Op(c.Op)})
	}
	g := group.Group{
		Name:        cr.Name,
		Kind:        kind,
		Comment:     cr.Spec.Comment,
		Criteria:    crit,
		PolicyMode:  group.Mode(strings.TrimSpace(cr.Spec.PolicyMode)),
		ProfileMode: group.Mode(strings.TrimSpace(cr.Spec.ProfileMode)),
	}
	// Validate defaults empty modes to monitor and rejects bad kind/mode/regex.
	if err := g.Validate(); err != nil {
		return policydb.GroupRow{}, err
	}
	return policydb.GroupRow{
		OrgID:       orgID,
		Name:        g.Name,
		Kind:        string(g.Kind),
		Comment:     g.Comment,
		Criteria:    g.Criteria,
		PolicyMode:  string(g.PolicyMode),
		ProfileMode: string(g.ProfileMode),
	}, nil
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *GroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cv1alpha1.ConstellationGroup{}).
		Complete(r)
}

// ----------------------------- ConstellationNetworkRule -----------------------------

// NetworkRuleReconciler reconciles ConstellationNetworkRule CRs.
type NetworkRuleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Store  NetworkRuleStore
}

// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationnetworkrules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationnetworkrules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationnetworkrules/finalizers,verbs=update

// Reconcile drives a ConstellationNetworkRule to its desired state in the policy store.
func (r *NetworkRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	cr := &cv1alpha1.ConstellationNetworkRule{}
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if cr.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(cr, policyFinalizer) {
			orgID, clusterID, perr := parseNetworkRuleScope(cr)
			if perr != nil {
				logger.Error(perr, "delete: unparseable org/cluster scope, releasing finalizer", "name", cr.Name)
			} else if _, derr := r.Store.DeleteNetworkRule(ctx, orgID, clusterID,
				strings.TrimSpace(cr.Spec.FromGroup), strings.TrimSpace(cr.Spec.ToGroup)); derr != nil {
				return ctrl.Result{}, fmt.Errorf("delete network rule row: %w", derr)
			}
			controllerutil.RemoveFinalizer(cr, policyFinalizer)
			if err := r.Update(ctx, cr); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(cr, policyFinalizer) {
		controllerutil.AddFinalizer(cr, policyFinalizer)
		if err := r.Update(ctx, cr); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	row, verr := mapNetworkRule(cr)
	if verr != nil {
		markError(&cr.Status, cr.Generation, "InvalidSpec", verr.Error(), true)
		if err := r.Status().Update(ctx, cr); err != nil {
			logger.Error(err, "status update")
		}
		return ctrl.Result{}, nil
	}

	if err := r.Store.UpsertNetworkRule(ctx, row); err != nil {
		if errors.Is(err, policydb.ErrImperativeConflict) {
			markError(&cr.Status, cr.Generation, "Conflict", err.Error(), true)
			if serr := r.Status().Update(ctx, cr); serr != nil {
				logger.Error(serr, "status update")
			}
			return ctrl.Result{RequeueAfter: driftResyncInterval}, nil
		}
		markError(&cr.Status, cr.Generation, "StoreError", err.Error(), false)
		if serr := r.Status().Update(ctx, cr); serr != nil {
			logger.Error(serr, "status update")
		}
		return ctrl.Result{}, err
	}

	markSynced(&cr.Status, cr.Generation)
	cr.Status.LastAppliedOrgID = row.OrgID.String()
	if err := r.Status().Update(ctx, cr); err != nil {
		logger.Error(err, "status update")
	}
	logger.Info("reconciled network rule", "name", cr.Name, "org", row.OrgID, "cluster", row.ClusterID)
	return ctrl.Result{RequeueAfter: driftResyncInterval}, nil
}

// parseNetworkRuleScope resolves the (orgID, clusterID) delete key from the CR spec, falling back
// to the last-applied org so a mutated spec.orgID cannot orphan the backing row.
func parseNetworkRuleScope(cr *cv1alpha1.ConstellationNetworkRule) (uuid.UUID, uuid.UUID, error) {
	orgID, err := uuid.Parse(strings.TrimSpace(cr.Spec.OrgID))
	if err != nil {
		orgID, err = uuid.Parse(strings.TrimSpace(cr.Status.LastAppliedOrgID))
		if err != nil {
			return uuid.Nil, uuid.Nil, fmt.Errorf("no valid orgID")
		}
	}
	clusterID, cerr := uuid.Parse(strings.TrimSpace(cr.Spec.ClusterID))
	if cerr != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid clusterID %q: %w", cr.Spec.ClusterID, cerr)
	}
	return orgID, clusterID, nil
}

// mapNetworkRule maps a ConstellationNetworkRule CR to its group_rule_edges-row representation,
// applying the documented default (mode "monitor") and validating org/cluster scope plus the edge
// itself via the shared pkg/netpolicy.GroupEdge.Validate gatekeeper (which normalises ports and
// rejects a bad mode) — before any store write.
func mapNetworkRule(cr *cv1alpha1.ConstellationNetworkRule) (policydb.NetworkRuleRow, error) {
	orgID, err := uuid.Parse(strings.TrimSpace(cr.Spec.OrgID))
	if err != nil {
		return policydb.NetworkRuleRow{}, fmt.Errorf("invalid orgID %q: %w", cr.Spec.OrgID, err)
	}
	clusterID, err := uuid.Parse(strings.TrimSpace(cr.Spec.ClusterID))
	if err != nil {
		return policydb.NetworkRuleRow{}, fmt.Errorf("invalid clusterID %q: %w", cr.Spec.ClusterID, err)
	}
	ports := make([]netpolicy.PortSpec, 0, len(cr.Spec.Ports))
	for _, p := range cr.Spec.Ports {
		ports = append(ports, netpolicy.PortSpec{Protocol: p.Protocol, Port: p.Port})
	}
	edge := netpolicy.GroupEdge{
		FromGroup: strings.TrimSpace(cr.Spec.FromGroup),
		ToGroup:   strings.TrimSpace(cr.Spec.ToGroup),
		Ports:     ports,
		Mode:      strings.TrimSpace(cr.Spec.Mode),
		Comment:   cr.Spec.Comment,
	}
	// Validate normalises ports (uppercases protocol, defaults TCP), defaults mode to monitor,
	// and rejects a missing from/to or a bad mode/port.
	if err := edge.Validate(); err != nil {
		return policydb.NetworkRuleRow{}, err
	}
	return policydb.NetworkRuleRow{
		OrgID:     orgID,
		ClusterID: clusterID,
		FromGroup: edge.FromGroup,
		ToGroup:   edge.ToGroup,
		Ports:     edge.Ports,
		Mode:      edge.Mode,
		Comment:   edge.Comment,
	}, nil
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *NetworkRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cv1alpha1.ConstellationNetworkRule{}).
		Complete(r)
}
