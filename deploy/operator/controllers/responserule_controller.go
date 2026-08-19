// ResponseRuleReconciler syncs ConstellationResponseRule CRs into the Constellation policy
// store (response_rules table, migration 103 — the E1 CLUSResponseRule-parity engine). The CR
// is the source of truth: each reconcile upserts the CR's mapped fields (correcting any DB
// drift), and a finalizer deletes the backing row when the CR is removed so no orphan rule
// survives. Mirrors the ConstellationCluster Reconciler style.
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
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// ResponseRuleReconciler reconciles ConstellationResponseRule CRs.
type ResponseRuleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Store  ResponseRuleStore
}

// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationresponserules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationresponserules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationresponserules/finalizers,verbs=update

// Reconcile drives a ConstellationResponseRule to its desired state in the policy store.
func (r *ResponseRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	crr := &cv1alpha1.ConstellationResponseRule{}
	if err := r.Get(ctx, req.NamespacedName, crr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Deletion: drop the backing row, then release the finalizer.
	if crr.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(crr, policyFinalizer) {
			orgID, err := uuid.Parse(strings.TrimSpace(crr.Spec.OrgID))
			if err != nil {
				// Spec.OrgID was mutated to a non-UUID; fall back to the org we last wrote
				// the row under so the backing row is still deleted (not orphaned).
				orgID, err = uuid.Parse(strings.TrimSpace(crr.Status.LastAppliedOrgID))
			}
			if err != nil {
				// No parseable current or last-applied orgID means no row was ever written
				// we could key a delete on; release the finalizer so the CR is not wedged.
				logger.Error(err, "delete: no valid orgID, releasing finalizer", "name", crr.Name)
			} else if _, derr := r.Store.DeleteResponseRule(ctx, orgID, crr.Name); derr != nil {
				return ctrl.Result{}, fmt.Errorf("delete response rule row: %w", derr)
			}
			controllerutil.RemoveFinalizer(crr, policyFinalizer)
			if err := r.Update(ctx, crr); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(crr, policyFinalizer) {
		controllerutil.AddFinalizer(crr, policyFinalizer)
		if err := r.Update(ctx, crr); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	rule, verr := mapResponseRule(crr)
	if verr != nil {
		markError(&crr.Status, crr.Generation, "InvalidSpec", verr.Error(), true)
		if err := r.Status().Update(ctx, crr); err != nil {
			logger.Error(err, "status update")
		}
		return ctrl.Result{}, nil
	}

	if err := r.Store.UpsertResponseRule(ctx, rule); err != nil {
		if errors.Is(err, policydb.ErrImperativeConflict) {
			// The (org, name) identity is owned by a REST/UI-authored (imperative) row; the
			// store refused to clobber it. Record it and retry slowly without an error-requeue.
			markError(&crr.Status, crr.Generation, "Conflict", err.Error(), true)
			if serr := r.Status().Update(ctx, crr); serr != nil {
				logger.Error(serr, "status update")
			}
			return ctrl.Result{RequeueAfter: driftResyncInterval}, nil
		}
		markError(&crr.Status, crr.Generation, "StoreError", err.Error(), false)
		if serr := r.Status().Update(ctx, crr); serr != nil {
			logger.Error(serr, "status update")
		}
		return ctrl.Result{}, err
	}

	markSynced(&crr.Status, crr.Generation)
	crr.Status.LastAppliedOrgID = rule.OrgID.String()
	if err := r.Status().Update(ctx, crr); err != nil {
		logger.Error(err, "status update")
	}
	logger.Info("reconciled response rule", "name", crr.Name, "org", rule.OrgID)
	return ctrl.Result{RequeueAfter: driftResyncInterval}, nil
}

// mapResponseRule maps a ConstellationResponseRule CR to a pkg/responserule.ResponseRule and
// validates it through the same gatekeeper the REST handler uses, so the operator rejects the
// same malformed specs the API does (before any store write).
func mapResponseRule(crr *cv1alpha1.ConstellationResponseRule) (responserule.ResponseRule, error) {
	orgID, err := uuid.Parse(strings.TrimSpace(crr.Spec.OrgID))
	if err != nil {
		return responserule.ResponseRule{}, fmt.Errorf("invalid orgID %q: %w", crr.Spec.OrgID, err)
	}
	conds := make([]responserule.Condition, 0, len(crr.Spec.Conditions))
	for _, c := range crr.Spec.Conditions {
		conds = append(conds, responserule.Condition{
			Field: c.Field,
			Op:    responserule.Op(c.Op),
			Value: c.Value,
		})
	}
	acts := make([]responserule.Action, 0, len(crr.Spec.Actions))
	for _, a := range crr.Spec.Actions {
		acts = append(acts, responserule.Action{
			Type:   responserule.ActionType(a.Type),
			Params: a.Params,
		})
	}
	rule := responserule.ResponseRule{
		OrgID:      orgID,
		Name:       crr.Name,
		Enabled:    crr.Spec.Enabled,
		Priority:   crr.Spec.Priority,
		EventType:  responserule.EventType(crr.Spec.EventType),
		Conditions: conds,
		Actions:    acts,
	}
	if err := rule.Validate(); err != nil {
		return responserule.ResponseRule{}, err
	}
	return rule, nil
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *ResponseRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cv1alpha1.ConstellationResponseRule{}).
		Complete(r)
}
