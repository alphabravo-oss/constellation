// AdmissionRuleReconciler syncs ConstellationAdmissionRule CRs into the Constellation policy
// store (policies table, category="admission"). The CR is the source of truth: each reconcile
// upserts the CR's mapped fields (correcting any DB drift), and a finalizer deletes the backing
// row when the CR is removed so no orphan policy survives. It mirrors the style of the
// ConstellationCluster Reconciler (Reconcile / SetupWithManager / status update).
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
)

// AdmissionRuleReconciler reconciles ConstellationAdmissionRule CRs.
type AdmissionRuleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Store  AdmissionRuleStore
}

// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationadmissionrules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationadmissionrules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationadmissionrules/finalizers,verbs=update

// Reconcile drives a ConstellationAdmissionRule to its desired state in the policy store.
func (r *AdmissionRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	car := &cv1alpha1.ConstellationAdmissionRule{}
	if err := r.Get(ctx, req.NamespacedName, car); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Deletion: drop the backing row, then release the finalizer.
	if car.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(car, policyFinalizer) {
			orgID, err := uuid.Parse(strings.TrimSpace(car.Spec.OrgID))
			if err != nil {
				// Spec.OrgID was mutated to a non-UUID; fall back to the org we last wrote
				// the row under so the backing row is still deleted (not orphaned).
				orgID, err = uuid.Parse(strings.TrimSpace(car.Status.LastAppliedOrgID))
			}
			if err != nil {
				// No parseable current or last-applied orgID means no row was ever written
				// we could key a delete on; release the finalizer so the CR is not wedged.
				logger.Error(err, "delete: no valid orgID, releasing finalizer", "name", car.Name)
			} else if _, derr := r.Store.DeleteAdmissionRule(ctx, orgID, car.Name); derr != nil {
				return ctrl.Result{}, fmt.Errorf("delete admission rule row: %w", derr)
			}
			controllerutil.RemoveFinalizer(car, policyFinalizer)
			if err := r.Update(ctx, car); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure the finalizer is present before we create the row, so a delete can never
	// race ahead of cleanup.
	if !controllerutil.ContainsFinalizer(car, policyFinalizer) {
		controllerutil.AddFinalizer(car, policyFinalizer)
		if err := r.Update(ctx, car); err != nil {
			return ctrl.Result{}, err
		}
		// The Update re-queues us via the watch; return now with the finalizer persisted.
		return ctrl.Result{}, nil
	}

	row, verr := mapAdmissionRule(car)
	if verr != nil {
		// Permanent (spec) error: record it and do not requeue — a spec edit re-triggers us.
		markError(&car.Status, car.Generation, "InvalidSpec", verr.Error(), true)
		if err := r.Status().Update(ctx, car); err != nil {
			logger.Error(err, "status update")
		}
		return ctrl.Result{}, nil
	}

	if err := r.Store.UpsertAdmissionRule(ctx, row); err != nil {
		if errors.Is(err, policydb.ErrImperativeConflict) {
			// The (org, name) identity is owned by a REST/UI-authored (imperative) row; the
			// store refused to clobber it. This is not transient — record it and retry slowly
			// (it self-heals only if the imperative row is removed), without an error-requeue.
			markError(&car.Status, car.Generation, "Conflict", err.Error(), true)
			if serr := r.Status().Update(ctx, car); serr != nil {
				logger.Error(serr, "status update")
			}
			return ctrl.Result{RequeueAfter: driftResyncInterval}, nil
		}
		// Transient store error: surface it and let controller-runtime requeue.
		markError(&car.Status, car.Generation, "StoreError", err.Error(), false)
		if serr := r.Status().Update(ctx, car); serr != nil {
			logger.Error(serr, "status update")
		}
		return ctrl.Result{}, err
	}

	markSynced(&car.Status, car.Generation)
	car.Status.LastAppliedOrgID = row.OrgID.String()
	if err := r.Status().Update(ctx, car); err != nil {
		logger.Error(err, "status update")
	}
	logger.Info("reconciled admission rule", "name", car.Name, "org", row.OrgID)
	return ctrl.Result{RequeueAfter: driftResyncInterval}, nil
}

// mapAdmissionRule maps a ConstellationAdmissionRule CR to its policies-row representation,
// applying the documented defaults (engine "kyverno") and validating the org scope.
func mapAdmissionRule(car *cv1alpha1.ConstellationAdmissionRule) (policydb.AdmissionRuleRow, error) {
	orgID, err := uuid.Parse(strings.TrimSpace(car.Spec.OrgID))
	if err != nil {
		return policydb.AdmissionRuleRow{}, fmt.Errorf("invalid orgID %q: %w", car.Spec.OrgID, err)
	}
	if strings.TrimSpace(car.Name) == "" {
		return policydb.AdmissionRuleRow{}, fmt.Errorf("metadata.name is required")
	}
	engine := strings.TrimSpace(car.Spec.Engine)
	if engine == "" {
		engine = "kyverno"
	}
	mode := strings.TrimSpace(car.Spec.Mode)
	if mode == "" {
		mode = "monitor"
	}
	if mode != "learn" && mode != "monitor" && mode != "enforce" {
		return policydb.AdmissionRuleRow{}, fmt.Errorf("invalid mode %q: want learn|monitor|enforce", car.Spec.Mode)
	}
	return policydb.AdmissionRuleRow{
		OrgID:       orgID,
		Name:        car.Name,
		Description: car.Spec.Description,
		Engine:      engine,
		Mode:        mode,
		Enabled:     car.Spec.Enabled,
		SpecYAML:    car.Spec.SpecYAML,
	}, nil
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *AdmissionRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cv1alpha1.ConstellationAdmissionRule{}).
		Complete(r)
}
