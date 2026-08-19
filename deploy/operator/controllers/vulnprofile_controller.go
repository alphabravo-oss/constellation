// VulnProfileReconciler syncs ConstellationVulnProfile CRs into the Constellation policy store
// (vuln_profiles table, migration 022 — vulnerability exception/exemption profiles). The CR is the
// source of truth: each reconcile upserts the CR's mapped fields (correcting DB drift), and a
// finalizer deletes the backing row when the CR is removed. Mirrors the AdmissionRule/ResponseRule
// reconciler style.
package controllers

import (
	"context"
	"errors"
	"fmt"
	"regexp"
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

// VulnProfileReconciler reconciles ConstellationVulnProfile CRs.
type VulnProfileReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Store  VulnProfileStore
}

// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationvulnprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationvulnprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationvulnprofiles/finalizers,verbs=update

// Reconcile drives a ConstellationVulnProfile to its desired state in the policy store.
func (r *VulnProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	cr := &cv1alpha1.ConstellationVulnProfile{}
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Deletion: drop the backing row, then release the finalizer.
	if cr.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(cr, policyFinalizer) {
			orgID, err := uuid.Parse(strings.TrimSpace(cr.Spec.OrgID))
			if err != nil {
				orgID, err = uuid.Parse(strings.TrimSpace(cr.Status.LastAppliedOrgID))
			}
			if err != nil {
				logger.Error(err, "delete: no valid orgID, releasing finalizer", "name", cr.Name)
			} else if _, derr := r.Store.DeleteVulnProfile(ctx, orgID, cr.Name); derr != nil {
				return ctrl.Result{}, fmt.Errorf("delete vuln profile row: %w", derr)
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

	row, verr := mapVulnProfile(cr)
	if verr != nil {
		markError(&cr.Status, cr.Generation, "InvalidSpec", verr.Error(), true)
		if err := r.Status().Update(ctx, cr); err != nil {
			logger.Error(err, "status update")
		}
		return ctrl.Result{}, nil
	}

	if err := r.Store.UpsertVulnProfile(ctx, row); err != nil {
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
	logger.Info("reconciled vuln profile", "name", cr.Name, "org", row.OrgID)
	return ctrl.Result{RequeueAfter: driftResyncInterval}, nil
}

// mapVulnProfile maps a ConstellationVulnProfile CR to its vuln_profiles-row representation,
// validating the org scope and each entry's action, severity floor and CVE name regex (mirroring
// pkg/vulnprofile.Profile.Validate) before any store write. Entry/DomainScope fields are converted
// from the CR's camelCase spec into the DB's snake_case JSONB shape the vuln evaluator reads.
func mapVulnProfile(cr *cv1alpha1.ConstellationVulnProfile) (policydb.VulnProfileRow, error) {
	orgID, err := uuid.Parse(strings.TrimSpace(cr.Spec.OrgID))
	if err != nil {
		return policydb.VulnProfileRow{}, fmt.Errorf("invalid orgID %q: %w", cr.Spec.OrgID, err)
	}
	if strings.TrimSpace(cr.Name) == "" {
		return policydb.VulnProfileRow{}, fmt.Errorf("metadata.name is required")
	}
	entries := make([]policydb.VulnProfileEntry, 0, len(cr.Spec.Entries))
	for i, e := range cr.Spec.Entries {
		if strings.TrimSpace(e.Name) == "" {
			return policydb.VulnProfileRow{}, fmt.Errorf("entry %d: name is required", i)
		}
		if e.Action != "suppress" && e.Action != "escalate" {
			return policydb.VulnProfileRow{}, fmt.Errorf("entry %d %q: invalid action %q: want suppress|escalate", i, e.Name, e.Action)
		}
		if e.NameRegex != "" {
			if _, rerr := regexp.Compile(e.NameRegex); rerr != nil {
				return policydb.VulnProfileRow{}, fmt.Errorf("entry %d %q: bad nameRegex: %w", i, e.Name, rerr)
			}
		}
		if e.SeverityFloor != "" {
			switch e.SeverityFloor {
			case "low", "medium", "high", "critical":
			default:
				return policydb.VulnProfileRow{}, fmt.Errorf("entry %d %q: invalid severityFloor %q: want low|medium|high|critical", i, e.Name, e.SeverityFloor)
			}
		}
		entries = append(entries, policydb.VulnProfileEntry{
			Name:          e.Name,
			NameRegex:     e.NameRegex,
			Images:        e.Images,
			Action:        e.Action,
			DaysToFix:     e.DaysToFix,
			SeverityFloor: e.SeverityFloor,
			ScoreFloor:    e.ScoreFloor,
			Reserved:      e.Reserved,
			RecentDays:    e.RecentDays,
			Comment:       e.Comment,
		})
	}
	return policydb.VulnProfileRow{
		OrgID:       orgID,
		Name:        cr.Name,
		Description: cr.Spec.Description,
		Active:      cr.Spec.Active,
		Entries:     entries,
		DomainScope: policydb.VulnDomainScope{
			Clusters:   cr.Spec.DomainScope.Clusters,
			Namespaces: cr.Spec.DomainScope.Namespaces,
		},
	}, nil
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *VulnProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cv1alpha1.ConstellationVulnProfile{}).
		Complete(r)
}
