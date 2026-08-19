// SignatureRuleReconciler syncs ConstellationSignatureRule CRs into the Constellation policy
// store (runtime_dlp_rules table, category='signature', migrations 044/046 — the DPI/L7 signature
// surface that replaced the removed WAF-groups CRUD). The CR is the source of truth: each reconcile
// upserts the CR's mapped fields (correcting DB drift), and a finalizer deletes the backing row when
// the CR is removed. Mirrors the AdmissionRule/ResponseRule reconciler style.
//
// DATAPLANE: an upserted signature row is picked up by the existing agent sync poller (which reads
// runtime_dlp_rules by cluster+category+mode) and compiled into dp's hyperscan engine via the
// BuildDLPRules RPC — the same path REST-authored signatures take. No new dataplane wiring is
// added here; the operator is a thin k8s->store bridge.
//
// SAFETY: Mode defaults to "monitor" (dp observes and emits threat events but never drops the
// connection). "enforce" is honoured only when the CR spec explicitly asks for it.
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
	"github.com/alphabravocompany/constellation/internal/runtime/dlp"
)

// SignatureRuleReconciler reconciles ConstellationSignatureRule CRs.
type SignatureRuleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Store  SignatureRuleStore
}

// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationsignaturerules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationsignaturerules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationsignaturerules/finalizers,verbs=update

// Reconcile drives a ConstellationSignatureRule to its desired state in the policy store.
func (r *SignatureRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	cr := &cv1alpha1.ConstellationSignatureRule{}
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Deletion: drop the backing row, then release the finalizer.
	if cr.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(cr, policyFinalizer) {
			orgID, clusterID, perr := parseSignatureScope(cr)
			if perr != nil {
				logger.Error(perr, "delete: unparseable org/cluster scope, releasing finalizer", "name", cr.Name)
			} else if _, derr := r.Store.DeleteSignatureRule(ctx, orgID, clusterID, cr.Name); derr != nil {
				return ctrl.Result{}, fmt.Errorf("delete signature rule row: %w", derr)
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

	row, verr := mapSignatureRule(cr)
	if verr != nil {
		markError(&cr.Status, cr.Generation, "InvalidSpec", verr.Error(), true)
		if err := r.Status().Update(ctx, cr); err != nil {
			logger.Error(err, "status update")
		}
		return ctrl.Result{}, nil
	}

	if err := r.Store.UpsertSignatureRule(ctx, row); err != nil {
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
	logger.Info("reconciled signature rule", "name", cr.Name, "org", row.OrgID, "cluster", row.ClusterID)
	return ctrl.Result{RequeueAfter: driftResyncInterval}, nil
}

// parseSignatureScope resolves the (orgID, clusterID) delete key from the CR spec, falling back to
// the last-applied org so a mutated spec.orgID cannot orphan the backing row.
func parseSignatureScope(cr *cv1alpha1.ConstellationSignatureRule) (uuid.UUID, uuid.UUID, error) {
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

// mapSignatureRule maps a ConstellationSignatureRule CR to its runtime_dlp_rules-row
// representation, applying the documented defaults (mode "monitor", severity 5, applyDir 3=both)
// and validating org/cluster scope, mode, severity range, direction and PCRE patterns — mirroring
// internal/handler/runtime.RuntimeDLPStore.Insert — before any store write.
func mapSignatureRule(cr *cv1alpha1.ConstellationSignatureRule) (policydb.SignatureRow, error) {
	orgID, err := uuid.Parse(strings.TrimSpace(cr.Spec.OrgID))
	if err != nil {
		return policydb.SignatureRow{}, fmt.Errorf("invalid orgID %q: %w", cr.Spec.OrgID, err)
	}
	clusterID, err := uuid.Parse(strings.TrimSpace(cr.Spec.ClusterID))
	if err != nil {
		return policydb.SignatureRow{}, fmt.Errorf("invalid clusterID %q: %w", cr.Spec.ClusterID, err)
	}
	if strings.TrimSpace(cr.Name) == "" {
		return policydb.SignatureRow{}, fmt.Errorf("metadata.name is required")
	}
	// SAFETY: default mode is monitor (observe). enforce is honoured only if explicitly declared.
	mode := strings.TrimSpace(cr.Spec.Mode)
	if mode == "" {
		mode = "monitor"
	}
	if mode != "monitor" && mode != "enforce" && mode != "disabled" {
		return policydb.SignatureRow{}, fmt.Errorf("invalid mode %q: want monitor|enforce|disabled", cr.Spec.Mode)
	}
	severity := cr.Spec.Severity
	if severity == 0 {
		severity = 5
	}
	if severity < 1 || severity > 9 {
		return policydb.SignatureRow{}, fmt.Errorf("severity %d out of range: want 1..9", cr.Spec.Severity)
	}
	applyDir := cr.Spec.ApplyDir
	if applyDir == 0 {
		applyDir = 3 // signatures inspect both directions by default
	}
	if applyDir < 1 || applyDir > 3 {
		return policydb.SignatureRow{}, fmt.Errorf("applyDir %d invalid: want 1 (egress), 2 (ingress) or 3 (both)", cr.Spec.ApplyDir)
	}
	if len(cr.Spec.Patterns) == 0 {
		return policydb.SignatureRow{}, fmt.Errorf("at least one pattern is required")
	}
	patterns := make([]string, 0, len(cr.Spec.Patterns))
	for i, p := range cr.Spec.Patterns {
		if strings.TrimSpace(p) == "" {
			return policydb.SignatureRow{}, fmt.Errorf("pattern %d is empty", i)
		}
		// P1-03: validate with the PCRE-tolerant proxy, not stdlib regexp (RE2).
		// RE2 rejects lookaheads that dp's pcre2 engine accepts, which would
		// fail-closed on legitimate NeuVector-grade signature patterns.
		if cerr := dlp.CompilePattern(p); cerr != nil {
			return policydb.SignatureRow{}, fmt.Errorf("pattern %d: bad PCRE: %w", i, cerr)
		}
		patterns = append(patterns, p)
	}
	return policydb.SignatureRow{
		OrgID:       orgID,
		ClusterID:   clusterID,
		Name:        cr.Name,
		Mode:        mode,
		Severity:    severity,
		ApplyDir:    applyDir,
		Patterns:    patterns,
		Description: cr.Spec.Description,
	}, nil
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *SignatureRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cv1alpha1.ConstellationSignatureRule{}).
		Complete(r)
}
