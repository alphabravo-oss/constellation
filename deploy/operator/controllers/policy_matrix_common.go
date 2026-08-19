// policy_matrix_common.go wires the B7 "broader CRD coverage" reconcilers: DPI/WAF
// signatures and vulnerability exception profiles. (The ConstellationDLPSensor
// reconciler was removed in P0-01 — dlp_sensors never reached the dataplane, so it
// was an orphan surface like the WS-G G1 waf/groups CRUD.) Each reconciler mirrors the
// AdmissionRule/ResponseRule pattern (finalizer-guarded upsert-as-source-of-truth into the
// operator policy store, drift resync, source/ownership-guarded delete).
package controllers

import (
	"context"

	"github.com/google/uuid"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/alphabravocompany/constellation/deploy/operator/policydb"
)

// SignatureRuleStore is the operator's data-access contract for ConstellationSignatureRule
// reconciliation. *policydb.Store satisfies it; tests provide a fake.
type SignatureRuleStore interface {
	UpsertSignatureRule(ctx context.Context, row policydb.SignatureRow) error
	DeleteSignatureRule(ctx context.Context, orgID, clusterID uuid.UUID, name string) (bool, error)
}

// VulnProfileStore is the operator's data-access contract for ConstellationVulnProfile
// reconciliation. *policydb.Store satisfies it; tests provide a fake.
type VulnProfileStore interface {
	UpsertVulnProfile(ctx context.Context, row policydb.VulnProfileRow) error
	DeleteVulnProfile(ctx context.Context, orgID uuid.UUID, name string) (bool, error)
}

// MatrixStore is the union of the B7 store contracts. *policydb.Store satisfies it, so a single
// store instance backs both matrix reconcilers.
type MatrixStore interface {
	SignatureRuleStore
	VulnProfileStore
}

// SetupMatrixControllers registers the B7 policy reconcilers (DPI/WAF signature, vuln profile)
// with the manager, sharing one store. It is the single entrypoint the operator main wires when a
// DB DSN is configured, alongside the existing AdmissionRule/ResponseRule reconcilers.
//
// TODO(matrix): cmd/constellation-operator/main.go must call this (one line, next to the existing
// AdmissionRuleReconciler/ResponseRuleReconciler setup) to activate the new controllers at
// runtime. That file is outside the operator-crds subsystem's edit scope, so the wiring line is
// left to the integration step; the reconcilers, store, CRDs and RBAC are complete.
func SetupMatrixControllers(mgr ctrl.Manager, store MatrixStore) error {
	if err := (&SignatureRuleReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), Store: store}).SetupWithManager(mgr); err != nil {
		return err
	}
	if err := (&VulnProfileReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), Store: store}).SetupWithManager(mgr); err != nil {
		return err
	}
	return nil
}
