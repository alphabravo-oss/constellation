package controllers

import (
	"context"
	"time"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cv1alpha1 "github.com/alphabravocompany/constellation/deploy/operator/api/v1alpha1"
	"github.com/alphabravocompany/constellation/deploy/operator/policydb"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// policyFinalizer is added to every policy CR so the controller can delete the backing
// DB row before Kubernetes garbage-collects the object — guaranteeing no orphan policy
// is left in the store when a CR is removed.
const policyFinalizer = "constellation.alphabravo.io/policy-finalizer"

// driftResyncInterval is the RequeueAfter a successful (or conflicted) reconcile returns so the
// controller proactively re-asserts the CR over its backing row, correcting drift introduced
// out-of-band (a direct DB edit, or a REST/UI write to a declarative row) within bounded time
// rather than only on the next CR event or the manager's ~10h cache resync. A conflicted reconcile
// re-tries on the same cadence so it self-heals once a colliding imperative row is removed.
const driftResyncInterval = 5 * time.Minute

// AdmissionRuleStore is the operator's data-access contract for ConstellationAdmissionRule
// reconciliation. *policydb.Store satisfies it; tests provide a fake.
type AdmissionRuleStore interface {
	UpsertAdmissionRule(ctx context.Context, row policydb.AdmissionRuleRow) error
	DeleteAdmissionRule(ctx context.Context, orgID uuid.UUID, name string) (bool, error)
}

// ResponseRuleStore is the operator's data-access contract for ConstellationResponseRule
// reconciliation. *policydb.Store satisfies it; tests provide a fake.
type ResponseRuleStore interface {
	UpsertResponseRule(ctx context.Context, rule responserule.ResponseRule) error
	DeleteResponseRule(ctx context.Context, orgID uuid.UUID, name string) (bool, error)
}

// markSynced records a successful reconcile on a policy status: Synced=True, Error cleared,
// phase "Synced", observedGeneration advanced to the reconciled generation.
func markSynced(status *cv1alpha1.PolicyStatus, generation int64) {
	status.ObservedGeneration = generation
	status.Phase = "Synced"
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               cv1alpha1.ConditionSynced,
		Status:             metav1.ConditionTrue,
		Reason:             "Reconciled",
		Message:            "policy synced into the Constellation store",
		ObservedGeneration: generation,
	})
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               cv1alpha1.ConditionError,
		Status:             metav1.ConditionFalse,
		Reason:             "Reconciled",
		Message:            "no error",
		ObservedGeneration: generation,
	})
}

// markError records a failed reconcile on a policy status: Error=True with the failure,
// Synced=False, phase "Error". observedGeneration is advanced only for permanent
// (validation/conflict) failures so a client can tell the controller observed this
// generation and rejected it; for transient (requeued) failures it is left unchanged so
// an observedGeneration==generation readiness gate does not treat the retry as settled.
func markError(status *cv1alpha1.PolicyStatus, generation int64, reason, message string, permanent bool) {
	if permanent {
		status.ObservedGeneration = generation
	}
	status.Phase = "Error"
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               cv1alpha1.ConditionError,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
	})
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               cv1alpha1.ConditionSynced,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
	})
}
