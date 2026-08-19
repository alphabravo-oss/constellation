package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	cv1alpha1 "github.com/alphabravocompany/constellation/deploy/operator/api/v1alpha1"
	"github.com/alphabravocompany/constellation/deploy/operator/policydb"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

func policyScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(cv1alpha1.AddToScheme(s))
	return s
}

func rowKey(org uuid.UUID, name string) string { return org.String() + "|" + name }

// --- fake admission store ---------------------------------------------------

type fakeAdmStore struct {
	rows      map[string]policydb.AdmissionRuleRow
	upserts   int
	deletes   int
	upsertErr error
}

func newFakeAdmStore() *fakeAdmStore {
	return &fakeAdmStore{rows: map[string]policydb.AdmissionRuleRow{}}
}

func (f *fakeAdmStore) UpsertAdmissionRule(_ context.Context, row policydb.AdmissionRuleRow) error {
	if f.upsertErr != nil {
		return f.upsertErr
	}
	f.upserts++
	f.rows[rowKey(row.OrgID, row.Name)] = row
	return nil
}

func (f *fakeAdmStore) DeleteAdmissionRule(_ context.Context, org uuid.UUID, name string) (bool, error) {
	f.deletes++
	k := rowKey(org, name)
	_, ok := f.rows[k]
	delete(f.rows, k)
	return ok, nil
}

// --- fake response store ----------------------------------------------------

type fakeRespStore struct {
	rows      map[string]responserule.ResponseRule
	upserts   int
	deletes   int
	upsertErr error
}

func newFakeRespStore() *fakeRespStore {
	return &fakeRespStore{rows: map[string]responserule.ResponseRule{}}
}

func (f *fakeRespStore) UpsertResponseRule(_ context.Context, rule responserule.ResponseRule) error {
	if f.upsertErr != nil {
		return f.upsertErr
	}
	f.upserts++
	f.rows[rowKey(rule.OrgID, rule.Name)] = rule
	return nil
}

func (f *fakeRespStore) DeleteResponseRule(_ context.Context, org uuid.UUID, name string) (bool, error) {
	f.deletes++
	k := rowKey(org, name)
	_, ok := f.rows[k]
	delete(f.rows, k)
	return ok, nil
}

// --- helpers ----------------------------------------------------------------

const testOrg = "11111111-1111-1111-1111-111111111111"

func condTrue(conds []metav1.Condition, typ string) bool {
	c := apimeta.FindStatusCondition(conds, typ)
	return c != nil && c.Status == metav1.ConditionTrue
}

// =================== ConstellationAdmissionRule ============================

func TestAdmissionRule_AddsFinalizerThenUpserts(t *testing.T) {
	scheme := policyScheme(t)
	car := &cv1alpha1.ConstellationAdmissionRule{
		ObjectMeta: metav1.ObjectMeta{Name: "no-privileged", Generation: 1},
		Spec: cv1alpha1.ConstellationAdmissionRuleSpec{
			OrgID: testOrg, Mode: "enforce", Enabled: true, SpecYAML: "kind: AdmissionRule",
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(car).
		WithStatusSubresource(&cv1alpha1.ConstellationAdmissionRule{}).Build()
	store := newFakeAdmStore()
	r := &AdmissionRuleReconciler{Client: c, Scheme: scheme, Store: store}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: car.Name}}

	// First reconcile only installs the finalizer (no store write yet).
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile #1: %v", err)
	}
	if store.upserts != 0 {
		t.Fatalf("upserts after finalizer pass = %d, want 0", store.upserts)
	}
	got := &cv1alpha1.ConstellationAdmissionRule{}
	if err := c.Get(context.Background(), req.NamespacedName, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !controllerutil.ContainsFinalizer(got, policyFinalizer) {
		t.Fatalf("finalizer not added")
	}

	// Second reconcile upserts the mapped row + marks Synced.
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile #2: %v", err)
	}
	if store.upserts != 1 {
		t.Fatalf("upserts = %d, want 1", store.upserts)
	}
	row, ok := store.rows[rowKey(uuid.MustParse(testOrg), car.Name)]
	if !ok {
		t.Fatalf("row not stored")
	}
	if row.Mode != "enforce" || !row.Enabled || row.Engine != "kyverno" || row.SpecYAML != "kind: AdmissionRule" {
		t.Fatalf("mapped row mismatch: %+v", row)
	}
	if err := c.Get(context.Background(), req.NamespacedName, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !condTrue(got.Status.Conditions, cv1alpha1.ConditionSynced) {
		t.Fatalf("Synced condition not true: %+v", got.Status.Conditions)
	}
	if got.Status.ObservedGeneration != 1 || got.Status.Phase != "Synced" {
		t.Fatalf("status = %+v, want gen 1 / Synced", got.Status)
	}

	// Re-reconcile is idempotent (another clean upsert, no error, same mapping).
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile #3: %v", err)
	}
	if store.upserts != 2 {
		t.Fatalf("idempotent upserts = %d, want 2", store.upserts)
	}
}

func TestAdmissionRule_DriftCorrected(t *testing.T) {
	scheme := policyScheme(t)
	car := &cv1alpha1.ConstellationAdmissionRule{
		ObjectMeta: metav1.ObjectMeta{Name: "drifty", Generation: 1, Finalizers: []string{policyFinalizer}},
		Spec: cv1alpha1.ConstellationAdmissionRuleSpec{
			OrgID: testOrg, Mode: "enforce", Enabled: true, SpecYAML: "spec: true",
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(car).
		WithStatusSubresource(&cv1alpha1.ConstellationAdmissionRule{}).Build()
	store := newFakeAdmStore()
	r := &AdmissionRuleReconciler{Client: c, Scheme: scheme, Store: store}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: car.Name}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// Simulate out-of-band drift in the stored row.
	k := rowKey(uuid.MustParse(testOrg), car.Name)
	drifted := store.rows[k]
	drifted.Mode = "monitor"
	drifted.Enabled = false
	store.rows[k] = drifted

	// Reconcile again: CR is source of truth, drift overwritten.
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile (drift): %v", err)
	}
	if store.rows[k].Mode != "enforce" || !store.rows[k].Enabled {
		t.Fatalf("drift not corrected: %+v", store.rows[k])
	}
}

func TestAdmissionRule_DeleteRemovesRowAndFinalizer(t *testing.T) {
	scheme := policyScheme(t)
	now := metav1.NewTime(time.Now())
	car := &cv1alpha1.ConstellationAdmissionRule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "to-delete", Generation: 1,
			Finalizers:        []string{policyFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: cv1alpha1.ConstellationAdmissionRuleSpec{OrgID: testOrg, Mode: "enforce", Enabled: true},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(car).
		WithStatusSubresource(&cv1alpha1.ConstellationAdmissionRule{}).Build()
	store := newFakeAdmStore()
	// Seed the row the CR "owns".
	store.rows[rowKey(uuid.MustParse(testOrg), car.Name)] = policydb.AdmissionRuleRow{OrgID: uuid.MustParse(testOrg), Name: car.Name}
	r := &AdmissionRuleReconciler{Client: c, Scheme: scheme, Store: store}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: car.Name}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile (delete): %v", err)
	}
	if store.deletes != 1 {
		t.Fatalf("deletes = %d, want 1", store.deletes)
	}
	if _, ok := store.rows[rowKey(uuid.MustParse(testOrg), car.Name)]; ok {
		t.Fatalf("row not deleted")
	}
	// Finalizer released => object gone from the fake client.
	got := &cv1alpha1.ConstellationAdmissionRule{}
	err := c.Get(context.Background(), req.NamespacedName, got)
	if err == nil {
		t.Fatalf("object still present, finalizer not released")
	}
}

// TestAdmissionRule_DeleteMutatedOrgIDUsesLastApplied proves that when .spec.orgID has been
// mutated to a non-UUID after the row was written, deletion falls back to the last-applied org
// so the backing row is still removed (not orphaned) before the finalizer is released.
func TestAdmissionRule_DeleteMutatedOrgIDUsesLastApplied(t *testing.T) {
	scheme := policyScheme(t)
	now := metav1.NewTime(time.Now())
	car := &cv1alpha1.ConstellationAdmissionRule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "mutated", Generation: 1,
			Finalizers:        []string{policyFinalizer},
			DeletionTimestamp: &now,
		},
		Spec:   cv1alpha1.ConstellationAdmissionRuleSpec{OrgID: "not-a-uuid-anymore", Mode: "enforce"},
		Status: cv1alpha1.PolicyStatus{LastAppliedOrgID: testOrg},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(car).
		WithStatusSubresource(&cv1alpha1.ConstellationAdmissionRule{}).Build()
	store := newFakeAdmStore()
	store.rows[rowKey(uuid.MustParse(testOrg), car.Name)] = policydb.AdmissionRuleRow{OrgID: uuid.MustParse(testOrg), Name: car.Name}
	r := &AdmissionRuleReconciler{Client: c, Scheme: scheme, Store: store}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: car.Name}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile (delete): %v", err)
	}
	if _, ok := store.rows[rowKey(uuid.MustParse(testOrg), car.Name)]; ok {
		t.Fatalf("orphan: row under last-applied org not deleted")
	}
	got := &cv1alpha1.ConstellationAdmissionRule{}
	if err := c.Get(context.Background(), req.NamespacedName, got); err == nil {
		t.Fatalf("object still present, finalizer not released")
	}
}

func TestAdmissionRule_InvalidSpecNoUpsert(t *testing.T) {
	scheme := policyScheme(t)
	car := &cv1alpha1.ConstellationAdmissionRule{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-org", Generation: 1, Finalizers: []string{policyFinalizer}},
		Spec:       cv1alpha1.ConstellationAdmissionRuleSpec{OrgID: "not-a-uuid", Mode: "enforce"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(car).
		WithStatusSubresource(&cv1alpha1.ConstellationAdmissionRule{}).Build()
	store := newFakeAdmStore()
	r := &AdmissionRuleReconciler{Client: c, Scheme: scheme, Store: store}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: car.Name}}

	res, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("invalid spec should not requeue with error: %v", err)
	}
	if res.Requeue {
		t.Fatalf("invalid spec should not requeue")
	}
	if store.upserts != 0 {
		t.Fatalf("upserts on invalid spec = %d, want 0", store.upserts)
	}
	got := &cv1alpha1.ConstellationAdmissionRule{}
	if err := c.Get(context.Background(), req.NamespacedName, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !condTrue(got.Status.Conditions, cv1alpha1.ConditionError) {
		t.Fatalf("Error condition not true: %+v", got.Status.Conditions)
	}
}

func TestAdmissionRule_StoreErrorRequeues(t *testing.T) {
	scheme := policyScheme(t)
	car := &cv1alpha1.ConstellationAdmissionRule{
		ObjectMeta: metav1.ObjectMeta{Name: "transient", Generation: 1, Finalizers: []string{policyFinalizer}},
		Spec:       cv1alpha1.ConstellationAdmissionRuleSpec{OrgID: testOrg, Mode: "enforce"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(car).
		WithStatusSubresource(&cv1alpha1.ConstellationAdmissionRule{}).Build()
	store := newFakeAdmStore()
	store.upsertErr = errors.New("db down")
	r := &AdmissionRuleReconciler{Client: c, Scheme: scheme, Store: store}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: car.Name}}

	if _, err := r.Reconcile(context.Background(), req); err == nil {
		t.Fatalf("store error should be returned to trigger requeue")
	}
}

// TestAdmissionRule_ImperativeConflictSurfaced proves a CR whose identity collides with an
// imperative row is reported as a Conflict (not a transient error-requeue) and is retried slowly so
// it self-heals if the imperative row is later removed.
func TestAdmissionRule_ImperativeConflictSurfaced(t *testing.T) {
	scheme := policyScheme(t)
	car := &cv1alpha1.ConstellationAdmissionRule{
		ObjectMeta: metav1.ObjectMeta{Name: "collide", Generation: 1, Finalizers: []string{policyFinalizer}},
		Spec:       cv1alpha1.ConstellationAdmissionRuleSpec{OrgID: testOrg, Mode: "enforce"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(car).
		WithStatusSubresource(&cv1alpha1.ConstellationAdmissionRule{}).Build()
	store := newFakeAdmStore()
	store.upsertErr = policydb.ErrImperativeConflict
	r := &AdmissionRuleReconciler{Client: c, Scheme: scheme, Store: store}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: car.Name}}

	res, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("imperative conflict must not error-requeue: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatalf("imperative conflict should requeue-after for self-heal")
	}
	got := &cv1alpha1.ConstellationAdmissionRule{}
	if err := c.Get(context.Background(), req.NamespacedName, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	cond := apimeta.FindStatusCondition(got.Status.Conditions, cv1alpha1.ConditionError)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "Conflict" {
		t.Fatalf("want Error=True reason=Conflict, got %+v", cond)
	}
}

// =================== ConstellationResponseRule ============================

func newResponseCR() *cv1alpha1.ConstellationResponseRule {
	return &cv1alpha1.ConstellationResponseRule{
		ObjectMeta: metav1.ObjectMeta{Name: "curl-quarantine", Generation: 1, Finalizers: []string{policyFinalizer}},
		Spec: cv1alpha1.ConstellationResponseRuleSpec{
			OrgID: testOrg, Enabled: true, Priority: 10, EventType: "process",
			Conditions: []cv1alpha1.ResponseRuleCondition{{Field: "process_name", Op: "contains", Value: "curl"}},
			Actions:    []cv1alpha1.ResponseRuleAction{{Type: "quarantine"}},
		},
	}
}

func TestResponseRule_UpsertMapsFields(t *testing.T) {
	scheme := policyScheme(t)
	crr := newResponseCR()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(crr).
		WithStatusSubresource(&cv1alpha1.ConstellationResponseRule{}).Build()
	store := newFakeRespStore()
	r := &ResponseRuleReconciler{Client: c, Scheme: scheme, Store: store}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: crr.Name}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if store.upserts != 1 {
		t.Fatalf("upserts = %d, want 1", store.upserts)
	}
	rule, ok := store.rows[rowKey(uuid.MustParse(testOrg), crr.Name)]
	if !ok {
		t.Fatalf("rule not stored")
	}
	if rule.Priority != 10 || rule.EventType != responserule.EventProcess ||
		len(rule.Conditions) != 1 || rule.Conditions[0].Op != responserule.OpContains ||
		len(rule.Actions) != 1 || rule.Actions[0].Type != responserule.ActionQuarantine {
		t.Fatalf("mapped rule mismatch: %+v", rule)
	}

	// Idempotent re-reconcile.
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile #2: %v", err)
	}
	if store.upserts != 2 {
		t.Fatalf("idempotent upserts = %d, want 2", store.upserts)
	}
	got := &cv1alpha1.ConstellationResponseRule{}
	if err := c.Get(context.Background(), req.NamespacedName, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !condTrue(got.Status.Conditions, cv1alpha1.ConditionSynced) || got.Status.ObservedGeneration != 1 {
		t.Fatalf("status not Synced@gen1: %+v", got.Status)
	}
}

// TestResponseRule_DeleteMutatedOrgIDUsesLastApplied mirrors the admission-rule case: a
// non-UUID .spec.orgID at delete time falls back to the last-applied org so no orphan row
// survives to keep firing actions.
func TestResponseRule_DeleteMutatedOrgIDUsesLastApplied(t *testing.T) {
	scheme := policyScheme(t)
	now := metav1.NewTime(time.Now())
	crr := newResponseCR()
	crr.Spec.OrgID = "not-a-uuid-anymore"
	crr.Status.LastAppliedOrgID = testOrg
	crr.DeletionTimestamp = &now
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(crr).
		WithStatusSubresource(&cv1alpha1.ConstellationResponseRule{}).Build()
	store := newFakeRespStore()
	store.rows[rowKey(uuid.MustParse(testOrg), crr.Name)] = responserule.ResponseRule{OrgID: uuid.MustParse(testOrg), Name: crr.Name}
	r := &ResponseRuleReconciler{Client: c, Scheme: scheme, Store: store}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: crr.Name}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile (delete): %v", err)
	}
	if _, ok := store.rows[rowKey(uuid.MustParse(testOrg), crr.Name)]; ok {
		t.Fatalf("orphan: row under last-applied org not deleted")
	}
	got := &cv1alpha1.ConstellationResponseRule{}
	if err := c.Get(context.Background(), req.NamespacedName, got); err == nil {
		t.Fatalf("object still present, finalizer not released")
	}
}

// TestMarkError_TransientDoesNotAdvanceObservedGeneration guards the L6 contract: a transient
// (requeued) StoreError must NOT advance ObservedGeneration, while a permanent failure does, so a
// readiness gate keyed on observedGeneration==generation cannot mistake a retry for settled.
func TestMarkError_TransientDoesNotAdvanceObservedGeneration(t *testing.T) {
	transient := &cv1alpha1.PolicyStatus{ObservedGeneration: 3}
	markError(transient, 7, "StoreError", "db down", false)
	if transient.ObservedGeneration != 3 {
		t.Fatalf("transient error advanced ObservedGeneration to %d, want 3", transient.ObservedGeneration)
	}
	permanent := &cv1alpha1.PolicyStatus{ObservedGeneration: 3}
	markError(permanent, 7, "InvalidSpec", "bad", true)
	if permanent.ObservedGeneration != 7 {
		t.Fatalf("permanent error left ObservedGeneration at %d, want 7", permanent.ObservedGeneration)
	}
}

func TestResponseRule_InvalidSpecRejected(t *testing.T) {
	scheme := policyScheme(t)
	crr := newResponseCR()
	crr.Spec.Conditions[0].Op = "startswith" // invalid op -> Validate fails
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(crr).
		WithStatusSubresource(&cv1alpha1.ConstellationResponseRule{}).Build()
	store := newFakeRespStore()
	r := &ResponseRuleReconciler{Client: c, Scheme: scheme, Store: store}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: crr.Name}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("invalid spec should not error-requeue: %v", err)
	}
	if store.upserts != 0 {
		t.Fatalf("upserts on invalid spec = %d, want 0", store.upserts)
	}
	got := &cv1alpha1.ConstellationResponseRule{}
	if err := c.Get(context.Background(), req.NamespacedName, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !condTrue(got.Status.Conditions, cv1alpha1.ConditionError) {
		t.Fatalf("Error condition not set: %+v", got.Status.Conditions)
	}
}

func TestResponseRule_DeleteRemovesRow(t *testing.T) {
	scheme := policyScheme(t)
	now := metav1.NewTime(time.Now())
	crr := newResponseCR()
	crr.DeletionTimestamp = &now
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(crr).
		WithStatusSubresource(&cv1alpha1.ConstellationResponseRule{}).Build()
	store := newFakeRespStore()
	store.rows[rowKey(uuid.MustParse(testOrg), crr.Name)] = responserule.ResponseRule{OrgID: uuid.MustParse(testOrg), Name: crr.Name}
	r := &ResponseRuleReconciler{Client: c, Scheme: scheme, Store: store}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: crr.Name}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile (delete): %v", err)
	}
	if store.deletes != 1 {
		t.Fatalf("deletes = %d, want 1", store.deletes)
	}
	if _, ok := store.rows[rowKey(uuid.MustParse(testOrg), crr.Name)]; ok {
		t.Fatalf("row not deleted")
	}
	got := &cv1alpha1.ConstellationResponseRule{}
	if err := c.Get(context.Background(), req.NamespacedName, got); err == nil {
		t.Fatalf("object still present, finalizer not released")
	}
}
