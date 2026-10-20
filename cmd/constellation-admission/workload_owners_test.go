package main

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestWorkloadOwnerResolverVerifiesUIDAndNamespace(t *testing.T) {
	yes := true
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api-hash", UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "api", UID: "deployment-uid", Controller: &yes}}}}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "backup-123", UID: "job-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "CronJob", Name: "backup", UID: "cron-uid", Controller: &yes}}}}
	r := &workloadOwnerResolver{client: fake.NewSimpleClientset(rs, job)}
	for _, tc := range []struct {
		namespace string
		owner     metav1.OwnerReference
		want      string
		fail      bool
	}{
		{"payments", metav1.OwnerReference{Kind: "ReplicaSet", Name: "api-hash", UID: "rs-uid"}, "api", false},
		{"payments", metav1.OwnerReference{Kind: "Job", Name: "backup-123", UID: "job-uid"}, "backup", false},
		{"other", metav1.OwnerReference{Kind: "ReplicaSet", Name: "api-hash", UID: "rs-uid"}, "", true},
		{"payments", metav1.OwnerReference{Kind: "ReplicaSet", Name: "api-hash", UID: "reused-name"}, "", true},
		{"payments", metav1.OwnerReference{Kind: "ReplicaSet", Name: "api-hash"}, "", true},
	} {
		got, err := r.Parent(t.Context(), tc.namespace, tc.owner)
		if tc.fail {
			if err == nil {
				t.Fatal("unverified owner accepted")
			}
			continue
		}
		if err != nil || got == nil || got.Name != tc.want {
			t.Fatalf("owner=%v err=%v", got, err)
		}
	}
}
