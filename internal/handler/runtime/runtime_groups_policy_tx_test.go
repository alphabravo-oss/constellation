//go:build integration

package runtime

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

func auditedEdgeFixture(t *testing.T) (reviewedPolicyFixture, *GroupEdgeStore, netpolicy.GroupEdge) {
	t.Helper()
	f := reviewedFixture(t)
	for _, g := range []struct{ name, members string }{{"front", `["app/front"]`}, {"back", `["app/back"]`}} {
		if _, err := f.h.store.db.Pool().Exec(t.Context(), `INSERT INTO groups(org_id,cluster_id,name,kind,members)VALUES($1,$2,$3,'ground',$4::jsonb)`, f.org, f.cluster, g.name, g.members); err != nil {
			t.Fatal(err)
		}
	}
	edge := netpolicy.GroupEdge{FromGroup: "front", ToGroup: "back", Mode: "protect", Ports: []netpolicy.PortSpec{{Protocol: "TCP", Port: 443}}}
	return f, NewGroupEdgeStore(f.h.store.db, f.h.store), edge
}

func edgePolicySnapshot(t *testing.T, f reviewedPolicyFixture) string {
	t.Helper()
	var snapshot string
	if err := f.h.store.db.Pool().QueryRow(t.Context(), `SELECT jsonb_build_object(
 'policies',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.id) FROM runtime_policies p WHERE org_id=$1),
 'edges',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id) FROM group_rule_edges e WHERE org_id=$1),
 'groups',(SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM groups g WHERE org_id=$1),
 'baselines',(SELECT jsonb_agg(to_jsonb(b) ORDER BY b.id) FROM process_baseline_states b WHERE org_id=$1))::text`, f.org).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestEdgePolicyAuditFailureRollsBackCreationExpansionRetractionAndEdit(t *testing.T) {
	f, store, edge := auditedEdgeFixture(t)
	row, result, err := store.UpsertAndExpand(t.Context(), f.org, f.cluster, edge, &f.actor)
	if err != nil || len(result.Policies) != 2 {
		t.Fatalf("initial edge expansion %+v %v", result, err)
	}
	edge.ID = row.ID.String()
	before := edgePolicySnapshot(t, f)
	rejectLegacyPolicyAudit(t, f)
	operations := map[string]func() error{
		"expand existing": func() error { _, err := store.Expand(t.Context(), f.org, f.cluster, edge, &f.actor); return err },
		"delete existing": func() error { return store.deleteEdgeWithActor(t.Context(), f.org, row.ID, &f.actor) },
		"edit expanded": func() error {
			changed := edge
			changed.Ports = []netpolicy.PortSpec{{Protocol: "TCP", Port: 8443}}
			_, err := store.Upsert(t.Context(), f.org, f.cluster, changed, &f.actor)
			return err
		},
		"create and expand": func() error {
			changed := edge
			changed.ID = ""
			changed.FromGroup = "back"
			changed.ToGroup = "front"
			_, _, err := store.UpsertAndExpand(t.Context(), f.org, f.cluster, changed, &f.actor)
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			if err := operation(); err == nil {
				t.Fatal("audit failure was ignored")
			}
			if after := edgePolicySnapshot(t, f); after != before {
				t.Fatalf("audit failure changed edge/policy/profile state\nbefore%s\nafter%s", before, after)
			}
		})
	}
}

func TestEdgePolicyAuditUsesFinalMarkedRowExactlyOnce(t *testing.T) {
	f, store, edge := auditedEdgeFixture(t)
	row, result, err := store.UpsertAndExpand(t.Context(), f.org, f.cluster, edge, &f.actor)
	if err != nil || len(result.Policies) != 2 {
		t.Fatalf("expand %+v %v", result, err)
	}
	assertFinalEdgePolicyAudits(t, f, audit.ActionPolicyCreate, 2)
	edge.ID = row.ID.String()
	if _, err := store.Expand(t.Context(), f.org, f.cluster, edge, &f.actor); err != nil {
		t.Fatal(err)
	}
	assertFinalEdgePolicyAudits(t, f, audit.ActionPolicyUpdate, 2)
	if err := store.deleteEdgeWithActor(t.Context(), f.org, row.ID, &f.actor); err != nil {
		t.Fatal(err)
	}
	var creates, updates, deletes int
	if err := store.db.Pool().QueryRow(t.Context(), `SELECT count(*) FILTER(WHERE action=$2),count(*) FILTER(WHERE action=$3),count(*) FILTER(WHERE action=$4) FROM audit_events WHERE org_id=$1`, f.org, audit.ActionPolicyCreate, audit.ActionPolicyUpdate, audit.ActionPolicyDelete).Scan(&creates, &updates, &deletes); err != nil || creates != 2 || updates != 2 || deletes != 2 {
		t.Fatalf("duplicate or missing audits %d/%d/%d %v", creates, updates, deletes, err)
	}
	var wrongActors int
	if err := store.db.Pool().QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND actor_id IS DISTINCT FROM $2`, f.org, f.actor).Scan(&wrongActors); err != nil || wrongActors != 0 {
		t.Fatalf("wrong policy actor%d %v", wrongActors, err)
	}
}

func assertFinalEdgePolicyAudits(t *testing.T, f reviewedPolicyFixture, action string, want int) {
	t.Helper()
	var matches int
	if err := f.h.store.db.Pool().QueryRow(t.Context(), `SELECT count(*) FROM audit_events a JOIN runtime_policies p ON a.org_id=p.org_id AND a.target_id=p.id::text
 WHERE a.org_id=$1 AND a.action=$2 AND a.after->>'revision'=p.version::text AND (a.after->>'rule_count')::int=jsonb_array_length(p.rules)
 AND p.mode='enforce' AND p.def_action=7 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p.rules)r WHERE r->>'edge_id' IS NULL)`, f.org, action).Scan(&matches); err != nil || matches != want {
		t.Fatalf("audit did not reflect final marked protect policy matches%d want%d %v", matches, want, err)
	}
}

func rejectLearnedCreateAudit(t *testing.T, f reviewedPolicyFixture) {
	t.Helper()
	function := pgx.Identifier{"reject_learned_" + uuid.NewString()}.Sanitize()
	trigger := pgx.Identifier{"reject_learned_" + uuid.NewString()}.Sanitize()
	pool := f.h.store.db.Pool()
	sql := fmt.Sprintf(`CREATE FUNCTION %s()RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.org_id='%s'::uuid AND NEW.action='%s' THEN RAISE EXCEPTION 'fixture learned create audit rejected'; END IF; RETURN NEW; END $$`, function, f.org, audit.ActionPolicyCreate)
	if _, err := pool.Exec(t.Context(), sql); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `CREATE TRIGGER `+trigger+` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION `+function+`() `); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, sql := range []string{`DROP TRIGGER IF EXISTS ` + trigger + ` ON audit_events`, `DROP FUNCTION IF EXISTS ` + function + `() `} {
			if _, err := pool.Exec(context.Background(), sql); err != nil {
				t.Error(err)
			}
		}
	})
}

func TestMembershipAuditFailureRollsBackRetractionProfileAndNewExpansion(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	org, cluster, group, _, reconciler := membershipEdgeFixture(t, d)
	reconciler.edges.pol.auditLog = audit.New(d.Pool())
	f := reviewedPolicyFixture{h: &RuntimePoliciesHTTP{store: reconciler.edges.pol}, org: org, cluster: cluster}
	before := edgePolicySnapshot(t, f)
	rejectLearnedCreateAudit(t, f)
	if _, changed, err := reconciler.reconcileMembership(t.Context(), org, group, membershipGuardWorkloads(cluster)); err == nil || changed {
		t.Fatalf("audit failed membership claimed success %v %v", changed, err)
	}
	if after := edgePolicySnapshot(t, f); after != before {
		t.Fatalf("membership failure changed policies/profile/members\nbefore%s\nafter%s", before, after)
	}
	var audits int
	if err := d.Pool().QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE org_id=$1`, org).Scan(&audits); err != nil || audits != 0 {
		t.Fatalf("rolled-back membership left deletion audit%d %v", audits, err)
	}
}

func TestEdgeExpansionRejectsAuthoredPolicyCreatedAfterOwnershipPrecheck(t *testing.T) {
	f, store, edge := auditedEdgeFixture(t)
	tx, err := store.db.Pool().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	name := edgePolicyName(edge)
	var authoredID uuid.UUID
	if err := tx.QueryRow(t.Context(), `INSERT INTO runtime_policies(org_id,cluster_id,workload,namespace,name,mode,rules)VALUES($1,$2,'app/front','app',$3,'enforce','[{"cfg":"user","port":1234,"proto":6,"action":7}]')RETURNING id`, f.org, f.cluster, name).Scan(&authoredID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, _, err := store.UpsertAndExpand(t.Context(), f.org, f.cluster, edge, &f.actor)
		result <- err
	}()
	awaitLearnedDatabaseLock(t, f, result, "%ON CONFLICT(org_id,cluster_id,workload,name) DO NOTHING%")
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, errEdgePolicyOwnership) {
		t.Fatalf("concurrent authored collision was not rejected: %v", err)
	}
	authored, err := store.pol.Get(t.Context(), f.org, authoredID)
	if err != nil {
		t.Fatal(err)
	}
	assertLearnedPorts(t, authored, map[uint16]netpolicy.CfgType{1234: netpolicy.CfgTypeUser})
	var edges, audits int
	if err := store.db.Pool().QueryRow(t.Context(), `SELECT (SELECT count(*) FROM group_rule_edges WHERE org_id=$1),(SELECT count(*) FROM audit_events WHERE org_id=$1)`, f.org).Scan(&edges, &audits); err != nil || edges != 0 || audits != 0 {
		t.Fatalf("rejected collision left edge/audit side effects %d/%d %v", edges, audits, err)
	}
}
