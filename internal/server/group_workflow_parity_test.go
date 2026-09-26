package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestGroupWorkflowUsagePromotionAndUnsafeDelete(t *testing.T) {
	_, server, pool, signer, adminID, auditorID, orgID := newSysConfigTestServer(t)
	ctx := context.Background()
	admin := issueFor(t, signer, adminID, orgID, 0)
	auditor := issueFor(t, signer, auditorID, orgID, 0)
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, $3, 'connected')`,
		clusterID, orgID, "group-workflow-"+clusterID.String()); err != nil {
		t.Fatalf("create cluster: %v", err)
	}

	baseURL := server.URL + "/api/v1"
	groupName := "nv.workflow-" + uuid.NewString()[:8]
	peerName := "nv.peer-" + uuid.NewString()[:8]
	createGroup := func(name, mode string) string {
		t.Helper()
		status, body := doJSON(t, http.MethodPost, baseURL+"/groups?cluster_id="+clusterID.String(), admin,
			map[string]any{"name": name, "kind": "ground", "policy_mode": mode, "profile_mode": "monitor"})
		if status != http.StatusCreated {
			t.Fatalf("create group %s: status=%d body=%+v", name, status, body)
		}
		id, _ := body["id"].(string)
		if _, err := uuid.Parse(id); err != nil {
			t.Fatalf("create group %s returned invalid id %q: %v", name, id, err)
		}
		return id
	}
	groupID := createGroup(groupName, "discover")
	createGroup(peerName, "monitor")
	groupURL := baseURL + "/groups/" + groupID

	if status, body := doJSON(t, http.MethodPost, baseURL+"/groups?cluster_id="+clusterID.String(), auditor,
		map[string]any{"name": "forbidden", "kind": "ground"}); status != http.StatusForbidden {
		t.Fatalf("auditor create: status=%d body=%+v, want 403", status, body)
	}

	export := "network_rules:\n" +
		"  - id: 1001\n" +
		"    comment: workflow binding\n" +
		"    from: " + groupName + "\n" +
		"    to: " + peerName + "\n" +
		"    ports: tcp/5432\n" +
		"    action: allow\n" +
		"dlp_groups:\n" +
		"  - name: " + groupName + "\n" +
		"    status: true\n" +
		"    sensors:\n" +
		"      - name: pii-sensor\n" +
		"        action: deny\n" +
		"waf_groups:\n" +
		"  - name: " + groupName + "\n" +
		"    status: true\n" +
		"    sensors:\n" +
		"      - name: waf-sensor\n" +
		"        action: alert\n"
	previewURL := baseURL + "/migration/preview"
	previewRequest := map[string]any{"source": "neuvector", "cluster_id": clusterID.String(), "export": export}
	if status, body := doJSON(t, http.MethodPost, previewURL, auditor, previewRequest); status != http.StatusForbidden {
		t.Fatalf("auditor migration preview: status=%d body=%+v, want 403", status, body)
	}
	status, preview := doJSON(t, http.MethodPost, previewURL, admin, previewRequest)
	if status != http.StatusOK {
		t.Fatalf("migration preview: status=%d body=%+v", status, preview)
	}
	importID, _ := preview["import_id"].(string)
	if _, err := uuid.Parse(importID); err != nil {
		t.Fatalf("migration preview returned invalid import id %q: %v", importID, err)
	}
	summary, ok := preview["summary"].(map[string]any)
	if !ok || summary["network_rules"] != float64(1) || summary["dpi_bindings"] != float64(2) || summary["unsupported"] != float64(0) {
		t.Fatalf("migration preview omitted group references: %+v", preview)
	}
	applyURL := baseURL + "/migration/imports/" + importID + ":apply"
	if status, body := doJSON(t, http.MethodPost, applyURL, auditor, nil); status != http.StatusForbidden {
		t.Fatalf("auditor migration apply: status=%d body=%+v, want 403", status, body)
	}
	status, applied := doJSON(t, http.MethodPost, applyURL, admin, nil)
	if status != http.StatusOK || applied["status"] != "applied" {
		t.Fatalf("migration apply: status=%d body=%+v", status, applied)
	}
	appliedCounts, ok := applied["applied"].(map[string]any)
	if !ok || appliedCounts["network_rules"] != float64(1) || appliedCounts["dpi_bindings"] != float64(2) {
		t.Fatalf("migration apply omitted network/DPI bindings: %+v", applied)
	}

	usageURL := groupURL + "/usage?cluster_id=" + clusterID.String()
	for _, token := range []string{admin, auditor} {
		status, usage := doJSON(t, http.MethodGet, usageURL, token, nil)
		if status != http.StatusOK {
			t.Fatalf("group usage: status=%d body=%+v", status, usage)
		}
		summary, ok := usage["summary"].(map[string]any)
		if !ok || usage["group_id"] != groupID || summary["network_rules"] != float64(1) ||
			summary["dpi_sensor_bindings"] != float64(2) || summary["blocking_references"] != float64(3) ||
			summary["delete_blocked"] != true {
			t.Fatalf("network binding not reflected in usage: %+v", usage)
		}
		references, ok := usage["references"].([]any)
		if !ok || len(references) != 3 {
			t.Fatalf("unexpected usage references: %+v", usage)
		}
		seen := map[string]bool{}
		for _, item := range references {
			ref, ok := item.(map[string]any)
			if !ok || ref["blocking"] != true {
				t.Fatalf("non-blocking or malformed group reference: %+v", item)
			}
			kind, _ := ref["kind"].(string)
			seen[kind] = true
			if kind == "group-rule-edge" && (ref["family"] != "network" || ref["name"] != groupName+" -> "+peerName) {
				t.Fatalf("network rule reference mismatch: %+v", ref)
			}
		}
		if !seen["group-rule-edge"] || !seen["dlp-sensor-binding"] || !seen["waf-sensor-binding"] {
			t.Fatalf("network/DLP/WAF references missing: %+v", references)
		}
	}

	promoteURL := baseURL + "/groups:promote?cluster_id=" + clusterID.String()
	promotion := map[string]any{"dimension": "policy", "from": "discover", "to": "monitor"}
	if status, body := doJSON(t, http.MethodPost, promoteURL, auditor, promotion); status != http.StatusForbidden {
		t.Fatalf("auditor promote: status=%d body=%+v, want 403", status, body)
	}
	status, body := doJSON(t, http.MethodPost, promoteURL, admin, promotion)
	if status != http.StatusOK || body["changed"] != float64(1) || body["to"] != "monitor" {
		t.Fatalf("promote policy mode: status=%d body=%+v", status, body)
	}
	var policyMode string
	if err := pool.QueryRow(ctx, `SELECT policy_mode FROM groups WHERE id=$1 AND org_id=$2`, groupID, orgID).Scan(&policyMode); err != nil || policyMode != "monitor" {
		t.Fatalf("persisted policy mode=%q err=%v, want monitor", policyMode, err)
	}

	if status, body := doJSON(t, http.MethodDelete, groupURL, auditor, nil); status != http.StatusForbidden {
		t.Fatalf("auditor delete: status=%d body=%+v, want 403", status, body)
	}
	status, body = doJSON(t, http.MethodDelete, groupURL, admin, nil)
	if status != http.StatusConflict || body["error"] != "group has policy references" || body["blocking_references"] != float64(3) {
		t.Fatalf("unsafe delete: status=%d body=%+v, want blocking 409", status, body)
	}
	var groupCount, edgeCount, bindingCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE id=$1 AND org_id=$2`, groupID, orgID).Scan(&groupCount); err != nil || groupCount != 1 {
		t.Fatalf("group after denied delete: count=%d err=%v", groupCount, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE org_id=$1 AND cluster_id=$2 AND from_group=$3`,
		orgID, clusterID, groupName).Scan(&edgeCount); err != nil || edgeCount != 1 {
		t.Fatalf("network edge after denied delete: count=%d err=%v", edgeCount, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_dpi_sensor_bindings WHERE org_id=$1 AND group_id=$2`,
		orgID, groupID).Scan(&bindingCount); err != nil || bindingCount != 2 {
		t.Fatalf("DLP/WAF bindings after denied delete: count=%d err=%v", bindingCount, err)
	}

	for _, auditCase := range []struct {
		action string
		count  int
	}{
		{"group.create", 2},
		{"migration.import.apply", 1},
		{"group.mode.bulk", 1},
		{"group.delete", 0},
	} {
		status, history := doJSON(t, http.MethodGet, baseURL+"/audit/events?action="+auditCase.action, admin, nil)
		if status != http.StatusOK {
			t.Fatalf("audit %s: status=%d body=%+v", auditCase.action, status, history)
		}
		events, ok := history["events"].([]any)
		if !ok || len(events) != auditCase.count {
			t.Fatalf("audit %s: events=%+v, want %d", auditCase.action, history, auditCase.count)
		}
		createdGroupAudited := false
		for _, item := range events {
			event, ok := item.(map[string]any)
			if !ok || event["actor_id"] != adminID.String() || event["org_id"] != orgID.String() {
				t.Fatalf("audit %s actor/org mismatch: %+v", auditCase.action, item)
			}
			if auditCase.action == "group.create" && event["target_id"] == groupID {
				createdGroupAudited = true
			}
			if auditCase.action == "migration.import.apply" && event["target_id"] != importID {
				t.Fatalf("migration apply audit target mismatch: %+v", event)
			}
		}
		if auditCase.action == "group.create" && !createdGroupAudited {
			t.Fatalf("created group %s missing from audit: %+v", groupID, events)
		}
	}
}
