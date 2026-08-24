import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Network map shows live flow telemetry and edge drill-down", async ({ page }) => {
  await page.route("**/api/v1/network/map**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        summary: { window_hours: 24, workloads: 2, flows: 1 },
        workloads: [
          { id: "default/frontend", namespace: "default", name: "frontend", kind: "Deployment", risk_score: 71, finding_count: 9 },
          { id: "default/api-service", namespace: "default", name: "api-service", kind: "Deployment", risk_score: 92, finding_count: 14 },
        ],
        flows: [
          {
            id: "flow-1",
            src: "default/frontend",
            dst: "default/api-service",
            src_addr: "10.42.0.10",
            dst_addr: "10.42.0.21",
            src_port: 41010,
            protocol: "TCP",
            l7_protocol: "GRPC",
            dst_port: 8443,
            verdict: "allow",
            state: "ok",
            traffic_scope: "internal",
            bytes: 19700000,
            packets: 31400,
            samples: 2,
            last_seen_at: new Date().toISOString(),
          },
        ],
        recent_flows: [
          {
            id: "sample-1",
            flow_id: "flow-1",
            src: "default/frontend",
            dst: "default/api-service",
            src_addr: "10.42.0.10",
            dst_addr: "10.42.0.21",
            src_port: 41010,
            protocol: "TCP",
            l7_protocol: "GRPC",
            dst_port: 8443,
            verdict: "allow",
            state: "ok",
            traffic_scope: "internal",
            bytes: 19700000,
            packets: 31400,
            observed_at: new Date().toISOString(),
          },
        ],
      }),
    });
  });
  await page.goto("/network");
  await expect(page.getByRole("heading", { name: /Network Activity/i })).toBeVisible();
  await expect(page.getByTestId("network-map")).toBeVisible();
  const firstEdge = page.locator(".react-flow__edge").first();
  await expect(firstEdge).toBeVisible({ timeout: 10_000 });
  await firstEdge.click({ force: true });
  await expect(page.getByTestId("network-flow-inspector")).toBeVisible();
  await expect(page.getByTestId("network-flow-inspector-title")).toContainText("frontend");
  await page.getByTestId("network-flow-inspector-tab-policy").click();
  await expect(page.getByTestId("network-policy-tab")).toContainText("Generated policy for");
});

test("Network policy lifecycle shows preview, diff, and action previews", async ({ page }) => {
  let lifecyclePhase: "pending" | "approved" | "applied" | "rolledback" = "pending";
  let sawApproveHash = false;
  let sawApplyHash = false;
  await page.route("**/api/v1/network/map**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        summary: { window_hours: 24, workloads: 2, flows: 1 },
        workloads: [
          { id: "default/frontend", namespace: "default", name: "frontend", kind: "Deployment", risk_score: 71, finding_count: 9 },
          { id: "default/api-service", namespace: "default", name: "api-service", kind: "Deployment", risk_score: 92, finding_count: 14 },
        ],
        flows: [
          {
            id: "flow-1",
            src: "default/frontend",
            dst: "default/api-service",
            protocol: "TCP",
            l7_protocol: "GRPC",
            dst_port: 8443,
            verdict: "allow",
            state: "ok",
            bytes: 19700000,
            packets: 31400,
            samples: 2,
            last_seen_at: new Date().toISOString(),
          },
        ],
        recent_flows: [
          {
            id: "sample-1",
            flow_id: "flow-1",
            src: "default/frontend",
            dst: "default/api-service",
            protocol: "TCP",
            l7_protocol: "GRPC",
            dst_port: 8443,
            verdict: "allow",
            state: "ok",
            bytes: 19700000,
            packets: 31400,
            observed_at: new Date().toISOString(),
          },
        ],
      }),
    });
  });
  await page.route("**/api/v1/network/policies/lifecycle**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        summary: { total: 2, ready: lifecyclePhase === "pending" || lifecyclePhase === "approved" ? 1 : 0, discover: lifecyclePhase === "pending" || lifecyclePhase === "rolledback" ? 1 : 0, monitor: lifecyclePhase === "applied" ? 2 : 1, protect: 0, rollback_ready: lifecyclePhase === "applied" ? 1 : 0, pending_approval: lifecyclePhase === "pending" ? 1 : 0 },
        items: [
          {
            id: "default/frontend",
            workload: "default/frontend",
            namespace: "default",
            current_mode: lifecyclePhase === "applied" ? "monitor" : "discover",
            target_mode: lifecyclePhase === "pending" || lifecyclePhase === "approved" ? "monitor" : undefined,
            reason: lifecyclePhase === "applied" ? "applied monitor policy bundle" : lifecyclePhase === "rolledback" ? "rolled back to discover from monitor" : lifecyclePhase === "approved" ? "approved for monitor; awaiting apply" : "stable for 24h + sufficient traffic observed",
            auto_applied: false,
            evaluated_at: new Date().toISOString(),
            candidate_hash: "candidate-frontend-v1",
            approved_candidate_hash: lifecyclePhase === "pending" ? undefined : "candidate-frontend-v1",
            candidate_stale: false,
            approval_status: lifecyclePhase === "applied" ? "applied" : lifecyclePhase === "rolledback" ? "rolled_back" : lifecyclePhase === "approved" ? "approved" : "pending",
            rollback_available: lifecyclePhase === "applied",
            rollback_ref: lifecyclePhase === "applied" ? "rollback-frontend-monitor" : undefined,
            summary: { total_flows: 5, unique_peers: 2, unique_port_protocol: 2, out_of_policy_alerts: 0, new_tuples_last_24h: 0, first_observation: new Date().toISOString(), last_observation: new Date().toISOString() },
            tuple_preview: [
              { direction: "egress", peer: "default/api-service", protocol: "TCP", port: 8443, l7_protocol: "grpc", verdict: "allow", samples: 5, bytes: 12000, packets: 80, first_seen_at: new Date().toISOString(), last_seen_at: new Date().toISOString(), included: true },
              { direction: "egress", peer: "external/new.example", protocol: "TCP", port: 443, l7_protocol: "http", verdict: "alert", samples: 1, bytes: 600, packets: 4, first_seen_at: new Date().toISOString(), last_seen_at: new Date().toISOString(), included: false, exclude_reason: "held: alert verdict" },
            ],
            preview: { engine: "cilium", yaml: "kind: CiliumNetworkPolicy\nmetadata:\n  name: frontend-cilium", refs: { cilium: "frontend-cilium" } },
            diff: { summary: "Adds stable frontend egress rules.", added: ["egress tcp/8443 to default/api-service"], removed: [], changed: ["policy mode discover -> monitor"] },
            audit_trail: lifecyclePhase === "pending" ? [] : [
              { at: new Date().toISOString(), actor: "test-user", action: "approve", message: "approved for monitor; awaiting apply", idempotency_key: "network-policy:default/frontend:approve:test" },
              ...(lifecyclePhase === "applied" || lifecyclePhase === "rolledback" ? [{ at: new Date().toISOString(), actor: "test-user", action: "apply", message: "applied monitor policy bundle", idempotency_key: "network-policy:default/frontend:apply:test" }] : []),
              ...(lifecyclePhase === "rolledback" ? [{ at: new Date().toISOString(), actor: "test-user", action: "rollback", message: "rolled back to discover from monitor", idempotency_key: "network-policy:default/frontend:rollback:test" }] : []),
            ],
          },
          {
            id: "default/api-service",
            workload: "default/api-service",
            namespace: "default",
            current_mode: "monitor",
            reason: "hold in monitor",
            auto_applied: false,
            evaluated_at: new Date().toISOString(),
            candidate_hash: "candidate-api-v1",
            candidate_stale: false,
            approval_status: "blocked",
            rollback_available: false,
            summary: { total_flows: 3, unique_peers: 1, unique_port_protocol: 1, out_of_policy_alerts: 1, new_tuples_last_24h: 1, first_observation: new Date().toISOString(), last_observation: new Date().toISOString() },
            tuple_preview: [
              { direction: "ingress", peer: "default/frontend", protocol: "TCP", port: 8443, l7_protocol: "grpc", verdict: "allow", samples: 3, bytes: 9000, packets: 50, first_seen_at: new Date().toISOString(), last_seen_at: new Date().toISOString(), included: true },
            ],
            preview: { engine: "cilium", yaml: "kind: CiliumNetworkPolicy\nmetadata:\n  name: api-service-cilium", refs: { cilium: "api-service-cilium" } },
            diff: { summary: "No change while alerts are active.", added: [], removed: [], changed: [] },
            audit_trail: [],
          },
        ],
      }),
    });
  });
  await page.route("**/api/v1/network/policies/**/rollback**", async (route) => {
    lifecyclePhase = "rolledback";
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ action: "rollback", action_id: "action-3", persists: true, applies_live: false, next_mode: "discover", rollback_ref: "rollback-frontend-monitor", rollback_refs: {} }) });
  });
  await page.route("**/api/v1/network/policies/**/apply**", async (route) => {
    sawApplyHash = (await route.request().postDataJSON()).candidate_hash === "candidate-frontend-v1";
    lifecyclePhase = "applied";
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ action: "apply", action_id: "action-2", persists: true, applies_live: false, next_mode: "monitor", rollback_ref: "rollback-frontend-monitor", rollback_refs: {} }) });
  });
  await page.route("**/api/v1/network/policies/**/approve**", async (route) => {
    sawApproveHash = (await route.request().postDataJSON()).candidate_hash === "candidate-frontend-v1";
    lifecyclePhase = "approved";
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ action: "approve", action_id: "action-1", persists: true, applies_live: false, next_mode: "monitor", rollback_refs: {} }) });
  });

  await page.goto("/network");
  const frontendNode = page.locator(".react-flow__node").filter({ hasText: "frontend" }).first();
  await expect(frontendNode).toBeVisible({ timeout: 10_000 });
  await frontendNode.click();
  await expect(page.getByTestId("network-policy-lifecycle")).toBeVisible();
  await expect(page.getByTestId("network-policy-lifecycle").getByTestId("network-policy-mode").filter({ hasText: "discover" }).first()).toBeVisible();
  await expect(page.getByText("stable for 24h + sufficient traffic observed")).toBeVisible();
  await expect(page.getByTestId("network-policy-preview")).toContainText("kind: CiliumNetworkPolicy");
  await expect(page.getByTestId("network-policy-diff")).toContainText("Adds stable frontend egress rules");
  await expect(page.getByTestId("network-policy-lifecycle")).toContainText("candidate-fr");
  await expect(page.getByTestId("network-policy-included-tuple").first()).toContainText("grpc TCP/8443");
  await expect(page.getByTestId("network-policy-held-tuple").first()).toContainText("held: alert verdict");
  await page.getByTestId("network-policy-approve").click();
  await expect.poll(() => sawApproveHash).toBeTruthy();
  await expect(page.getByTestId("network-policy-lifecycle")).toContainText("approved for monitor; awaiting apply");
  await expect(page.getByTestId("network-policy-dry-run-badge")).toContainText("state persisted");
  await expect(page.getByTestId("network-policy-action-state")).toContainText("retry key");
  await expect(page.getByTestId("network-policy-audit-trail")).toContainText("approve");
  await expect(page.getByTestId("network-policy-approve")).toHaveCount(0);
  await page.getByTestId("network-policy-apply").click();
  await expect.poll(() => sawApplyHash).toBeTruthy();
  await expect(page.getByTestId("network-policy-lifecycle")).toContainText("applied monitor policy bundle");
  await expect(page.getByTestId("network-policy-rollback-status")).toContainText("Rollback ready");
  await expect(page.getByTestId("network-policy-rollback-card")).toBeVisible();
  await expect(page.getByTestId("network-policy-rollback-ref")).toContainText("rollback-frontend-monitor");
  await page.getByTestId("network-policy-rollback-preview-toggle").click();
  await expect(page.getByTestId("network-policy-rollback-preview")).toContainText("kind: CiliumNetworkPolicy");
  await expect(page.getByTestId("network-policy-rollback-diff")).toContainText("Restores the previous policy bundle");
  await expect(page.getByTestId("network-policy-audit-trail")).toContainText("apply");
  await page.getByTestId("network-policy-rollback-reason").fill("undo test promotion");
  await page.getByTestId("network-policy-rollback").click();
  await expect(page.getByTestId("network-policy-lifecycle")).toContainText("rolled back to discover from monitor");
  await expect(page.getByTestId("network-policy-audit-trail")).toContainText("rollback");
  await expect(page.getByTestId("network-policy-rollback-status")).toHaveCount(0);
});

test("Network filters, refresh, live stream, and workload flow tabs are wired", async ({ page }) => {
  let sawFilteredRequest = false;
  await page.route("**/api/v1/network/map**", async (route) => {
    const url = new URL(route.request().url());
    if (url.searchParams.get("hours") === "1" && url.searchParams.get("cluster_id") && url.searchParams.get("namespace") === "default" && url.searchParams.get("verdict") === "block") {
      sawFilteredRequest = true;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        summary: {
          window_hours: Number(url.searchParams.get("hours") || 24),
          selected_cluster_id: url.searchParams.get("cluster_id") || "cluster-dev",
          clusters: [
            { id: "cluster-dev", name: "dev-west", state: "connected" },
            { id: "cluster-prod", name: "prod-east", state: "connected" },
          ],
          workloads: 2,
          flows: 2,
          recent_flows: 2,
          total_bytes: 19818000,
          total_packets: 31540,
          allowed: 1,
          alerted: 0,
          blocked: 1,
        },
        workloads: [
          { id: "default/frontend", cluster_id: "cluster-prod", cluster_name: "prod-east", namespace: "default", name: "frontend", kind: "Deployment", risk_score: 71, finding_count: 9 },
          { id: "default/api-service", cluster_id: "cluster-prod", cluster_name: "prod-east", namespace: "default", name: "api-service", kind: "Deployment", risk_score: 92, finding_count: 14 },
        ],
        flows: [
          {
            id: "flow-1",
            src: "default/frontend",
            dst: "default/api-service",
            protocol: "TCP",
            l7_protocol: "GRPC",
            dst_port: 8443,
            verdict: "allow",
            state: "ok",
            bytes: 19700000,
            packets: 31400,
            samples: 2,
            last_seen_at: new Date().toISOString(),
          },
          {
            id: "flow-blocked",
            src: "default/frontend",
            dst: "external/tracker.example",
            protocol: "TCP",
            l7_protocol: "HTTP",
            dst_port: 443,
            verdict: "block",
            state: "denied",
            bytes: 118000,
            packets: 140,
            samples: 1,
            last_seen_at: new Date().toISOString(),
          },
        ],
        recent_flows: [
          {
            id: "sample-1",
            flow_id: "flow-1",
            src: "default/frontend",
            dst: "default/api-service",
            protocol: "TCP",
            l7_protocol: "GRPC",
            dst_port: 8443,
            verdict: "allow",
            state: "ok",
            bytes: 19700000,
            packets: 31400,
            observed_at: new Date().toISOString(),
          },
          {
            id: "sample-2",
            flow_id: "flow-blocked",
            src: "default/frontend",
            dst: "external/tracker.example",
            protocol: "TCP",
            l7_protocol: "HTTP",
            dst_port: 443,
            verdict: "block",
            state: "denied",
            bytes: 118000,
            packets: 140,
            observed_at: new Date().toISOString(),
          },
        ],
      }),
    });
  });
  await page.route("**/api/v1/network/policies/lifecycle**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ summary: { total: 0, ready: 0, discover: 0, monitor: 0, protect: 0, rollback_ready: 0, pending_approval: 0 }, items: [] }),
    });
  });

  await page.goto("/network");
  await page.getByTestId("network-window-select").selectOption("1");
  await page.getByTestId("network-namespace-select").selectOption("default");
  await page.getByTestId("network-verdict-select").selectOption("block");
  await expect.poll(() => sawFilteredRequest).toBeTruthy();
  await expect(page).toHaveURL(/hours=1/);
  await expect(page).toHaveURL(/namespace=default/);
  await expect(page).toHaveURL(/verdict=block/);

  await expect(page.getByTestId("network-last-updated")).toBeVisible();
  await page.getByRole("button", { name: "Pause" }).click();
  await expect(page.getByRole("button", { name: "Resume" })).toBeVisible();
  await page.getByRole("button", { name: "Refresh" }).click();

  await page.locator(".react-flow__node").filter({ hasText: "frontend" }).first().click();
  await expect(page.getByTestId("network-workload-detail")).toContainText("frontend");
  await page.getByTestId("network-workload-egress-tab").click();
  await expect(page.getByTestId("network-related-flow-row")).toHaveCount(2);
  await page.getByTestId("network-workload-ingress-tab").click();
  await expect(page.getByText("No observed traffic in this direction")).toBeVisible();
});
