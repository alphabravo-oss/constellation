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

test("Network lifecycle evidence opens scoped dedicated review forms and Cancel preserves context", async ({ page }) => {
  let phase: "pending" | "approved" | "applied" = "pending";
  let writes = 0;
  const policy = (clusterId: string) => ({
    id: "default/frontend", cluster_id: clusterId, workload: "default/frontend", namespace: "default",
    current_mode: phase === "applied" ? "monitor" : "discover",
    target_mode: phase === "applied" ? undefined : "monitor",
    candidate_hash: "candidate-frontend-v1", approved_candidate_hash: phase === "pending" ? undefined : "candidate-frontend-v1",
    candidate_stale: false, approval_status: phase === "pending" ? "pending" : phase === "approved" ? "approved" : "applied",
    rollback_available: phase === "applied", rollback_ref: phase === "applied" ? "rollback-frontend-monitor" : undefined,
    reason: "Seven-day observed policy candidate", auto_applied: false, evaluated_at: new Date().toISOString(),
    summary: { total_flows: 5, unique_peers: 2, unique_port_protocol: 2, out_of_policy_alerts: 0, new_tuples_last_24h: 0, first_observation: new Date().toISOString(), last_observation: new Date().toISOString() },
    tuple_preview: [
      { direction: "egress", peer: "default/api-service", protocol: "TCP", port: 8443, l7_protocol: "grpc", verdict: "allow", samples: 5, bytes: 12000, packets: 80, first_seen_at: new Date().toISOString(), last_seen_at: new Date().toISOString(), included: true },
      { direction: "egress", peer: "external/new.example", protocol: "TCP", port: 443, verdict: "alert", samples: 1, bytes: 600, packets: 4, first_seen_at: new Date().toISOString(), last_seen_at: new Date().toISOString(), included: false, exclude_reason: "held: alert verdict" },
    ],
    preview: { engine: "cilium", yaml: "kind: CiliumNetworkPolicy\nmetadata:\n  name: frontend-cilium", manifests: {}, refs: { cilium: "frontend-cilium" } },
    diff: { summary: "Adds stable frontend egress rules.", added: ["egress tcp/8443 to default/api-service"], removed: [], changed: [] },
    audit_trail: [],
  });
  await page.route("**/api/v1/network/map**", async route => {
    const clusterId = new URL(route.request().url()).searchParams.get("cluster_id")!;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
      summary: { selected_cluster_id: clusterId, window_hours: 168, workloads: 1, flows: 0, cni: "cilium" },
      workloads: [{ id: "default/frontend", cluster_id: clusterId, namespace: "default", name: "frontend", kind: "Deployment", risk_score: 71, finding_count: 9 }], flows: [], recent_flows: [],
    }) });
  });
  await page.route("**/api/v1/network/policies/lifecycle**", async route => {
    const clusterId = new URL(route.request().url()).searchParams.get("cluster_id")!;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
      summary: { selected_cluster_id: clusterId, total: 1, ready: 1, discover: phase === "applied" ? 0 : 1, monitor: phase === "applied" ? 1 : 0, protect: 0, rollback_ready: phase === "applied" ? 1 : 0, pending_approval: phase === "pending" ? 1 : 0 }, items: [policy(clusterId)],
    }) });
  });
  await page.route("**/api/v1/network/policies/**", async route => {
    if (route.request().method() === "GET") return route.fallback();
    writes += 1;
    await route.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ error: "This read-only workflow must not write" }) });
  });
  await page.goto("/network?tab=rules&workload=default%2Ffrontend&hours=168&hide_platform=false");
  await expect(page.getByTestId("network-lifecycle-table")).toBeVisible();
  await expect(page.getByTestId("network-policy-lifecycle")).toContainText("Seven-day observed policy candidate");
  await page.getByText("Advanced: candidate and observed tuples", { exact: true }).click();
  await expect(page.getByTestId("network-policy-tuple-preview")).toContainText("grpc TCP/8443");
  await expect(page.getByTestId("network-policy-tuple-preview")).toContainText("held: alert verdict");
  await page.getByText("Advanced: current manifest and differences", { exact: true }).click();
  await expect(page.getByTestId("network-policy-preview")).toContainText("kind: CiliumNetworkPolicy");
  await expect(page.getByTestId("network-policy-lifecycle")).toContainText("Adds stable frontend egress rules");
  const returnContext = async () => {
    await page.getByRole("link", { name: "Cancel", exact: true }).click();
    await expect(page.getByTestId("network-lifecycle-table")).toBeVisible();
    const search = new URL(page.url()).searchParams;
    expect(search.get("tab")).toBe("rules"); expect(search.get("workload")).toBe("default/frontend"); expect(search.get("hours")).toBe("168");
  };
  await page.getByTestId("network-policy-approve").click();
  await expect(page.getByRole("heading", { name: "Approve observed network policy", exact: true })).toBeVisible();
  await expect(page.locator("#network-action-reason")).toBeVisible();
  await expect(page.getByTestId("network-action-policy-preview")).toContainText("frontend-cilium");
  phase = "approved";
  await returnContext();
  await page.getByTestId("network-policy-apply").click();
  await expect(page.getByRole("heading", { name: "Apply reviewed network policy", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Apply policy", exact: true })).toBeDisabled();
  phase = "applied";
  await returnContext();
  await page.getByTestId("network-policy-rollback").click();
  await expect(page.getByRole("heading", { name: "Roll back network policy", exact: true })).toBeVisible();
  await expect(page.getByText(/Historical bundle contents|historical bundle contents/)).toBeVisible();
  await expect(page.getByText(/rollback-frontend-monitor/).first()).toBeVisible();
  await returnContext();
  expect(writes).toBe(0);
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
