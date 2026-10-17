import { expect, type Page } from "@playwright/test";
import {
  ruleInventory,
  ruleRow,
} from "../../src/pages/network-rule-test-fixture";
import type {
  NetworkPolicyLifecycle,
  NetworkRuleInventoryParams,
} from "../../src/api/client";
import { notificationThreats } from "./network-inventory";

export const ruleCluster = "11111111-1111-4111-8111-111111111111";
export const ruleRoot = `/clusters/${ruleCluster}/network-rules`;
export const tailPair = {
  from: "custom-install/controller",
  to: "payments/api",
};
export function networkRuleFixture() {
  const rows = Array.from({ length: 5205 }, (_, index) =>
    ruleRow(index + 1, `team/app-${index + 1}`, {
      to: "payments/api",
      action: index % 2 ? "deny" : "allow",
    }),
  );
  rows[5204] = ruleRow(5205, tailPair.from, {
    to: tailPair.to,
    comment: "tail qualification marker",
    from_platform_role: "core",
  });
  const requests: URL[] = [],
    writes: Array<{
      from: string;
      to: string;
      comment: string;
      action: "allow" | "deny";
      disable: boolean;
      priority: number;
    }> = [];
  const policy: NetworkPolicyLifecycle = {
    id: "payments/api",
    cluster_id: ruleCluster,
    namespace: "payments",
    workload: "payments/api",
    platform_role: "",
    current_mode: "discover",
    target_mode: "monitor",
    approval_status: "pending",
    candidate_hash: "stable-candidate",
    candidate_stale: false,
    rollback_available: false,
    reason: "Returned retained tuple preview",
    auto_applied: false,
    evaluated_at: "2026-10-12T00:00:00Z",
    summary: {
      total_flows: 2,
      unique_peers: 2,
      unique_port_protocol: 1,
      out_of_policy_alerts: 0,
      new_tuples_last_24h: 0,
      first_observation: "2026-10-12T00:00:00Z",
      last_observation: "2026-10-12T00:00:00Z",
    },
    tuple_preview: ["custom-install/controller", "10.0.0.9"].map(
      (peer, index) => ({
        peer,
        peer_platform_role: index === 0 ? "core" : "",
        direction: "ingress",
        protocol: "TCP",
        port: 443,
        verdict: "allow",
        samples: 1,
        bytes: 10,
        packets: 1,
        first_seen_at: "2026-10-12T00:00:00Z",
        last_seen_at: "2026-10-12T00:00:00Z",
        included: true,
      }),
    ),
    preview: { engine: "cilium", yaml: "kind: NetworkPolicy", refs: {} },
    diff: {
      summary: "Returned source preview",
      added: [],
      removed: [],
      changed: [],
    },
    audit_trail: [],
  };
  const parse = (url: URL): NetworkRuleInventoryParams => ({
    q: url.searchParams.get("q") ?? "",
    from: url.searchParams.get("from") ?? "",
    to: url.searchParams.get("to") ?? "",
    action: url.searchParams.get("action") ?? "",
    status: url.searchParams.get("status") ?? "",
    cfg_type: url.searchParams.get("cfg_type") ?? "",
    hide_platform: url.searchParams.get("hide_platform") === "true",
    sort: url.searchParams.get("sort") ?? "evaluation",
    order: (url.searchParams.get("order") ?? "asc") as "asc" | "desc",
    limit: Number(url.searchParams.get("limit") ?? 100),
    offset: Number(url.searchParams.get("offset") ?? 0),
  });
  const quote = (value: unknown) => `"${String(value).replaceAll('"', '""')}"`;
  async function install(page: Page) {
    await page.route("**/api/v1/**", async (route) => {
      const request = route.request(),
        url = new URL(request.url()),
        path = url.pathname.replace(/^\/api\/v1/, ""),
        method = request.method();
      if (path === "/auth/me")
        return route.fulfill({
          json: {
            org_id: "org",
            user_id: "operator",
            email: "operator@example.test",
            roles: ["GlobalAdmin"],
          },
        });
      if (path === "/clusters")
        return route.fulfill({
          json: {
            clusters: [
              {
                id: ruleCluster,
                name: "Rule inventory fixture",
                state: "connected",
              },
            ],
          },
        });
      if (path === "/groups") return route.fulfill({ json: { groups: [] } });
      if (path === "/runtime-threats")
        return route.fulfill({
          json: url.searchParams.has("cluster_id")
            ? { threats: [] }
            : notificationThreats(url),
        });
      if (
        path === `/clusters/${ruleCluster}/network-rules/inventory` &&
        method === "GET"
      ) {
        requests.push(url);
        const params = parse(url);
        expect(params.limit).toBeGreaterThan(0);
        expect(params.limit).toBeLessThanOrEqual(500);
        expect(params.offset).toBeGreaterThanOrEqual(0);
        return route.fulfill({
          json: ruleInventory(ruleCluster, rows, params),
        });
      }
      if (
        path === `/clusters/${ruleCluster}/network-rules/inventory.csv` &&
        method === "GET"
      ) {
        requests.push(url);
        expect(url.searchParams.has("limit")).toBe(false);
        expect(url.searchParams.has("offset")).toBe(false);
        const data = ruleInventory(ruleCluster, rows, {
          ...parse(url),
          limit: rows.length,
          offset: 0,
        });
        const headers = [
          "row_id",
          "id",
          "cluster_id",
          "from",
          "to",
          "action",
          "from_platform_role",
          "to_platform_role",
        ];
        const body = [
          headers,
          ...data.rules.map((row) => [
            row.row_id,
            row.id,
            ruleCluster,
            row.from,
            row.to,
            row.action,
            row.from_platform_role,
            row.to_platform_role,
          ]),
        ]
          .map((row) => row.map(quote).join(","))
          .join("\n");
        return route.fulfill({
          contentType: "text/csv; charset=utf-8",
          headers: {
            "X-Export-Total": String(data.total),
            "X-Export-Limit": "100000",
            "X-Export-Truncated": "false",
          },
          body,
        });
      }
      if (
        path === `/clusters/${ruleCluster}/network-rules` &&
        method === "PUT"
      ) {
        const body = request.postDataJSON() as (typeof writes)[number];
        writes.push(body);
        const index = rows.findIndex(
          (row) => row.from === body.from && row.to === body.to,
        );
        expect(index).toBe(5204);
        rows[index] = { ...rows[index], ...body };
        return route.fulfill({
          json: {
            ok: true,
            id: rows[index].id,
            cfg_type: rows[index].cfg_type,
          },
        });
      }
      if (path === "/network/map")
        return route.fulfill({
          json: {
            summary: {
              window_hours: Number(url.searchParams.get("hours") ?? 24),
              selected_cluster_id: ruleCluster,
              workloads: 0,
              flows: 0,
            },
            workloads: [],
            flows: [],
            recent_flows: [],
          },
        });
      if (path === "/network/policies/lifecycle") {
        expect(url.searchParams.get("cluster_id")).toBe(ruleCluster);
        return route.fulfill({
          json: {
            items: [policy],
            summary: {
              selected_cluster_id: ruleCluster,
              total: 1,
              ready: 1,
              discover: 1,
              monitor: 0,
              protect: 0,
              rollback_ready: 0,
              pending_approval: 1,
            },
          },
        });
      }
      if (path === "/policies/dpi-threats")
        return route.fulfill({
          json: { cluster_id: ruleCluster, weak_tls_enabled: false },
        });
      return route.fulfill({
        status: 404,
        json: { error: `Outside rule inventory fixture: ${method} ${path}` },
      });
    });
  }
  return { install, requests, writes, rows, policy };
}
