import { expect, test } from "@playwright/test";

const clusterId = "11111111-1111-4111-8111-111111111111";

test("network activity uses shared filters and server pages", async ({ page }) => {
  const requests: URL[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
      return;
    }
    if (path === "/clusters") {
      await route.fulfill({ json: { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] } });
      return;
    }
    if (path === "/groups") {
      await route.fulfill({ json: { groups: [] } });
      return;
    }
    if (path === "/network/map") {
      requests.push(url);
      await route.fulfill({ json: { summary: { window_hours: 24, workloads: 0, flows: 0 }, workloads: [], flows: [], recent_flows: [] } });
      return;
    }
    if (path === "/network/conversations") {
      requests.push(url);
      const offset = Number(url.searchParams.get("offset") ?? 0);
      const conversations = Array.from({ length: offset === 200 ? 50 : 100 }, (_, index) => ({
        from: `default/client-${offset + index}`, to: "default/server", bytes: 1, packets: 1, edges: 1, last_seen: "2026-09-26T00:00:00Z",
      }));
      await route.fulfill({ json: { conversations, nodes: [], node_kinds: {}, edges: [], window_hours: 24, total: 250, limit: 100, offset, has_more: offset < 200 } });
      return;
    }
    if (path === "/network/sessions") {
      requests.push(url);
      const offset = Number(url.searchParams.get("offset") ?? 0);
      const sessions = Array.from({ length: offset === 200 ? 50 : 100 }, (_, index) => ({
        id: offset + index + 1, node: "node-a", application: "HTTPS", ip_proto: "TCP", client_ip: `10.0.${offset}.${index}`, client_port: 40000 + index,
        server_ip: "10.0.0.2", server_port: 443, client_state: "ESTABLISHED", server_state: "ESTABLISHED", client_bytes: 1, server_bytes: 1, client_pkts: 1, server_pkts: 1, age: 1, idle: 0, ingress: false, severity: 0,
      }));
      await route.fulfill({ json: { sessions, total: 250, limit: 100, offset, has_more: offset < 200 } });
      return;
    }
    if (path === "/runtime-threats") {
      requests.push(url);
      const offset = Number(url.searchParams.get("offset") ?? 0);
      const threats = Array.from({ length: offset === 200 ? 50 : 100 }, (_, index) => ({
        id: `threat-${offset + index}`, org_id: "org", cluster_id: clusterId, threat_id: 1001, severity: 8, action: 0, src_ip: "10.0.0.1", src_port: 40000, dst_ip: "10.0.0.2", dst_port: 443, pkt_ingress: false, sess_ingress: false, reported_at: "2026-09-26T00:00:00Z", at: "2026-09-26T00:00:00Z",
      }));
      await route.fulfill({ json: { threats, total: 250, limit: 100, offset, has_more: offset < 200 } });
      return;
    }
    if (path === "/network/policies/lifecycle") {
      await route.fulfill({ json: { summary: { total: 0, ready: 0 }, items: [] } });
      return;
    }
    await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
  });

  await page.goto(`/clusters/${clusterId}/network?tab=sessions`);
  await page.getByTestId("network-traffic-port").fill("443");
  await page.getByTestId("network-traffic-peer").fill("10.0.0.2");
  await page.getByTestId("network-traffic-application").fill("7");
  const sessions = page.getByTestId("network-sessions-tab");
  await expect(sessions).toContainText("of 250");
  await sessions.getByRole("button", { name: "Next" }).click();
  await expect(sessions).toContainText("Page 2 of 3");
  await expect.poll(() => requests.some((url) => url.pathname.endsWith("/network/sessions") && url.searchParams.get("offset") === "100")).toBe(true);

  await page.getByRole("tab", { name: /Conversations/ }).click();
  const conversations = page.getByTestId("network-conversations-tab");
  await expect(conversations).toContainText("of 250");
  await conversations.getByRole("button", { name: "Next" }).click();
  await expect(conversations).toContainText("Page 2 of 3");

  await page.getByRole("tab", { name: /Threats/ }).click();
  const threats = page.getByTestId("network-threats-tab");
  await expect(threats).toContainText("of 250");
  await threats.getByRole("button", { name: "Next" }).click();
  await expect(threats).toContainText("Page 2 of 3");
  for (const endpoint of ["/network/map", "/network/conversations", "/network/sessions", "/runtime-threats"]) {
    expect(requests.some((url) => url.pathname.endsWith(endpoint) && url.searchParams.get("port") === "443" && url.searchParams.get("peer") === "10.0.0.2")).toBe(true);
  }
});
