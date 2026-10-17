import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import type { NetworkPeerEvidenceResponse, RuntimePolicy } from "../src/api/client";
import { findingInstances, instanceCluster, instanceID, instanceRoot, instanceTimes } from "./fixtures/finding-instances";
import { savedViewCluster, savedViewsFixture } from "./fixtures/inventory-network-saved-views";

const policyID = "44444444-4444-4444-8444-444444444444";

test("Runtime policy conflict requires explicit review and preserves the candidate draft through failed refresh", async ({ page }) => {
  await savedViewsFixture(page);
  let policy: RuntimePolicy = { id: policyID, org_id: "org-a", cluster_id: savedViewCluster, namespace: "payments", workload: "payments/api", name: "Saved traffic policy", dp_policy_id: 77, mode: "monitor", rules: [], version: 1, revision: "1", def_action: 2, apply_dir: 0, created_at: "2026-10-12T00:00:00Z", updated_at: "2026-10-12T00:00:00Z" };
  const writes: Array<{ expected_version: string; cluster_id: string; name: string; rules: unknown[] }> = [];
  let failRead = false;
  await page.route("**/api/v1/runtime-policies**", async route => {
    const request = route.request(), url = new URL(request.url());
    if (request.method() === "GET") {
      if (failRead) return route.fulfill({ status: 500, json: { error: "Read unavailable" } });
      return route.fulfill({ json: url.pathname.endsWith(policyID) ? policy : { policies: [policy] } });
    }
    expect(request.method()).toBe("PUT");
    expect(url.pathname).toBe(`/api/v1/runtime-policies/${policyID}/reviewed`);
    const body = request.postDataJSON() as typeof writes[number];
    expect(body.cluster_id).toBe(savedViewCluster);
    writes.push(body);
    if (body.expected_version !== policy.revision) return route.fulfill({ status: 409, json: { error: "Policy changed" } });
    policy = { ...policy, name: body.name, rules: body.rules as RuntimePolicy["rules"], version: policy.version + 1, revision: String(BigInt(policy.revision!) + 1n), updated_at: "2026-10-13T01:00:00Z" };
    return route.fulfill({ json: policy });
  });
  await page.goto(`/clusters/${savedViewCluster}/runtime-policies/${policyID}?context=network-review`);
  const name = page.getByLabel("Name", { exact: true }), save = page.getByTestId("runtime-policies-editor-save");
  await expect(save).toBeEnabled();
  await name.fill("Retained operator draft");
  const rules = '[{"id":77,"action":2}]';
  await page.getByTestId("runtime-policies-editor-rules").fill(rules);
  policy = { ...policy, name: "Concurrently reviewed name", revision: "2", version: 2, mode: "enforce" };
  await save.click();
  await expect(page.getByRole("button", { name: "Review latest policy", exact: true })).toBeVisible();
  await expect(save).toBeDisabled();
  await expect(name).toHaveValue("Retained operator draft");
  failRead = true;
  await page.getByRole("button", { name: "Review latest policy", exact: true }).click();
  await expect(page.getByText("Current policy could not be reviewed. Your draft is preserved.", { exact: true })).toBeVisible();
  await expect(save).toBeDisabled();
  await expect(name).toHaveValue("Retained operator draft");
  await expect(page.getByTestId("runtime-policies-editor-rules")).toHaveValue(rules);
  failRead = false;
  await page.getByRole("button", { name: "Refresh policy", exact: true }).click();
  await expect(save).toBeEnabled();
  await page.locator("summary").filter({ hasText: "Advanced: request preview" }).click();
  await expect(page.getByText("Reviewed mode: enforce · revision 2", { exact: true })).toBeVisible();
  await expect(page.getByText(/Saved name: Concurrently reviewed name/)).toBeVisible();
  await expect(name).toHaveValue("Retained operator draft");
  await save.click();
  await expect(page).toHaveURL(url => url.pathname === `/clusters/${savedViewCluster}/runtime-policies` && url.searchParams.get("context") === "network-review");
  expect(writes.map(write => write.expected_version)).toEqual(["1", "2"]);
  expect(writes[1]).toEqual({ cluster_id: savedViewCluster, expected_version: "2", name: "Retained operator draft", rules: [{ id: 77, action: 2 }] });
  expect(policy.mode).toBe("enforce");
});

test("Disabled runtime policies re-enable only in monitor mode with exact reviewed receipts", async ({ page }) => {
  await savedViewsFixture(page);
  const otherID = "55555555-5555-4555-8555-555555555555";
  const disabled: RuntimePolicy = { id: policyID, org_id: "org-a", cluster_id: savedViewCluster, namespace: "payments", workload: "payments/api", name: "Paused runtime policy", dp_policy_id: 77, mode: "disabled", rules: [], version: 1, revision: "9007199254740993", def_action: 2, apply_dir: 0, created_at: "2026-10-12T00:00:00Z", updated_at: "2026-10-12T00:00:00Z" };
  let policies = [disabled, { ...disabled, id: otherID, workload: "payments/worker", name: "Unconfirmed runtime policy" }];
  const writes: Array<{ id: string; body: unknown }> = [];
  await page.route("**/api/v1/runtime-policies**", async route => {
    const request = route.request(), url = new URL(request.url());
    if (request.method() === "GET") return route.fulfill({ json: { policies } });
    expect(request.method()).toBe("POST");
    const id = url.pathname.split("/")[4];
    expect(url.pathname).toBe(`/api/v1/runtime-policies/${id}/reviewed/demote`);
    expect([policyID, otherID]).toContain(id);
    const body = request.postDataJSON();
    expect(body).toEqual({ cluster_id: savedViewCluster, expected_version: "9007199254740993" });
    writes.push({ id, body });
    const reviewed = policies.find(policy => policy.id === id)!;
    const receipt = { ...reviewed, mode: id === otherID ? "enforce" : "monitor", revision: "9007199254740994", updated_at: "2026-10-13T01:00:00Z" } satisfies RuntimePolicy;
    if (id === policyID) policies = policies.map(policy => policy.id === id ? receipt : policy);
    await route.fulfill({ json: receipt });
  });
  await page.goto(`/clusters/${savedViewCluster}/runtime-policies`);
  await expect(page.getByTestId(`runtime-policy-enable-${policyID}`)).toHaveText("Enable in monitor mode");
  await expect(page.getByTestId(`runtime-policy-promote-${policyID}`)).toHaveCount(0);
  await page.getByTestId(`runtime-policy-enable-${policyID}`).click();
  await expect(page.getByTestId(`runtime-policy-promote-${policyID}`)).toBeEnabled();
  await expect(page.getByTestId(`runtime-policy-enable-${policyID}`)).toHaveCount(0);
  const unconfirmed = page.getByTestId(`runtime-policy-row-${otherID}`);
  await page.getByTestId(`runtime-policy-enable-${otherID}`).click();
  await expect(unconfirmed).toContainText("Reload before another write");
  await expect(page.getByTestId(`runtime-policy-enable-${otherID}`)).toBeDisabled();
  expect(writes.map(write => write.id)).toEqual([policyID, otherID]);
  expect(policies.find(policy => policy.id === policyID)?.mode).toBe("monitor");
  expect(policies.find(policy => policy.id === otherID)?.mode).toBe("disabled");
});

test("Both peer diagnostics retain returned roles, selected visibility and shown CSV scope", async ({ page }) => {
  await savedViewsFixture(page);
  const requests: URL[] = [];
  const workloads = ["payments/api", "payments/client"].map(id => ({ id, cluster_id: savedViewCluster, namespace: "payments", name: id.split("/")[1], kind: "Deployment", platform_role: "", risk_score: 0, finding_count: 0 }));
  const flow = { id: "peer-fixture-flow", cluster_id: savedViewCluster, src: workloads[0].id, dst: workloads[1].id, src_platform_role: "", dst_platform_role: "", protocol: "TCP", l7_protocol: "HTTP", dst_port: 80, verdict: "allow", state: "ok", traffic_scope: "internal", bytes: 10, packets: 1, samples: 1, last_seen_at: "2026-10-13T00:00:00Z" };
  await page.route("**/api/v1/network/map**", route => route.fulfill({ json: { summary: { window_hours: 24, selected_cluster_id: savedViewCluster, workloads: 2, flows: 1 }, workloads, flows: [flow], recent_flows: [] } }));
  await page.route("**/api/v1/network/peers**", async route => {
    expect(route.request().method()).toBe("GET");
    const url = new URL(route.request().url()); requests.push(url);
    expect(url.searchParams.get("cluster_id")).toBe(savedViewCluster);
    expect(url.searchParams.get("workload")).toBe("payments/api");
    expect(url.searchParams.get("hours")).toBe("24");
    const all: NetworkPeerEvidenceResponse["peers"] = [
      { peer_ip: "10.0.0.2", peer: "custom-install/controller", peer_platform_role: "core", peer_cluster_id: savedViewCluster, direction: "egress", external: false, bytes: 20, packets: 2, sessions: 1, ports: [443], protocols: ["tcp"], verdict: "allow", last_seen_at: flow.last_seen_at },
      { peer_ip: "10.0.0.3", peer: "custom-install/ambiguous", peer_platform_role: "", peer_cluster_id: null, direction: "egress", external: false, bytes: 10, packets: 1, sessions: 1, ports: [443], protocols: ["tcp"], verdict: "allow", last_seen_at: flow.last_seen_at },
    ];
    const hide_platform = url.searchParams.get("hide_platform") === "true";
    const peers = all.filter(peer => !hide_platform || peer.peer_platform_role !== "core");
    await route.fulfill({ json: { cluster_id: savedViewCluster, workload: "payments/api", workload_platform_role: "", hide_platform, peers, source_limit: 500, total: peers.length, has_more: false } satisfies NetworkPeerEvidenceResponse });
  });
  await page.goto(`/clusters/${savedViewCluster}/network?tab=map&workload=payments/api&hide_platform=false`);
  await page.getByTestId("network-workload-peers-tab").click();
  const workloadView = page.getByTestId("network-workload-peers");
  await expect(workloadView.locator("tbody tr")).toHaveCount(2);
  await expect(workloadView.locator("tbody tr").filter({ hasText: "controller" })).toContainText("Core");
  await expect(workloadView.locator("tbody tr").filter({ hasText: "ambiguous" })).toContainText("Unclassified");
  const downloading = page.waitForEvent("download");
  await workloadView.getByRole("button", { name: "Export shown peers CSV", exact: true }).click();
  const csv = await readFile(await (await downloading).path(), "utf8");
  expect(csv.split(/\r?\n/)[0]).toContain("Platform role");
  expect(csv.split(/\r?\n/).find(line => line.includes("controller"))).toContain("core");
  expect(csv.split(/\r?\n/).find(line => line.includes("ambiguous"))).not.toContain("core");
  await page.getByTestId("platform-visibility-toggle").click();
  await expect(workloadView.locator("tbody tr")).toHaveCount(1);
  await expect(workloadView).not.toContainText("controller");
  await page.goto(`/clusters/${savedViewCluster}/network?tab=map&flow=peer-fixture-flow&hide_platform=false`);
  await page.getByRole("group", { name: "Edge from payments/api to payments/client", exact: true }).click({ force: true });
  await page.getByTestId("network-flow-inspector-tab-peers").click();
  const edgeView = page.getByTestId("network-edge-peers");
  await expect(edgeView.locator("tbody tr")).toHaveCount(2);
  await expect(edgeView.locator("tbody tr").filter({ hasText: "controller" })).toContainText("Core");
  await edgeView.locator("summary").filter({ hasText: "Peer evidence details" }).click();
  await expect(edgeView).toContainText("2 returned of 2 matching peer IP/direction groups");
  expect(requests.map(url => url.searchParams.get("hide_platform"))).toEqual(expect.arrayContaining(["true", "false"]));
});

test("Legacy Findings preferences hide new identities while the exact observation chooser reveals timestamps without erasing preferences", async ({ page }) => {
  const fixture = findingInstances(); fixture.rows.forEach(row => { row.title = "Repeated retained finding"; }); await fixture.install(page);
  const key = `constellation.table.${JSON.stringify(["org", "operator", "findings.instances"])}.v1`;
  await page.addInitScript(({ key }) => { localStorage.setItem(`constellation.operator.${JSON.stringify(["org", "operator", "constellation.findings.density"])}`, "compact"); if (!localStorage.getItem(key)) localStorage.setItem(key, JSON.stringify({ hiddenColumnIds: ["package"], density: "compact", columnOrder: ["severity", "title"], columnWidths: { title: 280 }, columnPinning: { start: ["title"], end: [] } })); }, { key });
  await page.goto(`${instanceRoot}?view=instances&lifecycle=all`);
  const table = page.getByTestId("findings-table");
  await expect(table.locator("tbody tr")).toHaveCount(2);
  await expect(table.locator('th[data-column-id="instance"]')).toHaveCount(0);
  await expect(table.locator('th[data-column-id="first-seen"]')).toHaveCount(0);
  await expect(table.getByRole("button", { name: "compact density", exact: true })).toHaveAttribute("aria-pressed", "true");
  const normal = await page.evaluate(key => JSON.parse(localStorage.getItem(key)!), key);
  expect(normal.hiddenColumnIds).toEqual(["package", "instance", "first-seen"]);
  expect(normal.preferenceMigrations).toEqual(["observation-metadata-v1"]);
  expect(normal.columnPinning.start).toEqual(["title"]);
  expect(normal.columnWidths.title).toBe(280);
  await page.goto(`${instanceRoot}?view=instances&lifecycle=all&q=${encodeURIComponent(`id:${instanceID}`)}`);
  await expect(table.locator('th[data-column-id="first-seen"]')).toBeVisible();
  for (const timestamp of instanceTimes) await expect(table.locator("tbody").getByText(timestamp, { exact: true })).toBeVisible();
  await expect(table.locator('th[data-column-id="instance"]')).toHaveCount(0);
  expect((await page.evaluate(key => JSON.parse(localStorage.getItem(key)!), key)).hiddenColumnIds).toContain("first-seen");
  await table.locator("tbody tr").filter({ hasText: instanceTimes[1] }).getByRole("button", { name: "Repeated retained finding", exact: true }).click();
  await expect(page).toHaveURL(url => url.pathname === `/clusters/${instanceCluster}/findings/${instanceID}` && url.searchParams.get("first_seen_at") === instanceTimes[1]);
  await page.goBack();
  await expect(table.locator('th[data-column-id="first-seen"]')).toBeVisible();
  await page.goto(`${instanceRoot}?view=instances&lifecycle=all`);
  await expect(table.locator('th[data-column-id="first-seen"]')).toHaveCount(0);
});
