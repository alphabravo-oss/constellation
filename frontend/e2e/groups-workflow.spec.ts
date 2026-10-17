import { randomUUID } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";
import { login } from "./utils";

test("native group-edge API rejects widening inputs without creating edges", async ({ page }) => {
  await login(page);
  await page.goto("/clusters");
  const cluster = page.getByTestId("cluster-card").first();
  await expect(cluster).toBeVisible();
  const clusterId = await cluster.getAttribute("data-cluster-id");
  expect(clusterId).toBeTruthy();
  const origin = new URL(page.url()).origin;
  const endpoint = `${origin}/api/v1/runtime-policies/group-edges`;
  const before = await page.request.get(`${endpoint}?cluster_id=${clusterId}`);
  expect(before.ok()).toBeTruthy();
  const originalEdges = (await before.json()).edges;
  for (const port of [
    { protocol: "SCTP", port: 443 },
    { protocol: "GRE", port: 443 },
    { protocol: "TCP", port: 65536 },
    { protocol: "UDP", port: -1 },
  ]) {
    const result = await page.request.post(endpoint, {
      headers: { Origin: origin, "X-Constellation-Client": "browser" },
      data: {
        cluster_id: clusterId, from_group: "invalid-source", to_group: "invalid-destination",
        mode: "protect", expand: true, ports: [port],
      },
    });
    expect(result.status()).toBe(400);
    expect(await result.text()).toContain("flow cannot be represented by the native datapath");
  }
  const after = await page.request.get(`${endpoint}?cluster_id=${clusterId}`);
  expect(after.ok()).toBeTruthy();
  expect((await after.json()).edges).toEqual(originalEdges);
});

async function removeFixture(page: Page, clusterId: string, groupName: string) {
  const origin = new URL(page.url()).origin;
  const mutationHeaders = { Origin: origin, "X-Constellation-Client": "browser" };
  const groups = await page.request.get(`${origin}/api/v1/groups?cluster_id=${encodeURIComponent(clusterId)}`);
  expect(groups.ok()).toBeTruthy();
  const group = ((await groups.json()).groups as Array<{ id: string; name: string }>).find((item) => item.name === groupName);
  if (!group) return;

  const bindings = await page.request.get(`${origin}/api/v1/runtime/dpi-sensor-bindings`);
  expect(bindings.ok()).toBeTruthy();
  const bindingIds = ((await bindings.json()).bindings as Array<{ id: string; group_id: string }>)
    .filter((binding) => binding.group_id === group.id)
    .map((binding) => binding.id);
  for (const id of bindingIds) {
    const response = await page.request.delete(`${origin}/api/v1/runtime/dpi-sensor-bindings/${encodeURIComponent(id)}`, { headers: mutationHeaders });
    expect(response.ok()).toBeTruthy();
  }

  const rule = await page.request.delete(
    `${origin}/api/v1/clusters/${encodeURIComponent(clusterId)}/network-rules?from=${encodeURIComponent(groupName)}&to=external`,
    { headers: mutationHeaders },
  );
  expect(rule.ok()).toBeTruthy();

  const deleted = await page.request.delete(`${origin}/api/v1/groups/${encodeURIComponent(group.id)}`, { headers: mutationHeaders });
  expect(deleted.ok()).toBeTruthy();
}

test("group creation, policy use, usage, promotion, and guarded deletion in a production browser", async ({ page }) => {
  test.setTimeout(120_000);
  await login(page);
  await page.goto("/clusters");
  const cluster = page.getByTestId("cluster-card").first();
  await expect(cluster).toBeVisible();
  const clusterId = await cluster.getAttribute("data-cluster-id");
  expect(clusterId).toBeTruthy();

  const groupName = `e2e-group-${randomUUID().slice(0, 8)}`;
  let groupId: string | undefined;
  let createAttempted = false;
  try {
    await page.goto(`/clusters/${clusterId}/groups`);
    await expect(page.getByTestId("groups-page")).toBeVisible();
    await page.getByRole("link", { name: "Add group", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/groups/new$`));
    await expect(page.getByRole("heading", { name: "Add group", exact: true })).toBeVisible();
    await page.getByLabel(/^Name/).fill(groupName);
    await page.getByLabel("Description", { exact: true }).fill("Temporary Playwright group workflow fixture");
    await page.getByLabel("Selector 1 value", { exact: true }).fill("e2e-never-match");
    await page.getByLabel("Network mode", { exact: true }).selectOption("discover");
    await page.getByLabel("Process/file mode", { exact: true }).selectOption("monitor");
    const created = page.waitForResponse((response) => response.url().includes("/api/v1/groups?") && response.request().method() === "POST");
    createAttempted = true;
    await page.getByRole("button", { name: "Save", exact: true }).click();
    const createResponse = await created;
    expect(createResponse.status(), await createResponse.text()).toBe(201);
    groupId = (await createResponse.json()).id as string;
    expect(groupId).toBeTruthy();
    await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/groups$`));
    const createdRow = page.getByRole("row").filter({ hasText: groupName });
    await expect(createdRow).toBeVisible();
    await createdRow.getByRole("link", { name: `Edit ${groupName}`, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/groups/${groupId}/edit$`));
    await expect(page.getByLabel("Selector 1 value", { exact: true })).toHaveValue("e2e-never-match");
    await page.getByLabel("Description", { exact: true }).fill("Updated Playwright group workflow fixture");
    const edited = page.waitForResponse((response) => new URL(response.url()).pathname === `/api/v1/groups/${groupId}` && response.request().method() === "PUT");
    await page.getByRole("button", { name: "Save", exact: true }).click();
    expect((await edited).ok()).toBeTruthy();
    await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/groups$`));
    await page.goto(`/clusters/${clusterId}/groups/${groupId}/edit`);
    await expect(page.getByLabel("Description", { exact: true })).toHaveValue("Updated Playwright group workflow fixture");
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/groups$`));

    await page.getByRole("link", { name: "Settings", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/groups/settings$`));
    await expect(page.getByRole("heading", { name: "Group settings", exact: true })).toBeVisible();
    await expect(page.getByLabel("Default network mode", { exact: true })).toBeVisible();
    const defaults = await page.request.get(`${new URL(page.url()).origin}/api/v1/policies/service-mode-defaults?cluster_id=${clusterId}`);
    expect(defaults.ok()).toBeTruthy();
    const originalDefaults = await defaults.json();
    await page.getByLabel("Default network mode", { exact: true }).selectOption(originalDefaults.policy_mode === "discover" ? "monitor" : "discover");
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    await page.getByRole("link", { name: "Settings", exact: true }).click();
    await expect(page.getByLabel("Default network mode", { exact: true })).toHaveValue(originalDefaults.policy_mode);
    await expect(page.getByLabel("Default process/file mode", { exact: true })).toHaveValue(originalDefaults.profile_mode);
    const defaultsSaved = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/policies/service-mode-defaults" && response.request().method() === "PATCH");
    await page.getByRole("button", { name: "Save", exact: true }).click();
    const savedDefaults = await defaultsSaved;
    expect(savedDefaults.ok()).toBeTruthy();
    expect(await savedDefaults.json()).toMatchObject({ cluster_id: clusterId, policy_mode: originalDefaults.policy_mode, profile_mode: originalDefaults.profile_mode });
    await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/groups$`));

    await page.goto(`/clusters/${clusterId}/network-rules/new`);
    await page.getByTestId("network-rule-from-group").getByRole("combobox").fill(groupName);
    await page.getByTestId("network-rule-from-group").getByRole("option", { name: new RegExp(groupName) }).click();
    await page.getByTestId("network-rule-to-group").getByRole("combobox").fill("external");
    await page.getByTestId("network-rule-to-group").getByRole("option", { name: "external" }).click();
    await page.getByLabel("Comment").fill("Temporary Playwright group workflow rule");
    const ruleCreated = page.waitForResponse((response) => response.url().includes(`/api/v1/clusters/${clusterId}/network-rules`) && response.request().method() === "PUT");
    await page.getByRole("button", { name: "Add rule" }).click();
    expect((await ruleCreated).ok()).toBeTruthy();
    await expect(page.getByRole("row").filter({ hasText: groupName })).toBeVisible();

    for (const [route, testId] of [["runtime-dlp", "dlp-group-bindings"], ["runtime-signatures", "signature-group-bindings"]] as const) {
      await page.goto(`/clusters/${clusterId}/${route}`);
      await page.getByText("Advanced", { exact: true }).click();
      const panel = page.getByTestId(testId);
      await expect(panel).toBeVisible();
      await panel.getByTestId(`${testId}-add`).click();
      await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/${route}/scope/new`));
      await page.getByTestId("dpi-scope-group").getByRole("combobox").fill(groupName);
      await page.getByTestId("dpi-scope-group").getByRole("option", { name: new RegExp(groupName) }).click();
      await page.getByRole("button", { name: "Save scope", exact: true }).click();
      await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/${route}(\\?|$)`));
      await page.getByText("Advanced", { exact: true }).click();
      await expect(page.getByTestId(`${testId}-rows`).getByRole("button", { name: groupName, exact: true })).toBeVisible();
    }

    await page.goto(`/clusters/${clusterId}/groups/${groupId}`);
    await expect(page.getByRole("heading", { name: groupName })).toBeVisible();
    await page.getByRole("tab", { name: /^Membership selectors/ }).click();
    await expect(page).toHaveURL(/tab=criteria/);
    await expect(page.getByRole("cell", { name: "e2e-never-match" })).toBeVisible();
    await page.getByRole("tab", { name: /^Policy usage/ }).click();
    await expect(page).toHaveURL(/tab=usage/);
    const usage = page.getByTestId("group-usage-panel");
    await expect(usage).toContainText("Deletion is blocked by 2 policy references");
    await expect(usage.getByTestId("group-usage-references")).toContainText("dlp-sensor-binding");
    await expect(usage.getByTestId("group-usage-references")).toContainText("waf-sensor-binding");

    await page.getByRole("tab", { name: "Enforcement & details", exact: true }).click();
    await expect(page).toHaveURL(/tab=configuration/);
    await page.getByRole("button", { name: "Move to monitor", exact: true }).click();
    await expect(page.getByText("Network mode", { exact: true }).locator("..")).toContainText("monitor");
    await page.reload();
    await expect(page.getByText("Network mode", { exact: true }).locator("..")).toContainText("monitor");

    await page.goto(`/clusters/${clusterId}/groups`);
    const row = page.getByRole("row").filter({ hasText: groupName });
    await expect(row).toBeVisible();
    page.once("dialog", (dialog) => dialog.accept());
    const denied = page.waitForResponse((response) => new URL(response.url()).pathname === `/api/v1/groups/${groupId}` && response.request().method() === "DELETE");
    await row.getByRole("button", { name: `Delete ${groupName}`, exact: true }).click();
    const deleteResponse = await denied;
    expect(deleteResponse.status()).toBe(409);
    expect((await deleteResponse.json()).blocking_references).toBe(2);
    await expect(row).toBeVisible();
  } finally {
    if (createAttempted) await removeFixture(page, clusterId!, groupName);
  }
});
