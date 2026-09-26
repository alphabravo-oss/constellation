import { randomUUID } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";

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
  await page.goto("/auth/login");
  await page.getByLabel("Email").fill("admin@demo.test");
  await page.getByLabel("Password", { exact: true }).fill("Constellation!1");
  await page.getByRole("button", { name: /^Sign in$/ }).click();
  await expect(page).toHaveURL(/\/clusters$/);
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
    await page.getByRole("button", { name: "New", exact: true }).click();
    await page.locator("textarea").fill(JSON.stringify({
      name: groupName,
      kind: "ground",
      comment: "Temporary Playwright group workflow fixture",
      criteria: [{ key: "namespace", value: "e2e-never-match", op: "eq" }],
      members: [],
      learned_from: "",
      cfg_type: "user",
      policy_mode: "discover",
      profile_mode: "monitor",
    }));
    const created = page.waitForResponse((response) => response.url().includes("/api/v1/groups?") && response.request().method() === "POST");
    createAttempted = true;
    await page.getByRole("button", { name: "Save", exact: true }).click();
    const createResponse = await created;
    expect(createResponse.status(), await createResponse.text()).toBe(201);
    groupId = (await createResponse.json()).id as string;
    expect(groupId).toBeTruthy();
    await expect(page.getByRole("row").filter({ hasText: groupName })).toBeVisible();

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
      const panel = page.getByTestId(testId);
      await expect(panel).toBeVisible();
      await panel.getByRole("combobox").fill(groupName);
      await panel.getByRole("option", { name: new RegExp(groupName) }).click();
      await panel.getByTestId(`${testId}-add`).click();
      await expect(panel.getByTestId(`${testId}-rows`).getByRole("link", { name: groupName })).toBeVisible();
    }

    await page.goto(`/clusters/${clusterId}/groups/${groupId}`);
    await expect(page.getByRole("heading", { name: groupName })).toBeVisible();
    await expect(page.getByRole("cell", { name: "e2e-never-match" })).toBeVisible();
    const usage = page.getByTestId("group-usage-panel");
    await expect(usage).toContainText("Delete blocked by 2 references");
    await expect(usage.getByTestId("group-usage-references")).toContainText("dlp-sensor-binding");
    await expect(usage.getByTestId("group-usage-references")).toContainText("waf-sensor-binding");

    await page.getByRole("button", { name: "monitor", exact: true }).click();
    await expect(page.getByText("Network mode", { exact: true }).locator("..")).toContainText("monitor");
    await page.reload();
    await expect(page.getByText("Network mode", { exact: true }).locator("..")).toContainText("monitor");

    await page.goto(`/clusters/${clusterId}/groups`);
    const row = page.getByRole("row").filter({ hasText: groupName });
    await expect(row).toBeVisible();
    page.once("dialog", (dialog) => dialog.accept());
    const denied = page.waitForResponse((response) => response.url().endsWith(`/api/v1/groups/${groupId}`) && response.request().method() === "DELETE");
    await row.getByRole("button", { name: "Delete" }).click();
    const deleteResponse = await denied;
    expect(deleteResponse.status()).toBe(409);
    expect((await deleteResponse.json()).blocking_references).toBe(2);
    await expect(row).toBeVisible();
  } finally {
    if (createAttempted) await removeFixture(page, clusterId!, groupName);
  }
});
