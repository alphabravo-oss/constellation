import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Response catalog shows built-in organization rules and URL event filters", async ({ page }) => {
  await page.goto("/response");
  await expect(page.getByRole("heading", { name: "Response Catalog", exact: true })).toBeVisible();
  await expect(page.getByTestId("response-rules-table")).toBeVisible();
  await expect(page.getByTestId("response-rule-row")).toHaveCount(5);
  await expect(page.getByTestId("response-rules-table").getByText("Unauthorized external egress")).toBeVisible();
  await expect(page.getByTestId("response-rules-table").getByText("alert, quarantine_workload")).toBeVisible();

  await page.getByRole("combobox", { name: /^Event type/ }).selectOption("network");
  await expect(page).toHaveURL(/event=network/);
  await expect(page.getByTestId("response-rule-row")).toHaveCount(1);
  await expect(page.getByTestId("response-rules-table").getByText("Unauthorized external egress")).toBeVisible();
  await page.reload();
  await expect(page.getByRole("combobox", { name: /^Event type/ })).toHaveValue("network");
  await expect(page.getByTestId("response-rule-row")).toHaveCount(1);
  await expect(page.getByRole("button", { name: "Authored response rules", exact: true })).toBeVisible();
});

test("shared table headers and cells stay aligned across widths and densities", async ({ page }) => {
  await page.goto("/response");
  const table = page.getByTestId("response-rules-table");
  await expect(table.getByTestId("response-rule-row").first()).toBeVisible();
  for (const width of [1440, 1024, 640]) {
    await page.setViewportSize({ width, height: 900 });
    for (const density of ["compact", "cozy", "comfy"]) {
      await table.getByRole("button", { name: `${density} density`, exact: true }).click();
      await expect.poll(() => table.evaluate((root) => {
        const headers = Array.from(root.querySelectorAll("thead th"));
        const cells = Array.from(root.querySelectorAll("tbody tr:first-child td"));
        if (!headers.length || headers.length !== cells.length) return false;
        return headers.every((header, index) => {
          const h = header.getBoundingClientRect();
          const c = cells[index].getBoundingClientRect();
          return Math.abs(h.x - c.x) < 1 && Math.abs(h.width - c.width) < 1
            && window.getComputedStyle(header).textAlign === window.getComputedStyle(cells[index]).textAlign;
        });
      })).toBe(true);
    }
  }
});

test("Response catalog overrides use a dedicated form and require a fresh preview", async ({ page }) => {
  await page.goto("/response");
  await page.getByRole("combobox", { name: /^Event type/ }).selectOption("dlp");
  await page.getByRole("button", { name: "Edit override for Secret exfiltration pattern", exact: true }).click();
  await expect(page).toHaveURL(/\/response\/dlp-secret-exfiltration\/edit/);
  await expect(page.getByRole("heading", { name: "Edit response catalog override", exact: true })).toBeVisible();
  await expect(page.getByText("This override changes organization-wide settings", { exact: true })).toBeVisible();
  await page.getByTestId("response-rule-mode-select").selectOption("enforce");
  const enabled = page.getByRole("switch", { name: "Enable built-in rule", exact: true });
  if (await enabled.getAttribute("aria-checked") !== "true") await enabled.click();
  await page.getByTestId("response-rule-reason").fill("pilot DLP enforcement in monitor-approved namespaces");
  await expect(page.getByTestId("response-rule-save")).toBeDisabled();
  await page.getByTestId("response-rule-preview").click();
  await expect(page.getByTestId("response-rule-preview-card")).toContainText("Dry run only");
  await expect(page.getByTestId("response-rule-preview-card")).toContainText("privileged Linux runtime agent");
  await expect(page.getByTestId("response-rule-save")).toBeEnabled();
  await page.getByTestId("response-rule-reason").fill("pilot DLP enforcement with organization owner approval");
  await expect(page.getByTestId("response-rule-save")).toBeDisabled();
  await page.getByTestId("response-rule-preview").click();
  await expect(page.getByTestId("response-rule-save")).toBeEnabled();
  await page.getByTestId("response-rule-save").click();
  await expect(page.getByRole("heading", { name: "Response Catalog", exact: true })).toBeVisible();
  await expect(page.getByRole("combobox", { name: /^Event type/ })).toHaveValue("dlp");
  const savedRule = page.getByTestId("response-rule-row").filter({ hasText: "Secret exfiltration pattern" });
  await expect(savedRule).toContainText("enforce");
  await expect(savedRule).toContainText("Organization override");
  await savedRule.getByRole("button", { name: "Edit override for Secret exfiltration pattern", exact: true }).click();
  await expect(page.getByTestId("response-rule-reason")).toHaveValue("pilot DLP enforcement with organization owner approval");
  await expect(page.getByTestId("response-rule-mode-select")).toHaveValue("enforce");
  await expect(page.getByRole("switch", { name: "Enable built-in rule", exact: true })).toHaveAttribute("aria-checked", "true");
});
