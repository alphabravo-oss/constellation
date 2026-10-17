import { expect, test } from "@playwright/test";

test("NVD form validates, preserves the stored key, and saves without a discard prompt", async ({ page }) => {
  let patches = 0;
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/auth/me")) {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    } else if (path.endsWith("/system/config")) {
      if (route.request().method() === "PATCH") {
        patches++;
        expect(route.request().headers()["if-match"]).toBe('"1"');
        expect(route.request().postDataJSON()).toEqual({ nvd_enabled: true, nvd_mirror_url: "https://mirror.test/api" });
      }
      await route.fulfill({ json: { revision: patches + 1, config: { nvd_enabled: patches > 0, nvd_api_key: "***REDACTED***", nvd_mirror_url: patches ? "https://mirror.test/api" : "" } } });
    } else {
      await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
    }
  });
  await page.goto("/settings/scanner/nvd");
  await expect(page.getByLabel("NVD API key")).toHaveValue("");
  await page.getByRole("switch", { name: "Enable NVD import" }).click();
  const mirror = page.getByLabel("Mirror URL");
  await mirror.fill("file:///etc/passwd"); await mirror.press("Tab");
  await expect(mirror).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByRole("button", { name: "Save changes" })).toBeDisabled();
  expect(patches).toBe(0);
  await mirror.fill("https://mirror.test/api");
  const dialogs: string[] = [];
  page.on("dialog", async (dialog) => { dialogs.push(dialog.message()); await dialog.dismiss(); });
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page).toHaveURL(/\/settings\/scanner$/);
  expect(patches).toBe(1); expect(dialogs).toEqual([]);
});

test("NVD key edits stay in the form when navigation is canceled", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({ json: path.endsWith("/auth/me")
      ? { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] }
      : { revision: 1, config: { nvd_enabled: false } } });
  });
  await page.goto("/settings/scanner/nvd");
  await page.getByLabel("NVD API key").fill("replacement-test-value");
  page.once("dialog", (dialog) => dialog.dismiss());
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(/\/settings\/scanner\/nvd$/);
  await expect(page.getByLabel("NVD API key")).toHaveValue("replacement-test-value");
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(/\/settings\/scanner$/);
});
