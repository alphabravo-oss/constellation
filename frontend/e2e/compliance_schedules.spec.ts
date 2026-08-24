import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Compliance page shows scheduled evidence and queues a run", async ({ page }) => {
  await page.goto("/compliance");
  await expect(page.getByRole("heading", { name: "Compliance" })).toBeVisible();
  await expect(page.getByTestId("compliance-schedules")).toContainText("CIS Kubernetes production weekly");
  await expect(page.getByTestId("compliance-schedule-card")).toHaveCount(3);

  await page.getByTestId("compliance-schedule-card").first().getByRole("button", { name: "Run now" }).click();
  await expect(page.getByText(/schedule queued for immediate run/i)).toBeVisible();
});
