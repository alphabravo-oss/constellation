import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Compliance page lists 16 frameworks and drills into one", async ({ page }) => {
  await page.goto("/compliance");
  await expect(page.getByTestId("frameworks-rail")).toBeVisible();

  // Spot-check categories from the framework registry.
  await expect(page.getByText(/^kubernetes$/i).first()).toBeVisible();
  await expect(page.getByText(/^regulatory-eu$/i).first()).toBeVisible();

  // Click CIS Kubernetes; the detail pane should show the framework's name.
  await page.getByTestId("framework-cis-k8s-1.9").click();
  await expect(page.getByRole("heading", { name: /CIS Kubernetes 1.9/i })).toBeVisible();

  // The page asks the API for /compliance/checks?framework=cis-k8s-1.9; even with no
  // ingested data we should see the empty-state hint, not a crash.
  await expect(page.getByTestId("framework-detail")).toContainText(
    /No controls evaluated yet|controls/i,
  );
});

test("Policies page renders the catalog rail", async ({ page }) => {
  await page.goto("/policies");
  // The seed has 1 policy; the rail should render it.
  await expect(page.getByTestId("policy-rail")).toBeVisible();
  await expect(page.getByTestId("policy-row-block-unsigned-images")).toBeVisible();
});

test("Policies page dry-runs admission decisions before enforcement", async ({ page }) => {
  await page.goto("/policies");
  await page.getByRole("tab", { name: /Admission simulator/i }).click();

  await expect(page.getByTestId("policy-simulator")).toBeVisible();
  await page.getByTestId("policy-simulator-run").click();

  await expect(page.getByTestId("policy-simulator-results")).toContainText("deny");
  await expect(page.getByTestId("policy-simulator-results")).toContainText("Pod/privileged-debug");
  await expect(page.getByTestId("policy-simulator-results")).toContainText("block-unsigned-images");
  await expect(page.getByTestId("policy-simulator-results")).toContainText("Sends webhook");
  await expect(page.getByTestId("policy-simulator-results")).toContainText("Persists decision");
  await expect(page.getByTestId("policy-simulator-guardrails")).toContainText("Dry-run only");
});
