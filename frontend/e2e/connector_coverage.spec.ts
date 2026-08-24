import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Settings links to registry and cloud connector coverage", async ({ page }) => {
  await page.goto("/settings");
  await expect(page.getByRole("link", { name: /Connectors Registry, cloud-account/i })).toBeVisible();

  await page.getByRole("link", { name: /Connectors Registry, cloud-account/i }).click();
  await expect(page).toHaveURL(/\/settings\/connectors$/);
  await expect(page.getByRole("heading", { name: "Registry & Cloud Connectors" })).toBeVisible();
});

test("Connector coverage shows registry, cloud, scan, and guardrail operations", async ({ page }) => {
  await page.goto("/settings/connectors");

  await expect(page.getByTestId("registry-connectors")).toContainText("GitHub Container Registry");
  await expect(page.getByTestId("registry-connectors")).toContainText("AWS ECR production");
  await expect(page.getByTestId("registry-connectors")).toContainText("JFrog Artifactory shared");

  await page.getByRole("tab", { name: /Cloud accounts/i }).click();
  await expect(page.getByTestId("cloud-connectors")).toContainText("AWS production");
  await expect(page.getByTestId("cloud-connectors")).toContainText("Azure enterprise subscription");

  await page.getByRole("tab", { name: /Scan jobs/i }).click();
  await page.getByText("Coverage gaps by scope").click();
  await expect(page.getByTestId("scan-coverage")).toContainText("Deployed images");

  await page.getByRole("tab", { name: /Scanner cache/i }).click();
  await expect(page.getByTestId("scanner-pools")).toContainText("Scanner workers");

  await page.getByRole("tab", { name: /Registries/i }).click();
  await page.getByText("Enterprise guardrails").click();
  await expect(page.getByTestId("connector-guardrails")).toContainText("Credential redaction");
});

test("Connector actions are wired to dry-run checks and scan queue", async ({ page }) => {
  await page.goto("/settings/connectors");
  const imageRef = `ghcr.io/alphabravocompany/api-service:e2e-${Date.now()}`;

  await page.getByRole("button", { name: /test connection/i }).first().click();
  await expect(page.getByTestId("connector-test-preview")).toContainText("no credential is persisted");
  await expect(page.getByTestId("connector-test-preview")).toContainText("scan: no");

  await page.goto("/settings/connectors/scan/new");
  await page.getByTestId("queue-scan-target-ref").fill(imageRef);
  await page.getByTestId("queue-scan").first().click();
  await expect(page).toHaveURL(/\/settings\/connectors\?tab=scan-jobs/);
  const job = page.getByTestId("scan-job-card").filter({ hasText: imageRef }).first();
  await expect(job).toContainText("pending");

  await job.getByTestId("scan-job-pause").click();
  await expect(job).toContainText("paused");

  await job.getByTestId("scan-job-resume").click();
  await expect(job).toContainText("pending");

  await job.getByTestId("scan-job-cancel").click();
  await expect(job).toContainText("canceled");

  await job.getByTestId("scan-job-retry").click();
  await expect(job).toContainText("pending");
});

test("Connector configuration saves metadata with external credential references", async ({ page }) => {
  await page.goto("/settings/connectors/new?type=registry");

  await expect(page.getByTestId("connector-config-editor")).toContainText("Raw credentials are never accepted");
  await page.getByTestId("connector-config-id").selectOption({ label: "GitHub Container Registry" });
  await page.getByTestId("connector-config-owner").fill("platform-security");
  await page.getByTestId("connector-config-credential-ref").fill("vault://kv/constellation/ghcr-prod");
  await page.getByTestId("connector-config-save").click();
  await expect(page).toHaveURL(/\/settings\/connectors/);
  await page.getByText("Saved connector metadata").click();

  await expect(page.getByTestId("saved-connector-configs")).toContainText("GitHub Container Registry");
  await expect(page.getByTestId("saved-connector-configs")).toContainText("vault://kv/constellation/ghcr-prod");
  await expect(page.getByTestId("saved-connector-configs")).toContainText("platform-security");
  await expect(page.getByTestId("saved-connector-config").filter({ hasText: "GitHub Container Registry" }).getByTestId("connector-config-test")).toBeVisible();
});

test("Saved connector configuration can be health tested", async ({ page }) => {
  await page.goto("/settings/connectors");
  await page.getByText("Saved connector metadata").click();

  const row = page.getByTestId("saved-connector-config").filter({ hasText: "GitHub Container Registry" });
  await expect(row).toContainText("vault://kv/constellation/ghcr-prod");
  await expect(row).toContainText(/not_tested|not tested|healthy/);

  await row.getByTestId("connector-config-test").click();

  await expect(row.getByTestId("connector-config-health")).toContainText("healthy");
  await expect(row.getByTestId("connector-config-last-test")).toContainText("last test");
  await expect(row.getByTestId("connector-config-last-test")).not.toContainText("not tested");
  await expect(row).toContainText("vault://kv/constellation/ghcr-prod");
});
