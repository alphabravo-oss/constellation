import { test, expect } from "@playwright/test";
import { login } from "./utils";

const clusterId = "11111111-1111-4111-8111-111111111111";
const root = `/clusters/${clusterId}/compliance`;

test.describe("Compliance controls and exemption pages", () => {
  test.beforeEach(async ({ page }) => {
    await page.route("**/api/v1/**", async (route) => {
      const path = new URL(route.request().url()).pathname.replace(/^\/api\/v1/, "");
      let body: unknown;
      if (path === "/auth/me") body = { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] };
      else if (path === "/clusters") body = { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] };
      else if (path === "/compliance/frameworks") body = { frameworks: [{ id: "cis-k8s-1.9", name: "CIS Kubernetes 1.9", category: "kubernetes" }, { id: "gdpr", name: "GDPR", category: "regulatory-eu" }] };
      else if (path === "/compliance/summary") body = { frameworks: [{ framework: "cis-k8s-1.9", total: 1, pass: 0, fail: 1, manual: 0, exempted: 0, pass_pct: 0 }] };
      else if (path === "/compliance/checks") {
        const params = new URL(route.request().url()).searchParams;
        expect(params.get("cluster_id")).toBe(clusterId);
        const framework = params.get("framework") || "cis-k8s-1.9";
        body = { checks: [{ id: `check-${framework}`, cluster_id: clusterId, framework, control_id: "1.2", title: "Restrict control-plane permissions", status: "fail", effective_status: "fail", severity: "high", evidence: "Fixture evidence" }], cluster_id: clusterId, framework, status: params.get("status") || "", profile: params.get("profile") || "", control_id: params.get("control_id") || "", q: params.get("q") || "", sort: params.get("sort") || "control", order: params.get("order") || "asc", limit: Number(params.get("limit") || 100), offset: Number(params.get("offset") || 0), total: 1, has_more: false, summary: { total: 1, pass: 0, fail: 1, manual: 0, not_applicable: 0, exempted: 0, graded: 1, ungraded: 0 } };
      }
      else if (path === "/compliance/exemptions" && route.request().method() === "POST") { await route.fulfill({ status: 503, json: { error: "Fixture save failure" } }); return; }
      else if (path === "/compliance/exemptions") body = { exemptions: [] };
      else { await route.fulfill({ status: 404, json: { error: `Unmocked ${path}` } }); return; }
      await route.fulfill({ json: body });
    });
  });

  test("Framework selection is URL-backed and opens one controls workspace", async ({ page }) => {
    await page.goto(`${root}?framework=cis-k8s-1.9&filter=auditors`);
    await expect(page.getByLabel("Framework", { exact: true })).toBeVisible();
    await expect(page.locator('optgroup[label="kubernetes"]')).toHaveCount(1);
    await expect(page.locator('optgroup[label="regulatory-eu"]')).toHaveCount(1);
    await expect(page.getByTestId("compliance-controls-table")).toContainText("Restrict control-plane permissions");
    await expect(page.locator("form")).toHaveCount(0);
    await page.getByLabel("Framework", { exact: true }).selectOption("gdpr");
    await expect(page).toHaveURL(`${root}?framework=gdpr&filter=auditors`);
    await page.goBack();
    await expect(page.getByLabel("Framework", { exact: true })).toHaveValue("cis-k8s-1.9");
  });

  test("Exemption creation has a dedicated URL and retains failed approval drafts", async ({ page }) => {
    await page.goto(`${root}?framework=cis-k8s-1.9&filter=auditors`);
    await page.getByRole("button", { name: "Exempt", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/compliance/exemptions/new`));
    await expect(page.getByRole("heading", { name: "New compliance exemption" })).toBeVisible();
    await page.getByRole("textbox", { name: /^Reason/ }).fill("Approved compensating controls");
    await page.getByRole("button", { name: "Create exemption", exact: true }).click();
    await expect(page.getByRole("alert").filter({ hasText: "Your draft is preserved" })).toBeVisible();
    await expect(page.getByRole("textbox", { name: /^Reason/ })).toHaveValue("Approved compensating controls");
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(page).toHaveURL(`${root}?framework=cis-k8s-1.9&filter=auditors&tab=frameworks`);
    await expect(page.locator("form")).toHaveCount(0);
  });
});

test.describe("Policy catalog", () => {
  test.beforeEach(async ({ page }) => { await login(page); });
test("Policies page renders the primary catalog table", async ({ page }) => {
  await page.goto("/policies");
  // The seed has 1 policy; the rail should render it.
  await expect(page.getByTestId("policy-catalog-table")).toBeVisible();
  await expect(page.getByTestId("policy-row-block-unsigned-images")).toBeVisible();
});

test("Policies page dry-runs admission decisions before enforcement", async ({ page }) => {
  await page.goto("/policies");
  await page.getByRole("tab", { name: /Admission simulator/i }).click();

  await expect(page.getByTestId("policy-simulator")).toBeVisible();
  const previewResponse = page.waitForResponse(response => response.url().includes("/api/v1/policies/simulate") && response.request().method() === "POST");
  await page.getByTestId("policy-simulator-run").click();
  expect((await (await previewResponse).json()).admission_review).toMatchObject({ dry_run: true, sends_webhook: false, persists_decision: false });

  await expect(page.getByTestId("policy-simulator-results")).toContainText("deny");
  await expect(page.getByTestId("policy-simulator-results")).toContainText("Pod/privileged-debug");
  await expect(page.getByTestId("policy-simulator-results")).toContainText("block-unsigned-images");
  await expect(page.getByTestId("policy-simulator-guardrails")).toContainText("Manifest redaction");
  await expect(page.getByTestId("policy-simulator-guardrails")).toContainText("Monitor before enforce");
  await expect(page.getByTestId("policy-simulator-guardrails")).toContainText("Dry-run only");
});

});
