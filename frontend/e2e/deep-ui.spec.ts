// deep-ui.spec.ts — exhaustive UI smoke + diagnostics walk for every page in
// the Constellation web app. Logs into the running dev server (5173), visits
// each top-nav page, screenshots it, and captures console + network errors to
// frontend/e2e/diagnostics.md. Specifically exercises the new Wave C / Wave D
// pages (PolicyWizard, RiskDetail, CVEDetail, ScopeBar, Response Rules, Vuln
// Profiles, Groups, WAF, DLP, Federation).
import { test, expect, type Page, type ConsoleMessage, type Request, type Response } from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import { getAuthToken, login } from "./utils";

const API = process.env.VITE_API_URL ?? "http://localhost:18080";
const SCREENS_DIR = path.resolve(process.cwd(), "e2e/screens");
const DIAG_PATH = path.resolve(process.cwd(), "e2e/diagnostics.md");

interface PageDiag {
  page: string;
  url: string;
  mounted: boolean;
  data: "yes" | "empty" | "n/a" | "error";
  consoleErrors: string[];
  failedRequests: Array<{ url: string; status: number; method: string }>;
  notes: string[];
}

const diagnostics: PageDiag[] = [];

async function programmaticLogin(page: Page) {
  await login(page);
}

function attachDiagnostics(page: Page, diag: PageDiag) {
  page.on("console", (msg: ConsoleMessage) => {
    if (msg.type() === "error") {
      const text = msg.text();
      // Skip noisy chunks unrelated to the app
      if (text.includes("Failed to load resource")) return; // covered by response listener
      diag.consoleErrors.push(text);
    }
  });
  page.on("pageerror", (err: Error) => {
    diag.consoleErrors.push(`pageerror: ${err.message}`);
  });
  page.on("requestfailed", (req: Request) => {
    const url = req.url();
    if (!url.includes("/api/")) return;
    diag.failedRequests.push({ url, status: 0, method: req.method() });
  });
  page.on("response", (resp: Response) => {
    const url = resp.url();
    if (!url.includes("/api/")) return;
    if (resp.status() >= 400) {
      diag.failedRequests.push({ url, status: resp.status(), method: resp.request().method() });
    }
  });
}

async function gotoAndShoot(page: Page, route: string, slug: string, diag: PageDiag) {
  await page.goto(route).catch((e) => { diag.notes.push(`goto failed: ${e.message}`); });
  // wait for some content; tolerate slow renders
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
  await page.waitForTimeout(400);
  const heading = await page.locator("h1").first().textContent().catch(() => null);
  diag.mounted = !!heading && heading.trim().length > 0;
  await fs.mkdir(SCREENS_DIR, { recursive: true });
  await page.screenshot({ path: path.join(SCREENS_DIR, `${slug}.png`), fullPage: true }).catch(() => {});
}

function newDiag(name: string, url: string): PageDiag {
  const d: PageDiag = {
    page: name, url, mounted: false, data: "n/a",
    consoleErrors: [], failedRequests: [], notes: [],
  };
  diagnostics.push(d);
  return d;
}

test.describe.configure({ mode: "serial" });

test.beforeEach(async ({ page }) => {
  await programmaticLogin(page);
});

// -------- single-page smoke tests --------

const SIMPLE_PAGES: Array<{ name: string; route: string; slug: string; expectRows?: boolean }> = [
  { name: "Dashboard",          route: "/dashboard",          slug: "dashboard" },
  { name: "Findings",           route: "/findings",           slug: "findings",       expectRows: true },
  { name: "Assets",             route: "/assets",             slug: "assets",         expectRows: true },
  { name: "Clusters",           route: "/clusters",           slug: "clusters" },
  { name: "Policies",           route: "/policies",           slug: "policies" },
  { name: "Compliance",         route: "/compliance",         slug: "compliance" },
  { name: "Exceptions",         route: "/exceptions",         slug: "exceptions" },
  { name: "Runtime",            route: "/runtime",            slug: "runtime" },
  { name: "Response (legacy)",  route: "/response",           slug: "response" },
  { name: "Response Rules",    route: "/response-rules",     slug: "response-rules", expectRows: true },
  { name: "Vuln Profiles",      route: "/vuln-profiles",      slug: "vuln-profiles",  expectRows: true },
  { name: "Groups",             route: "/groups",             slug: "groups",         expectRows: true },
  { name: "WAF Rules",          route: "/waf",                slug: "waf",            expectRows: true },
  { name: "DLP Sensors",        route: "/dlp",                slug: "dlp",            expectRows: true },
  { name: "Network Map",        route: "/network",            slug: "network" },
  { name: "Federation",         route: "/federation",         slug: "federation" },
  { name: "CVE DB",             route: "/cve",                slug: "cve" },
  { name: "Audit",              route: "/audit",              slug: "audit" },
  { name: "Coverage",           route: "/coverage",           slug: "coverage" },
  { name: "System Health",      route: "/system-health",      slug: "system-health" },
  { name: "Access Control",     route: "/access-control",     slug: "access-control" },
  { name: "Deployments (Risk)", route: "/deployments",        slug: "deployments",    expectRows: true },
  { name: "Settings",           route: "/settings",           slug: "settings" },
  { name: "Integrations",       route: "/settings/integrations", slug: "settings-integrations" },
  { name: "Connectors",         route: "/settings/connectors",   slug: "settings-connectors" },
];

for (const p of SIMPLE_PAGES) {
  test(`page: ${p.name}`, async ({ page }) => {
    const diag = newDiag(p.name, p.route);
    attachDiagnostics(page, diag);
    await gotoAndShoot(page, p.route, p.slug, diag);

    // Detect presence of any data row or "empty" state
    const tbody = page.locator("tbody tr");
    const count = await tbody.count().catch(() => 0);
    const bodyText = (await page.locator("body").textContent().catch(() => ""))?.toLowerCase() ?? "";
    const hasEmptyState = /no .* yet|none yet|no findings|no data|no rows|no policies|no checks|no integrations|none observed/.test(bodyText);
    if (count > 0) diag.data = "yes";
    else if (hasEmptyState) diag.data = "empty";

    // Bare-minimum mount check: an h1 exists.
    expect(diag.mounted, `${p.name} should mount with a heading`).toBeTruthy();
  });
}

// -------- detail page traversals --------

test("detail: findings -> finding detail", async ({ page }) => {
  const diag = newDiag("FindingDetail", "/findings/:id");
  attachDiagnostics(page, diag);
  await page.goto("/findings");
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
  const firstRowLink = page.locator("tbody tr a").first();
  const linkCount = await firstRowLink.count();
  if (linkCount === 0) {
    diag.notes.push("no row link to follow");
    return;
  }
  await firstRowLink.click().catch((e) => diag.notes.push(`click: ${e.message}`));
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
  await page.screenshot({ path: path.join(SCREENS_DIR, `finding-detail.png`), fullPage: true });
  const heading = await page.locator("h1").first().textContent();
  diag.mounted = !!heading;
  diag.data = "yes";
});

test("detail: assets -> asset detail", async ({ page }) => {
  const diag = newDiag("AssetDetail", "/assets/:id");
  attachDiagnostics(page, diag);
  await page.goto("/assets");
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
  const firstRowLink = page.locator("tbody tr a").first();
  if (await firstRowLink.count() === 0) { diag.notes.push("no asset row"); return; }
  await firstRowLink.click().catch((e) => diag.notes.push(`click: ${e.message}`));
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
  await page.screenshot({ path: path.join(SCREENS_DIR, `asset-detail.png`), fullPage: true });
  diag.mounted = !!(await page.locator("h1").first().textContent());
  diag.data = "yes";
});

test("detail: deployments -> deployment detail", async ({ page }) => {
  const diag = newDiag("DeploymentDetail", "/deployments/:id");
  attachDiagnostics(page, diag);
  await page.goto("/deployments");
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
  const firstRowLink = page.locator("tbody tr a").first();
  if (await firstRowLink.count() === 0) { diag.notes.push("no deployment row"); return; }
  await firstRowLink.click().catch((e) => diag.notes.push(`click: ${e.message}`));
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
  await page.screenshot({ path: path.join(SCREENS_DIR, `deployment-detail.png`), fullPage: true });
  diag.mounted = !!(await page.locator("h1").first().textContent());
  diag.data = "yes";
});

// -------- Wave C: PolicyWizard, RiskDetail, CVEDetail, ScopeBar --------

test("wave-c: PolicyWizard walks all 6 steps", async ({ page }) => {
  const diag = newDiag("PolicyWizard", "/policies/new");
  attachDiagnostics(page, diag);
  await page.goto("/policies/new");
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});

  // Identity
  await page.getByTestId("wizard-name").fill("e2e-test-policy");
  await page.screenshot({ path: path.join(SCREENS_DIR, "wizard-1-identity.png"), fullPage: true });
  await page.getByTestId("wizard-next").click();

  // Scope
  await expect(page.getByTestId("wizard-step-Scope")).toBeVisible();
  await page.screenshot({ path: path.join(SCREENS_DIR, "wizard-2-scope.png"), fullPage: true });
  await page.getByTestId("wizard-next").click();

  // Criteria — must add at least one criterion to advance
  await expect(page.getByTestId("wizard-step-Criteria")).toBeVisible();
  await page.getByTestId("criteria-add").click().catch((e) => diag.notes.push(`criteria-add: ${e.message}`));
  await page.screenshot({ path: path.join(SCREENS_DIR, "wizard-3-criteria.png"), fullPage: true });
  await page.getByTestId("wizard-next").click();

  // Exclusions
  await expect(page.getByTestId("wizard-step-Exclusions")).toBeVisible();
  await page.screenshot({ path: path.join(SCREENS_DIR, "wizard-4-exclusions.png"), fullPage: true });
  await page.getByTestId("wizard-next").click();

  // Actions
  await expect(page.getByTestId("wizard-step-Actions")).toBeVisible();
  await page.screenshot({ path: path.join(SCREENS_DIR, "wizard-5-actions.png"), fullPage: true });
  await page.getByTestId("wizard-next").click();

  // Review
  await expect(page.getByTestId("wizard-step-Review")).toBeVisible();
  await page.screenshot({ path: path.join(SCREENS_DIR, "wizard-6-review.png"), fullPage: true });
  diag.mounted = true;
  diag.data = "yes";
});

test("wave-c: RiskDetail tabs all render", async ({ page }) => {
  const diag = newDiag("RiskDetail", "/risk/asset/:id");
  attachDiagnostics(page, diag);
  // Pull an asset id to feed risk page (login + fetch via request context, no DOM access).
  // NB: the underlying risk/OverviewTab only knows entityType=asset|finding — passing
  // 'deployment' would 404 against /assets/<deployment-uuid>.
  const token = await getAuthToken(page);
  const list = await page.request.get(`${API}/api/v1/assets`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const j = await list.json();
  const id = j.assets?.[0]?.id ?? "missing";
  await page.goto(`/risk/asset/${id}`);
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
  diag.mounted = !!(await page.getByTestId("risk-detail-page").count());
  const tabs = ["Overview", "Findings", "Network", "Process", "Compliance"];
  for (const t of tabs) {
    await page.getByRole("tab", { name: t }).click().catch((e) => diag.notes.push(`tab ${t}: ${e.message}`));
    await page.waitForTimeout(300);
    await page.screenshot({ path: path.join(SCREENS_DIR, `risk-tab-${t.toLowerCase()}.png`), fullPage: true });
  }
  diag.data = "yes";
});

test("wave-c: CVEDetail page", async ({ page }) => {
  const diag = newDiag("CVEDetail", "/cve/:id");
  attachDiagnostics(page, diag);
  await page.goto("/cve/CVE-2024-3094");
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
  diag.mounted = !!(await page.getByTestId("cve-detail-page").count());
  await page.screenshot({ path: path.join(SCREENS_DIR, "cve-detail.png"), fullPage: true });
  diag.data = "yes";
});

test("wave-c: ScopeBar persists a filter", async ({ page }) => {
  const diag = newDiag("ScopeBar", "/timeline");
  attachDiagnostics(page, diag);
  await page.goto("/timeline");
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
  const scopeBar = page.getByTestId("scope-bar");
  await expect(scopeBar).toBeVisible();
  // Click "Cluster" chip
  await scopeBar.getByRole("button", { name: /Cluster/ }).click();
  await scopeBar.locator("input[placeholder='all clusters']").fill("prod-us-east-1");
  await scopeBar.locator("input[placeholder='all clusters']").press("Enter");
  await page.waitForTimeout(300);
  // URL should contain ?cluster=prod-us-east-1
  expect(page.url()).toMatch(/cluster=/);
  await page.screenshot({ path: path.join(SCREENS_DIR, "scopebar-filter.png"), fullPage: true });
  // Reload — should still have the chip selected
  await page.reload();
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
  expect(page.url()).toMatch(/cluster=/);
  diag.mounted = true;
  diag.data = "yes";
});

// -------- Wave D: Response Rules guided create --------

test("wave-d: ResponseRules guided create", async ({ page }) => {
  const diag = newDiag("ResponseRules-create", "/response-rules");
  attachDiagnostics(page, diag);
  await page.goto("/response-rules");
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
  await page.getByRole("button", { name: /New rule/i }).click();
  // Use a unique name based on timestamp
  const name = `e2e-rule-${Date.now()}`;
  await expect(page.getByRole("heading", { name: "New rule" })).toBeVisible();
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Description").fill("Created by the deep-ui smoke test");
  await page.screenshot({ path: path.join(SCREENS_DIR, "rrv2-builder.png"), fullPage: true });
  await page.getByRole("button", { name: /Save/ }).click();
  await expect(page.getByTestId("response-rules-page")).toContainText(name, { timeout: 5000 });
  diag.data = "yes";
  diag.mounted = true;
});

// -------- finalize: write diagnostics.md --------

test.afterAll(async () => {
  const lines: string[] = [];
  lines.push("# Constellation deep-ui diagnostics");
  lines.push("");
  lines.push(`Run at ${new Date().toISOString()}`);
  lines.push("");
  lines.push("## Page summary");
  lines.push("");
  lines.push("| Page | URL | Mounted | Data | Console errors | Failed /api requests |");
  lines.push("| --- | --- | --- | --- | --- | --- |");
  for (const d of diagnostics) {
    lines.push(
      `| ${d.page} | \`${d.url}\` | ${d.mounted ? "yes" : "**NO**"} | ${d.data} | ${d.consoleErrors.length} | ${d.failedRequests.length} |`,
    );
  }
  lines.push("");
  lines.push("## Details");
  for (const d of diagnostics) {
    if (d.consoleErrors.length === 0 && d.failedRequests.length === 0 && d.notes.length === 0) continue;
    lines.push("");
    lines.push(`### ${d.page} (\`${d.url}\`)`);
    if (d.notes.length) {
      lines.push("**notes:**");
      for (const n of d.notes) lines.push(`- ${n}`);
    }
    if (d.consoleErrors.length) {
      lines.push("**console errors:**");
      for (const e of d.consoleErrors.slice(0, 10)) lines.push(`- \`${e.replace(/\n/g, " ").slice(0, 240)}\``);
    }
    if (d.failedRequests.length) {
      lines.push("**failed /api requests:**");
      for (const f of d.failedRequests.slice(0, 20)) lines.push(`- ${f.method} ${f.status} ${f.url}`);
    }
  }
  await fs.writeFile(DIAG_PATH, lines.join("\n"));
});
