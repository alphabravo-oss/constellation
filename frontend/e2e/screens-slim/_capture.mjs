// Standalone screenshot capture for slim sidebar (wave L1).
// Connects to the running dev server at http://localhost:5173.
import { chromium } from "@playwright/test";

const BASE = process.env.BASE_URL ?? "http://localhost:5173";
const EMAIL = "admin@dev";
const PASSWORD = "devpass123";

async function login(page) {
  await page.goto(`${BASE}/auth/login`);
  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: /^Sign in$/ }).click();
  await page.waitForURL(/\/(clusters|dashboard)/, { timeout: 15000 });
  await page.waitForLoadState("networkidle").catch(() => {});
}

async function setCollapsed(page, val) {
  await page.evaluate((v) => {
    localStorage.setItem("constellation.sidebar.collapsed", v ? "1" : "0");
  }, val);
  await page.reload();
  await page.waitForLoadState("networkidle").catch(() => {});
}

async function measureSidebar(page) {
  return await page.evaluate(() => {
    const aside = document.querySelector('aside[aria-label="Primary"]');
    const header = document.querySelector("header");
    return {
      sidebar: aside ? Math.round(aside.getBoundingClientRect().width) : null,
      header: header ? Math.round(header.getBoundingClientRect().height) : null,
      mainW: Math.round((document.querySelector("main")?.getBoundingClientRect().width) ?? 0),
    };
  });
}

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
  const page = await ctx.newPage();

  await login(page);

  // Expanded
  await setCollapsed(page, false);
  const m1 = await measureSidebar(page);
  console.log("expanded:", m1);
  await page.screenshot({
    path: "e2e/screens-slim/sidebar-expanded.png",
    fullPage: false,
  });

  // Cluster-mode expanded (verify ClusterSwitcher pill fits).
  // Grab first cluster id from DOM (look at href on Enter cluster links).
  const firstId = await page.evaluate(() => {
    const links = Array.from(document.querySelectorAll("a[href^='/clusters/']"));
    for (const a of links) {
      const m = a.getAttribute("href").match(/^\/clusters\/([^/]+)(\/|$)/);
      if (m && m[1] !== "new") return m[1];
    }
    return null;
  });
  console.log("firstId:", firstId);
  if (firstId) {
    await page.goto(`${BASE}/clusters/${firstId}/dashboard`);
    await page.waitForLoadState("networkidle").catch(() => {});
    const m3 = await measureSidebar(page);
    console.log("cluster-mode:", m3, page.url());
    await page.screenshot({ path: "e2e/screens-slim/sidebar-cluster-expanded.png" });
    // Crop to sidebar only for legibility.
    const aside = await page.locator('aside[aria-label="Primary"]');
    await aside.screenshot({ path: "e2e/screens-slim/sidebar-cluster-only.png" });
  }

  // Collapsed
  await setCollapsed(page, true);
  const m2 = await measureSidebar(page);
  console.log("collapsed:", m2);
  await page.screenshot({
    path: "e2e/screens-slim/sidebar-collapsed.png",
    fullPage: false,
  });

  await browser.close();
})().catch((err) => { console.error(err); process.exit(1); });
