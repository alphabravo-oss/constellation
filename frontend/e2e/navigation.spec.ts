import { test, expect, type Page } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

// Routes mapped to the IA group that contains them in the redesigned AppShell.
// Sidebar groups are flat sections (Posture / Runtime / Supply Chain / Ops);
// all items in a group are visible without an accordion toggle.
const ROUTES: { label: string; heading: RegExp }[] = [
  { label: "Dashboard",      heading: /Posture|Security|Dashboard/i },
  { label: "Findings",       heading: /^Findings$/i },
  { label: "Assets",         heading: /^Assets$/i },
  { label: "Compliance",     heading: /^Compliance$/i },
  { label: "Exceptions",     heading: /Vulnerability Exceptions/i },
  { label: "CVE DB",         heading: /CVE/i },
  { label: "Network Map",    heading: /^Network/i },
  { label: "Runtime",        heading: /^Runtime$/i },
  { label: "Response Rules", heading: /Response Rules/i },
  { label: "Federation",     heading: /Federation/i },
  { label: "Policies",       heading: /^Policies$/i },
  { label: "Clusters",       heading: /^Clusters$/i },
  { label: "System Health",  heading: /System Health/i },
  { label: "Audit Log",      heading: /Audit/i },
  { label: "Coverage",       heading: /Coverage/i },
  { label: "Access Control", heading: /Access Control/i },
];

async function clickNav(page: Page, linkLabel: string) {
  const nav = page.locator("nav").first();
  await nav.waitFor({ state: "visible" });
  await nav.getByRole("link", { name: linkLabel, exact: true }).first().click();
}

test.describe("Sidebar navigation — routes", () => {
  for (const { label, heading } of ROUTES) {
    test(`opens ${label}`, async ({ page }) => {
      await page.goto("/dashboard");
      await clickNav(page, label);
      await expect(page.getByRole("heading", { name: heading }).first()).toBeVisible({ timeout: 5000 });
    });
  }
});

test("theme toggle switches dark <-> light", async ({ page }) => {
  await page.goto("/dashboard");
  const html = page.locator("html");
  const before = await html.getAttribute("class");
  // The header toggle has aria-label "Switch to light theme" or "Switch to dark theme".
  await page.getByRole("button", { name: /Switch to (light|dark) theme/i }).click();
  await expect(html).not.toHaveAttribute("class", before ?? "");
});

test("logout returns to /auth/login", async ({ page }) => {
  await page.goto("/dashboard");
  // The user menu trigger shows the user email; clicking it opens a dropdown
  // with a "Sign out" item.
  await page.getByRole("button", { name: /admin@/ }).first().click();
  await page.getByRole("menuitem", { name: /Sign out/i }).click();
  await expect(page).toHaveURL(/\/auth\/login/);
});
