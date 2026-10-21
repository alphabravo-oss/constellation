import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { firstClusterId, settled } from "./helpers";

const PAGES: Array<[string, (id: string) => string]> = [
  ["clusters", () => "/clusters"],
  ["overview", (id) => `/clusters/${id}/dashboard`],
  ["findings", (id) => `/clusters/${id}/findings`],
  ["nodes", (id) => `/clusters/${id}/nodes`],
  ["workloads", (id) => `/clusters/${id}/deployments`],
  ["network-map", (id) => `/clusters/${id}/network`],
  ["policies", (id) => `/clusters/${id}/admission`],
  ["compliance", (id) => `/clusters/${id}/compliance`],
  ["cve-database", () => "/cve"],
  ["settings-access", () => "/settings/access"],
  ["settings-identity", () => "/settings/identity"],
];

for (const theme of ["dark", "light"] as const) {
  test.describe(`axe (${theme})`, () => {
    for (const [name, path] of PAGES) {
      test(`${name} has no serious or critical violations`, async ({ page }) => {
        await page.addInitScript((mode) => localStorage.setItem("constellation.theme", mode), theme);
        const id = await firstClusterId(page);
        await page.goto(path(id));
        await settled(page);
        const result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
        const blocking = result.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
        const summary = blocking.map((v) => `${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ")}`);
        expect(summary, summary.join("\n")).toEqual([]);
      });
    }
  });
}
