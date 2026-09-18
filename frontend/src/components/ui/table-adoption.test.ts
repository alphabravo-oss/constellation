import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const operationalGrids = [
  "src/pages/NodesPage.tsx",
  "src/components/CrudPage.tsx",
  "src/pages/IntegrationsPage.tsx",
  "src/pages/baselines/BaselineDetailPage.tsx",
];

describe("TanStack table adoption", () => {
  for (const file of operationalGrids) {
    it(`${file} uses the shared DataTable instead of raw table markup`, () => {
      const source = readFileSync(resolve(process.cwd(), file), "utf8");
      expect(source).toContain("<DataTable");
      expect(source).not.toMatch(/<table\b/);
    });
  }

  it("requires every reviewed semantic table to use canonical styling", () => {
    const root = resolve(process.cwd(), "src");
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const path = resolve(dir, entry.name);
        if (entry.isDirectory()) walk(path);
        else if (entry.name.endsWith(".tsx")) files.push(path);
      }
    };
    walk(root);
    const dataTable = resolve(root, "components/ui/data-table.tsx");
    const offenders: string[] = [];
    for (const file of files) {
      if (file === dataTable || file.includes(".test.")) continue;
      const source = readFileSync(file, "utf8");
      for (const tag of source.matchAll(/<table\b[^>]*>/g)) {
        if (!tag[0].includes("app-semantic-table")) offenders.push(file);
      }
    }
    expect(offenders).toEqual([]);
  });
});
