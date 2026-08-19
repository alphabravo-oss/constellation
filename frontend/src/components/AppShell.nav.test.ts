import { describe, expect, it } from "vitest";
import { CLUSTER_NAV } from "./AppShell";

// FE-1 guard: these three pages used to be orphaned — wired to routes in App.tsx
// but absent from the sidebar (and command palette). If a future regroup drops
// them from CLUSTER_NAV, they become unreachable again and this test fails.
describe("CLUSTER_NAV reachability", () => {
  const paths = CLUSTER_NAV.flatMap((g) => g.items.map((i) => i.path));

  it("includes the previously orphaned cluster-scoped pages", () => {
    for (const p of ["runtime-policies", "response"]) {
      expect(paths).toContain(p);
    }
  });
});
