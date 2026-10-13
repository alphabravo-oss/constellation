import { expect, it } from "vitest";
import {
  applyResourceView,
  captureResourceView,
  isResourceSavedView,
  resourceViewHref,
  resourceViewSummary,
  resourceViewValidator,
  type ResourceSavedView,
  type ResourceViewKind,
} from "./resource-saved-views";
const saved = (
  kind: ResourceViewKind,
  query = "",
  overrides: Record<string, string> = {},
): ResourceSavedView => ({
  ...captureResourceView(kind, new URLSearchParams(query), overrides)!,
  id: "saved",
  name: "Reviewed",
});
it.each(["assets", "deployments", "runtime", "scanner"] as ResourceViewKind[])(
  "captures validated defaults for %s and keeps context out of the stored payload",
  (kind) => {
    const view = saved(kind, "page=3&selected=exact&context=retained");
    expect(isResourceSavedView(view)).toBe(true);
    expect(Object.keys(view.filters)).not.toContain("page");
    expect(Object.keys(view.filters)).not.toContain("selected");
    expect(Object.keys(view.filters)).not.toContain("context");
    expect(resourceViewValidator(kind)(view)).toBe(true);
  },
);
it("captures Assets supported filters and applies all fields without retaining an old selection", () => {
  const view = saved(
    "assets",
    "q=tail%25_needle&kind=serverless&criticality=high&ai_workload=false&sort=asset&order=asc",
  );
  expect(view.filters).toEqual({
    q: "tail%_needle",
    kind: "serverless",
    criticality: "high",
    ai_workload: "false",
    sort: "asset",
    order: "asc",
  });
  const next = applyResourceView(
    new URLSearchParams("page=4&selected=old&context=kept&kind=image&q=old"),
    view,
  );
  expect(next.get("page")).toBeNull();
  expect(next.get("selected")).toBeNull();
  expect(next.get("context")).toBe("kept");
  expect(next.get("q")).toBe("tail%_needle");
  expect(next.get("kind")).toBe("serverless");
});
it("captures effective platform preference and legacy deployment search without inventing a sort", () => {
  const view = saved(
    "deployments",
    "name=prod%2Fapi&namespace=prod&risk_fact=net_exposure&group_mode=protect&platform_role=core",
    { hide_platform: "false" },
  );
  expect(view.filters.q).toBe("prod/api");
  expect(view.filters.hide_platform).toBe("false");
  expect(view.filters).not.toHaveProperty("sort");
  const next = applyResourceView(
    new URLSearchParams("name=other&page=2&context=retained"),
    view,
  );
  expect(next.get("name")).toBeNull();
  expect(next.get("hide_platform")).toBe("false");
  expect(next.get("risk_fact")).toBe("net_exposure");
  expect(resourceViewSummary(view)).toContain("Strongest group mode: protect");
});
it("preserves runtime nanosecond bounds/timezones and all advanced filters", () => {
  const after = "2026-10-13T01:02:03.123456789+03:00",
    before = "2026-10-13T02:02:03.123456790+03:00";
  const view = saved(
    "runtime",
    new URLSearchParams({
      tab: "live",
      q: "process",
      kind: "exec,file",
      source: "agent",
      severity: "high",
      verdict: "alert,block",
      workload: "prod/api",
      namespace: "prod",
      node: "node-a",
      after,
      before,
      sort: "workload",
      order: "asc",
    }).toString(),
  );
  const next = applyResourceView(
    new URLSearchParams("page=4&event=uuid&event_at=old&context=kept"),
    view,
  );
  expect(next.get("after")).toBe(after);
  expect(next.get("before")).toBe(before);
  expect(next.get("node")).toBe("node-a");
  expect(next.get("event")).toBeNull();
  expect(next.get("event_at")).toBeNull();
  expect(next.get("context")).toBe("kept");
});
it("captures global Scanner job filters with explicit cluster/registry scopes", () => {
  const view = saved(
    "scanner",
    "q=worker&status=failed&target_type=image&cluster_id=11111111-1111-4111-8111-111111111111&registry_id=22222222-2222-4222-8222-222222222222&sort=attempts&order=asc",
  );
  expect(view.filters.tab).toBe("jobs");
  expect(view.filters.registry_id).toBe("22222222-2222-4222-8222-222222222222");
  expect(
    resourceViewHref(
      "scanner",
      undefined,
      new URLSearchParams("page=3&selected=job&context=keep"),
      "#attempts",
      true,
    ),
  ).toBe(
    "/settings/scanner/views/new?page=3&selected=job&context=keep#attempts",
  );
});
it.each([
  ["assets", "kind=unknown"],
  ["assets", "sort=sql"],
  ["assets", "ai_workload=maybe"],
  ["assets", "q=one&q=two"],
  ["deployments", "group_mode=all"],
  ["deployments", "risk_fact=unknown"],
  ["deployments", "hide_platform=maybe"],
  ["runtime", "tab=evidence"],
  ["runtime", "after=garbage"],
  ["runtime", "verdict=allow"],
  ["runtime", "after=2026-10-13T01:00:00Z&before=2026-10-13T00:00:00Z"],
  ["scanner", "status=healthy"],
  ["scanner", "cluster_id=invalid"],
  ["scanner", "tab=workers"],
  ["scanner", "order=sideways"],
] as Array<[ResourceViewKind, string]>)(
  "rejects invalid %s capture %s",
  (kind, query) =>
    expect(captureResourceView(kind, new URLSearchParams(query))).toBeNull(),
);
it("rejects incompatible inventory, unknown keys and malformed stored payloads", () => {
  const asset = saved("assets");
  expect(resourceViewValidator("runtime")(asset)).toBe(false);
  expect(
    isResourceSavedView({
      ...asset,
      filters: { ...asset.filters, unexpected: "broadening" },
    }),
  ).toBe(false);
  expect(isResourceSavedView({ ...asset, filters: [] })).toBe(false);
  expect(isResourceSavedView({ ...asset, schema: 2 })).toBe(false);
  expect(isResourceSavedView(null)).toBe(false);
});
it("keeps return page, selection, repeated context and hash in the dedicated canonical route", () => {
  const href = resourceViewHref(
    "assets",
    "cluster",
    new URLSearchParams("page=3&selected=id&context=one&context=two"),
    "#evidence",
    true,
  );
  expect(href).toBe(
    "/clusters/cluster/assets/views/new?page=3&selected=id&context=one&context=two#evidence",
  );
});
