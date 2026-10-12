import { expect, it } from "vitest";
import { findingViewPayload, timelineViewPayload, isFindingSavedView, isTimelineSavedView, inventoryViewHref } from "./inventory-saved-views";
it("captures complete Findings filter state without persisting page or selection context", () => {
  expect(findingViewPayload(new URLSearchParams("kind=runtime&lifecycle=all&severity=high&fixable=1&q=api&view=cve&group=asset&sort=title&order=asc&page=9&context=keep"))).toEqual({ kind: "runtime", lifecycle: "", severity: "high", fixable: true, query: "api", view: "instances", group: "asset", sort: "title", order: "asc" });
});
it.each(["kind=invalid", "lifecycle=invalid", "severity=urgent", "fixable=maybe", "view=invalid", "group=invalid", "sort=unknown", "order=random"])("rejects invalid Findings authoring context %s", raw => { expect(findingViewPayload(new URLSearchParams(raw))).toBeNull(); });
it("keeps legacy Findings views usable but rejects malformed payload fields", () => {
  const legacy = { kind: "vulnerability", lifecycle: "open", query: "kev:true" };
  expect(isFindingSavedView(legacy)).toBe(true);
  for (const bad of [{ ...legacy, kind: [] }, { ...legacy, query: 1 }, { ...legacy, fixable: "true" }, { ...legacy, view: {} }]) expect(isFindingSavedView(bad)).toBe(false);
});
it("captures timeline category sources and every advanced filter", () => {
  expect(timelineViewPayload(new URLSearchParams("tab=custom&type=runtime_event,audit&severity=critical,high&q=api&namespace=prod&workload=web&ref=rule&from=2026-10-10T00:00&to=2026-10-12T00:00&page=3&event=audit:1"))).toEqual({ category: "custom", sources: ["runtime_event", "audit"], severities: ["critical", "high"], query: "api", namespace: "prod", workload: "web", reference: "rule", from: "2026-10-10T00:00", to: "2026-10-12T00:00" });
  expect(timelineViewPayload(new URLSearchParams("tab=custom&type=none"))?.sources).toEqual([]);
});
it.each(["tab=invalid", "tab=custom&type=invalid", "severity=urgent", "from=garbage", "from=2026-10-12&to=2026-10-10"])("rejects invalid timeline authoring context %s", raw => { expect(timelineViewPayload(new URLSearchParams(raw))).toBeNull(); });
it("rejects malformed or contradictory saved timeline payloads", () => {
  const valid = timelineViewPayload(new URLSearchParams("tab=activity"))!;
  expect(isTimelineSavedView(valid)).toBe(true);
  for (const bad of [{ ...valid, sources: "runtime_event" }, { ...valid, sources: ["audit"] }, { ...valid, severities: [null] }, { ...valid, query: null }, { ...valid, from: [] }]) expect(isTimelineSavedView(bad)).toBe(false);
});
it("builds canonical form and return links preserving query, page, unknown context and hash", () => {
  const params = new URLSearchParams("q=api&page=2&event=runtime_event:1&context=keep&returnTo=https://evil.test");
  expect(inventoryViewHref("cluster", "timeline", params, "#evidence", true)).toBe(`/clusters/cluster/timeline/views/new?${params}#evidence`);
  expect(inventoryViewHref("cluster", "timeline", params, "evidence")).toBe(`/clusters/cluster/timeline?${params}#evidence`);
});

it("captures exact target cohorts and rejects malformed target filters without breaking legacy views", () => {
 const captured = findingViewPayload(new URLSearchParams("target_type=image-workload&view=instances&kind=vulnerability"));
 expect(captured?.targetType).toBe("image-workload"); expect(isFindingSavedView(captured)).toBe(true);
 expect(findingViewPayload(new URLSearchParams("target_type=image-workload-extra"))).toBeNull();
 expect(isFindingSavedView({ kind: "", lifecycle: "open", query: "", targetType: [] })).toBe(false);
});
