import { describe, expect, it } from "vitest";

import {
  compactTimelineFilters,
  timelineDateParam,
  timelineAfterParam,
  sameTimelineBoundary,
  timelineSavedViewSummary,
  timelineSeverityParam,
  timelineSourceParam,
  timelineTextParam,
} from "./timeline-filters";

describe("timeline filter serialization", () => {
  it("omits source and severity params for all/empty selections", () => {
    expect(timelineSourceParam(["dpi_threat", "runtime_event", "network_violation", "audit"])).toBeUndefined();
    expect(timelineSeverityParam([])).toBeUndefined();
  });

  it("orders and deduplicates selected sources and severities", () => {
    expect(timelineSourceParam(["audit", "dpi_threat", "audit"])).toBe("dpi_threat,audit");
    expect(timelineSeverityParam(["High", "critical", "high", " "])).toBe("high,critical");
  });

  it("trims text params and converts date params to RFC3339", () => {
    expect(timelineTextParam("  prod  ")).toBe("prod");
    expect(timelineTextParam("  ")).toBeUndefined();
    expect(timelineDateParam("2026-08-23T20:59")).toBe("2026-08-23T20:59:00.000Z");
    expect(timelineDateParam("not-a-date")).toBeUndefined();
  });

  it("compacts saved filters and renders a concise summary", () => {
    const payload = compactTimelineFilters({
      category: "custom",
      sources: ["runtime_event", "audit", "audit"],
      severities: ["High", "critical"],
      query: " exec ",
      namespace: " prod ",
      workload: " api ",
      reference: "",
      from: "",
      to: "",
    });

    expect(payload).toMatchObject({
      sources: ["runtime_event", "audit"],
      severities: ["high", "critical"],
      query: "exec",
      namespace: "prod",
      workload: "api",
    });
    expect(timelineSavedViewSummary(payload)).toBe("2 sources · high/critical · exec · ns:prod · workload:api");
  });
});

it("retains microsecond lower bounds and detects mismatched evidence within one millisecond",()=>{
 const after="2026-10-10T12:34:56.123456Z";expect(timelineAfterParam(after)).toBe(after);expect(sameTimelineBoundary(after,"2026-10-10T12:34:56.123455Z")).toBe(false);expect(sameTimelineBoundary(after,"2026-10-10T18:04:56.123456000+05:30")).toBe(true);
});
