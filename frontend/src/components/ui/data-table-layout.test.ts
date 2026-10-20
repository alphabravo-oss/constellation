import { createElement } from "react";
import { describe, expect, it } from "vitest";
import { COLUMN_KINDS, computeColumnWidths, headerFloor, parsePx, resolveColumnLayout, type ColumnLayoutInput, type ResolvedColumnLayout } from "./data-table-layout";
const column = (id: string, extra: Partial<ColumnLayoutInput> = {}): ColumnLayoutInput => ({ id, header: id, sortable: false, ...extra });
const layout = (id: string, extra: Partial<ColumnLayoutInput> = {}) => resolveColumnLayout(column(id, extra));
const bounded = (minSize: number, maxSize?: number): ResolvedColumnLayout => ({ sized: true, minSize, maxSize, grow: true, align: "left", overflow: "truncate", mono: false, numeric: false });

describe("semantic column contracts", () => {
  it("gives only names flexible width and keeps all preferred sizes within their bounds", () => {
    expect(Object.keys(COLUMN_KINDS)).toHaveLength(12);
    expect(Object.entries(COLUMN_KINDS).filter(([, spec]) => spec.grow).map(([kind]) => kind)).toEqual(["name"]);
    for (const spec of Object.values(COLUMN_KINDS)) { expect(spec.size).toBeGreaterThanOrEqual(spec.minSize); if (spec.maxSize !== undefined) expect(spec.size).toBeLessThanOrEqual(spec.maxSize); }
  });
  it("right-aligns counts, percentages and byte sizes, while dates and status stay left aligned", () => {
    for (const kind of ["count", "percent", "bytes"] as const) expect(layout(kind, { kind })).toMatchObject({ align: "right", numeric: true, overflow: "nowrap" });
    for (const kind of ["status", "date", "age", "version"] as const) expect(layout(kind, { kind })).toMatchObject({ align: "left", overflow: "nowrap" });
    expect(layout("id", { kind: "id" })).toMatchObject({ mono: true, overflow: "middle" });
    expect(layout("text", { kind: "text" }).overflow).toBe("wrap-2");
  });
  it("fits inline edit/delete controls while allowing a compact overflow-only override", () => {
    expect(layout("actions", { kind: "actions" })).toMatchObject({ size: 112, minSize: 112, overflow: "fixed", align: "right" });
    expect(layout("actions", { kind: "actions", size: 48, minSize: 48, maxSize: 48 })).toMatchObject({ size: 48, minSize: 48, maxSize: 48 });
  });
  it("keeps legacy tables native and supplies text sizing only when the caller opts into it", () => {
    expect(layout("legacy")).toMatchObject({ sized: false, size: undefined, minSize: 0, grow: false, align: "left", overflow: "legacy" });
    expect(resolveColumnLayout(column("legacy"), { defaultKind: "text" })).toMatchObject({ kind: "text", sized: true, size: 200, grow: false, overflow: "wrap-2" });
    expect(layout("legacy", { numeric: true })).toMatchObject({ sized: false, align: "right", numeric: true });
  });
  it("honors explicit layout overrides and a legacy width before the kind's preferred size", () => {
    expect(layout("Name", { kind: "name", size: 210, minSize: 140, maxSize: 230, grow: false, align: "center", overflow: "wrap" })).toMatchObject({ size: 210, minSize: 140, maxSize: 230, grow: false, align: "center", overflow: "wrap" });
    const fixed = layout("Name", { kind: "name", width: "12rem" }); expect(fixed).toMatchObject({ cssWidth: "12rem", size: undefined, grow: false }); expect(computeColumnWidths([fixed], 900)).toEqual([192]);
    expect(layout("text", { kind: "text", wrap: true }).overflow).toBe("wrap");
  });
  it("reserves enough width for header labels and sort icons, including composite header text", () => {
    const label = "Configured state"; expect(headerFloor(column(label, { sortable: true }))).toBe(label.length * 7 + 56);
    expect(headerFloor(column(label, { sortable: false }))).toBe(label.length * 7 + 32);
    expect(headerFloor(column("x", { header: createElement("span", null, "State") }))).toBe(67);
    expect(headerFloor(column("x", { header: null, headerLabel: "Full label" }))).toBe(102);
    const long = layout(label, { kind: "count", sortable: true, size: 80, maxSize: 100 }); expect(long.minSize).toBe(168); expect(long.size).toBe(168); expect(long.maxSize).toBe(168);
    expect(headerFloor(column("actions", { kind: "actions" }))).toBe(0);
  });
  it("supports compact age widths without forcing the roomy default", () => { expect(layout("Seen", { kind: "age", size: 84 }).size).toBe(84); });
});

describe("column width distribution", () => {
  it("lets the identity column grow without turning status/count/actions into equal columns", () => {
    const resolved = [layout("Name", { kind: "name" }), layout("Status", { kind: "status" }), layout("Count", { kind: "count" }), layout("", { kind: "actions" })];
    expect(computeColumnWidths(resolved, 900)).toEqual([588, 120, 80, 112]);
  });
  it("shrinks fixed columns before violating the name minimum and scrolls below all minimums", () => {
    const resolved = [layout("Name", { kind: "name" }), layout("Status", { kind: "status" }), layout("Count", { kind: "count" }), layout("", { kind: "actions" })];
    const narrow = computeColumnWidths(resolved, 440); expect(narrow.reduce((sum, width) => sum + width, 0)).toBeCloseTo(440); expect(narrow[0]).toBe(160); expect(narrow.every((width, i) => width >= resolved[i].minSize)).toBe(true);
    const phone = computeColumnWidths(resolved, 200); expect(phone).toEqual([160, 96, 67, 112]); expect(phone.reduce((sum, width) => sum + width, 0)).toBeGreaterThan(200);
  });
  it("redistributes flexible width correctly when some columns hit a minimum or maximum", () => {
    expect(computeColumnWidths([bounded(240), bounded(0, 180)], 400)).toEqual([240, 160]);
    expect(computeColumnWidths([bounded(0, 100), bounded(50)], 400)).toEqual([100, 300]);
    expect(computeColumnWidths([bounded(240), bounded(200)], 100)).toEqual([240, 200]);
  });
  it("does not widen structural columns when a table has no growing identity column", () => { expect(computeColumnWidths([layout("", { kind: "actions" }), layout("Count", { kind: "count" })], 800)).toEqual([112, 80]); });
  it("keeps native percentages opaque instead of misreading them as pixels", () => {
    expect(parsePx("140px")).toBe(140); expect(parsePx("8.5rem")).toBe(136); expect(parsePx("100")).toBe(100); expect(parsePx("20%")).toBeUndefined(); expect(parsePx("calc(100% - 2rem)")).toBeUndefined(); expect(parsePx("-20px")).toBeUndefined();
    const percent = layout("Name", { width: "30%" }); expect(percent.cssWidth).toBe("30%"); expect(percent.sized).toBe(false); expect(() => computeColumnWidths([percent], 800)).toThrow(/native table layout/);
  });
  it("handles empty and initially unmeasured tables without inventing widths", () => { expect(computeColumnWidths([], 0)).toEqual([]); expect(computeColumnWidths([layout("Name", { kind: "name" })], 0)).toEqual([160]); expect(() => computeColumnWidths([], -1)).toThrow(RangeError); });
});
