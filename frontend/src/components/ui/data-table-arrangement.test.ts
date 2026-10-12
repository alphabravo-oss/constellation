import { describe, expect, it } from "vitest";
import { arrangeColumns, pinnedOffsets, sanitizeArrangement } from "./data-table-arrangement";
import type { ColumnLayoutInput } from "./data-table-layout";

const columns: ColumnLayoutInput[] = [
  { id: "name", header: "Name", kind: "name" },
  { id: "count", header: "Count", kind: "count" },
  { id: "actions", header: "Actions", kind: "actions" },
];
describe("saved table arrangement", () => {
  it("removes obsolete and duplicate state and clamps widths to actual column bounds", () => {
    expect(sanitizeArrangement({ columnOrder: ["count", "old", "count", 12], columnWidths: { name: 1, count: 999999, old: 300, actions: NaN }, columnPinning: { start: ["name", "name", "old"], end: ["name", "actions"] } }, columns)).toEqual({
      columnOrder: ["count"], columnWidths: { name: 160, count: 120 }, columnPinning: { start: ["name"], end: ["actions"] },
    });
  });
  it("keeps declared new columns between ordered and right-pinned columns", () => {
    const pin = { start: ["name"], end: ["actions"] };
    expect(arrangeColumns([...columns, { id: "added", header: "New" }], ["actions", "count", "count", "obsolete"], pin).map(c => c.id)).toEqual(["name", "count", "added", "actions"]);
  });
  it("computes nonoverlapping measured offsets and leaves room to scroll on narrow screens", () => {
    const pin = { start: ["name", "count", "hidden"], end: ["actions"] };
    const wide = pinnedOffsets(["name", "count", "actions"], [200, 100, 120], pin, 800, 40);
    expect([...wide.offsets]).toEqual([["name", { side: "left", offset: 40 }], ["count", { side: "left", offset: 240 }], ["actions", { side: "right", offset: 0 }]]);
    expect(wide.suspended).toBe(false);
    const narrow = pinnedOffsets(["name", "count", "actions"], [200, 100, 120], pin, 450, 40);
    expect(narrow.suspended).toBe(true);
    expect(narrow.offsets.size).toBe(0);
    expect(pin.start).toEqual(["name", "count", "hidden"]);
  });
  it("ignores invalid stored scalar shapes and never treats opaque CSS columns as resizable", () => {
    expect(sanitizeArrangement({columnWidths:{name:300}},[{...columns[0],width:"50%"}])).toEqual({columnWidths:{}});
    expect(sanitizeArrangement(null, columns)).toEqual({});
    expect(sanitizeArrangement([], columns)).toEqual({});
    expect(sanitizeArrangement({ columnOrder: "name", columnWidths: [], columnPinning: true }, columns)).toEqual({});
    expect(sanitizeArrangement({ columnWidths: { name: -1, count: Infinity, actions: "100" } }, columns)).toEqual({ columnWidths: {} });
  });
});
