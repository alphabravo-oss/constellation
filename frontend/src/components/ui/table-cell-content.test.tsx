import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { TableCellContent } from "./table-cell-content";

afterEach(() => { vi.restoreAllMocks(); document.body.innerHTML = ""; });

it("keeps a clipped value keyboard accessible and retains links when its column narrows", () => {
  let availableWidth = 300;
  let nestedClipped = false;
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockImplementation(function (this: HTMLElement) { return nestedClipped && this.tagName === "A" ? 80 : availableWidth; });
  vi.spyOn(HTMLElement.prototype, "scrollWidth", "get").mockReturnValue(240);
  const host = document.createElement("div"); document.body.appendChild(host);
  const root = createRoot(host);
  const value = "1.24.13, 1.25.7, 1.26.0-rc.3";
  const render = () => root.render(<TableCellContent overflow="nowrap" width={availableWidth}><a href="/details">{value}</a></TableCellContent>);
  try {
    act(render);
    expect(host.querySelector("[tabindex='0']")).toBeNull();
    availableWidth = 80;
    act(render);
    expect(host.querySelector("[tabindex='0']")?.textContent).toBe(value);
    expect(host.querySelector("a")?.getAttribute("href")).toBe("/details");
    availableWidth = 300;
    act(render);
    expect(host.querySelector("[tabindex='0']")).toBeNull();
    expect(host.textContent).toBe(value);
    nestedClipped = true;
    availableWidth = 301;
    act(render);
    expect(host.querySelector("[tabindex='0']")?.textContent).toBe(value);
  } finally { act(() => root.unmount()); }
});
