import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { downloadCsv } from "@/lib/csv";
vi.mock("@/lib/csv", () => ({ downloadCsv: vi.fn() }));
import { DataTable, type Column } from "./data-table";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";

const columns: Column<{ id: string }>[] = [
  { id: "name", header: "Name", kind: "name", cell: row => row.id },
  { id: "risk", header: "Risk", kind: "count", sort: () => 0, cell: () => 7 },
  { id: "action", header: "Action", kind: "actions", cell: () => <button>Inspect</button> },
];
let root: Root; let host: HTMLDivElement;
const key = (org = "org", user = "user") => `constellation.table.${JSON.stringify([org,user,"arrangement"])}.v1`;
function mount(org = "org", user = "user") {
  if (!host) { host = document.createElement("div"); document.body.append(host); root = createRoot(host); }
  act(() => root.render(<TablePreferencesProvider identity={{ org_id: org, user_id: user }}><DataTable rows={[{id:"api"}]} columns={columns} rowKey={r=>r.id} preferencesKey="arrangement" exportFileName="arranged" /></TablePreferencesProvider>));
}
function keydown(element: HTMLElement, key: string, options: { ctrlKey?: boolean } = {}) { act(() => element.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true, ...options }))); }
afterEach(() => { act(() => root?.unmount()); host?.remove(); host = undefined!; localStorage.clear(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });

async function openMenu(label = "Column layout") {
  await act(async () => { host.querySelector<HTMLButtonElement>(`[aria-label="${label}"]`)!.dispatchEvent(new MouseEvent("pointerdown", { bubbles: true, button: 0 })); });
}
async function clickItem(label: string) {
  const item = [...document.querySelectorAll<HTMLElement>('[role="menuitem"]')].find(item => item.textContent === label);
  expect(item).toBeDefined();
  await act(async () => { item!.click(); });
}

describe("shared table arrangement controls", () => {
  it("pins headers and body cells at the same measured offset and resumes after a narrow viewport", () => {
    let viewport = 900; let resized = () => {};
    vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockImplementation(() => viewport);
    vi.stubGlobal("ResizeObserver", class { constructor(callback: () => void) { resized = callback; } observe() {} disconnect() {} });
    localStorage.setItem(key(), JSON.stringify({ columnWidths:{name:240},columnPinning:{start:["name","risk"],end:["action"]} }));
    mount();
    const header = host.querySelector<HTMLElement>('th[data-column-id="risk"]')!;
    const body = host.querySelector<HTMLElement>('td[data-column-id="risk"]')!;
    expect(header.style.position).toBe("sticky"); expect(header.style.left).toBe("240px");
    expect(body.style.left).toBe(header.style.left);
    expect(host.querySelector<HTMLElement>('td[data-column-id="action"]')!.style.right).toBe("0px");
    viewport = 320; act(() => resized());
    expect(header.style.position).toBe(""); expect(body.style.position).toBe("");
    expect(host.textContent).toContain("Column pinning pauses");
    viewport = 900; act(() => resized());
    expect(header.style.left).toBe("240px"); expect(host.textContent).not.toContain("Column pinning pauses");
  });
  it("moves and pins columns through the shared menu and exports their displayed order", async () => {
    mount();
    await openMenu(); await clickItem("Risk"); await clickItem("Move left");
    expect([...host.querySelectorAll("thead th")].map(e=>e.textContent)).toEqual(["Risk","Name","Action"]);
    await openMenu(); await clickItem("Risk"); await clickItem("Pin right");
    expect([...host.querySelectorAll("thead th")].map(e=>e.textContent)).toEqual(["Name","Action","Risk"]);
    expect(JSON.parse(localStorage.getItem(key())!).columnPinning).toEqual({ start: [], end: ["risk"] });
    act(() => host.querySelector<HTMLButtonElement>('[aria-label="Export CSV"]')!.click());
    expect(downloadCsv).toHaveBeenCalledWith("arranged", ["Name","Action","Risk"], [["api","",7]]);
    await openMenu(); await clickItem("Reset column layout");
    expect([...host.querySelectorAll("thead th")].map(e=>e.textContent)).toEqual(["Name","Risk","Action"]);
    expect(JSON.parse(localStorage.getItem(key())!).columnPinning).toBeUndefined();
  });
  it("the full preference reset also clears custom widths, ordering and pins", async () => {
    localStorage.setItem(key(), JSON.stringify({ density:"compact", hiddenColumnIds:["action"], columnOrder:["risk","name"],columnWidths:{name:320},columnPinning:{start:["risk"],end:[]} }));
    mount(); await openMenu("Columns"); await clickItem("Reset table preferences");
    expect(JSON.parse(localStorage.getItem(key())!)).toEqual({density:"cozy",hiddenColumnIds:[]});
    expect([...host.querySelectorAll("thead th")].map(e=>e.textContent)).toEqual(["Name","Risk","Action"]);
  });
  it("resizes through keyboard, persists width, keeps header/body order aligned, and resets from the handle", () => {
    mount();
    const handle = host.querySelector<HTMLElement>('[aria-label="Resize Risk"]')!;
    const before = Number(handle.getAttribute("aria-valuenow"));
    keydown(handle,"ArrowRight");
    const width = Number(handle.getAttribute("aria-valuenow"));
    expect(width).toBeGreaterThan(before);
    expect(JSON.parse(localStorage.getItem(key())!).columnWidths.risk).toBe(width);
    expect(host.querySelector('th[data-column-id="risk"]')?.getAttribute("aria-sort")).toBeNull();
    keydown(handle,"Home"); expect(Number(handle.getAttribute("aria-valuenow"))).toBe(Number(handle.getAttribute("aria-valuemin")));
    keydown(handle,"Enter"); expect(JSON.parse(localStorage.getItem(key())!).columnWidths).toEqual({});
  });
  it("restores ordering and pins without leaking them across organization or user changes", () => {
    localStorage.setItem(key(),JSON.stringify({ columnOrder:["risk","name"], columnWidths:{name:320},columnPinning:{start:["risk"],end:["action"]} }));
    mount();
    const ids = (selector: string) => [...host.querySelectorAll(selector)].map(e=>e.getAttribute("data-column-id"));
    expect(ids("thead th")).toEqual(["risk","name","action"]);
    expect(ids("tbody td")).toEqual(ids("thead th"));
    expect(host.textContent).toContain("Column pinning pauses");
    mount("other-org"); expect(ids("thead th")).toEqual(["name","risk","action"]);
    expect(JSON.parse(localStorage.getItem(key("other-org"))!).columnWidths).toBeUndefined();
    mount("org","other-user"); expect(ids("thead th")).toEqual(["name","risk","action"]);
    mount(); expect(ids("thead th")).toEqual(["risk","name","action"]);
  });
  it("scrolls only the focused region and leaves embedded control keys alone", () => {
    mount(); const region = host.querySelector<HTMLElement>('[role="region"]')!;
    Object.defineProperty(region,"scrollWidth",{value:1000}); Object.defineProperty(region,"clientWidth",{value:300});
    keydown(region,"ArrowRight"); expect(region.scrollLeft).toBe(80);
    keydown(region.querySelector("button")!,"ArrowRight"); expect(region.scrollLeft).toBe(80);
    keydown(region,"End"); expect(region.scrollLeft).toBe(1000);
    keydown(region,"Home"); expect(region.scrollLeft).toBe(0);
    keydown(region,"ArrowRight",{ctrlKey:true}); expect(region.scrollLeft).toBe(0);
  });
});
