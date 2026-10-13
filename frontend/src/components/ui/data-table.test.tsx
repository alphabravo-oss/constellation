import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { DataTable, type Column } from "./data-table";

type Row = { id: string; name: string; risk: number; owner: string };

const rows: Row[] = [
  { id: "one", name: "api", risk: 42, owner: "platform" },
];

const columns: Column<Row>[] = [
  { id: "name", header: "Name", cell: (row) => row.name },
  { id: "risk", header: "Risk", cell: (row) => row.risk, numeric: true },
  { id: "owner", header: "Owner", cell: (row) => row.owner },
];

let root: Root | undefined;
let host: HTMLDivElement | undefined;
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });

afterEach(() => {
  if (root) {
    act(() => root?.unmount());
  }
  host?.remove();
  root = undefined;
  host = undefined;
  document.body.innerHTML = "";
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  localStorage.clear();
});

describe("DataTable acceptance", () => {
  it("allows changes from a compact default and hides ineffective controls for fixed density", () => {
    render(<DataTable rows={rows} columns={columns} rowKey={row => row.id} defaultDensity="compact" preferencesKey="default-density" />);
    expect(host?.querySelector('[aria-label="compact density"]')?.getAttribute("aria-pressed")).toBe("true");
    act(() => host?.querySelector<HTMLButtonElement>('[aria-label="comfy density"]')?.click());
    expect(JSON.parse(localStorage.getItem(storageKey("default-density"))!).density).toBe("comfy");
    act(() => root?.render(<DataTable rows={rows} columns={columns} rowKey={row => row.id} density="compact" />));
    expect(host?.querySelector('[aria-label="comfy density"]')).toBeNull();
    expect(host?.querySelector("tbody tr")?.className).toContain("h-6");
  });
  it("repairs stale and all-hidden preferences before rendering and persists the repaired state", () => {
    localStorage.setItem(storageKey("stale"), JSON.stringify({ hiddenColumnIds: ["name", "risk", "risk", "owner", "retired", 42], density: "tiny" }));
    render(<DataTable rows={rows} columns={columns} rowKey={row => row.id} preferencesKey="stale" />);
    expect([...host!.querySelectorAll("th")].map(cell => cell.textContent)).toEqual(["Name"]);
    expect(host?.querySelector("tbody td")?.textContent).toBe("api");
    expect(JSON.parse(localStorage.getItem(storageKey("stale"))!)).toEqual({ hiddenColumnIds: ["risk", "owner"], density: "cozy" });
    expect(host?.querySelector('[aria-label="cozy density"]')?.getAttribute("aria-pressed")).toBe("true");
  });

  it("keeps a remaining column visible when previously visible columns are removed", () => {
    const view = (cols: Column<Row>[]) => <TablePreferencesProvider identity={{ org_id: "org", user_id: "user" }}><DataTable rows={rows} columns={cols} rowKey={row => row.id} preferencesKey="evolving" /></TablePreferencesProvider>;
    localStorage.setItem(storageKey("evolving"), JSON.stringify({ hiddenColumnIds: ["risk", "owner"] }));
    render(view(columns));
    act(() => root?.render(view(columns.slice(1))));
    expect([...host!.querySelectorAll("th")].map(cell => cell.textContent)).toEqual(["Risk"]);
    expect(JSON.parse(localStorage.getItem(storageKey("evolving"))!).hiddenColumnIds).toEqual(["owner"]);
  });

  it("keeps hidden-column sort visible and effective until the operator clears it", () => {
    const onSortChange = vi.fn();
    const list = [{ ...rows[0], id: "low", risk: 1 }, { ...rows[0], id: "high", name: "worker", risk: 9 }];
    render(<DataTable rows={list} columns={[columns[0], { ...columns[1], sort: (a,b) => a.risk-b.risk }]} rowKey={row => row.id} hiddenColumnIds={["risk"]} defaultSort={{ id: "risk", dir: "desc" }} onSortChange={onSortChange} />);
    expect(host?.textContent).toContain("Sorted by Risk (descending) · hidden column");
    expect(host?.querySelector("tbody tr")?.textContent).toBe("worker");
    act(() => [...host!.querySelectorAll("button")].find(button => button.textContent === "Clear sort")?.click());
    expect(onSortChange).toHaveBeenCalledWith(null);
    expect(host?.textContent).not.toContain("hidden column");
    expect(host?.querySelector("tbody tr")?.textContent).toBe("api");
  });

  it("follows controlled URL sort changes and clearing while preserving server row order", () => {
    const onSortChange = vi.fn();
    const cols = [columns[0], { ...columns[1], sort: (a: Row,b: Row) => a.risk-b.risk }];
    const list = [{ ...rows[0], id: "low", risk: 1 }, { ...rows[0], id: "high", name: "worker", risk: 9 }];
    const view = (sort: {id: string; dir: "asc"|"desc"}|null) => <TablePreferencesProvider identity={{ org_id: "org", user_id: "user" }}><DataTable rows={list} columns={cols} rowKey={row => row.id} sort={sort} manualSorting onSortChange={onSortChange} /></TablePreferencesProvider>;
    render(view({id:"risk",dir:"desc"}));
    expect(host?.querySelector('th[data-column-id="risk"]')?.getAttribute("aria-sort")).toBe("descending");
    act(() => root?.render(view({id:"risk",dir:"asc"})));
    expect(host?.querySelector('th[data-column-id="risk"]')?.getAttribute("aria-sort")).toBe("ascending");
    expect(host?.querySelector("tbody tr")?.textContent).toBe("api1");
    act(() => root?.render(view(null)));
    expect(host?.querySelector('th[aria-sort]')).toBeNull();
    expect(onSortChange).not.toHaveBeenCalled();
  });

  it("reports unavailable storage while keeping density controls usable", () => {
    const storage = localStorage;
    let unavailable = true;
    vi.stubGlobal("localStorage", { getItem: storage.getItem.bind(storage), setItem: (key: string, value: string) => { if (unavailable) throw new Error("quota"); storage.setItem(key,value); } });
    render(<DataTable rows={rows} columns={columns} rowKey={row => row.id} preferencesKey="blocked" />);
    expect(host?.querySelector('[role="status"]')?.textContent).toContain("could not be saved");
    act(() => host?.querySelector<HTMLButtonElement>('[aria-label="compact density"]')?.click());
    expect(host?.querySelector("tbody tr")?.className).toContain("h-6");
    expect(host?.querySelector('[aria-label="compact density"]')?.getAttribute("aria-pressed")).toBe("true");
    unavailable = false;
    act(() => [...host!.querySelectorAll("button")].find(button => button.textContent === "Retry saving preferences")?.click());
    expect(host?.querySelector('[role="status"]')).toBeNull();
    expect(JSON.parse(storage.getItem(storageKey("blocked"))!).density).toBe("compact");
  });

  it("shows mixed selection and exposes the scroll area to keyboard users", () => {
    const list = [rows[0], {...rows[0],id:"two"}];
    render(<DataTable rows={list} columns={columns} rowKey={row => row.id} selectable selected={new Set(["one"])} />);
    const all = host?.querySelector<HTMLInputElement>('input[aria-label="Select all"]');
    expect(all?.indeterminate).toBe(true);
    expect(all?.getAttribute("aria-checked")).toBe("mixed");
    expect(host?.querySelector('[role="region"]')?.getAttribute("tabindex")).toBe("0");
  });

  it("selects and clears the current page without discarding selections on other pages", () => {
    const list = Array.from({length:101},(_,index)=>({...rows[0],id:String(index)}));
    const changed = vi.fn();
    const view = (selected: Set<string>) => <TablePreferencesProvider identity={{org_id:"org",user_id:"user"}}><DataTable rows={list} columns={columns} rowKey={row=>row.id} selectable selected={selected} onSelectedChange={changed}/></TablePreferencesProvider>;
    render(view(new Set(["100"])));
    act(() => host?.querySelector<HTMLInputElement>('input[aria-label="Select all"]')?.click());
    const all = changed.mock.calls[0][0] as Set<string>;
    expect(all.size).toBe(101);
    expect(all.has("100")).toBe(true);
    act(() => root?.render(view(all)));
    act(() => host?.querySelector<HTMLInputElement>('input[aria-label="Select all"]')?.click());
    expect([...changed.mock.calls[1][0]]).toEqual(["100"]);
  });

  it("resets columns and density together through the shared menu", async () => {
    localStorage.setItem(storageKey("reset"), JSON.stringify({ hiddenColumnIds:["risk","owner"], density:"compact" }));
    render(<DataTable rows={rows} columns={columns} rowKey={row => row.id} preferencesKey="reset" defaultHiddenColumnIds={["owner"]} />);
    await act(async () => { host?.querySelector<HTMLButtonElement>('[aria-label="Columns"]')?.dispatchEvent(new MouseEvent("pointerdown", {bubbles:true,button:0})); });
    const item = [...document.querySelectorAll<HTMLElement>('[role="menuitem"]')].find(item => item.textContent?.includes("Reset table preferences"));
    expect(item).toBeDefined();
    await act(async () => { item?.click(); });
    expect([...host!.querySelectorAll("th")].map(cell => cell.textContent)).toEqual(["Name","Risk"]);
    expect(host?.querySelector('[aria-label="cozy density"]')?.getAttribute("aria-pressed")).toBe("true");
    expect(JSON.parse(localStorage.getItem(storageKey("reset"))!)).toEqual({ hiddenColumnIds:["owner"], density:"cozy" });
  });

  it("allows hiding the last optional column when a required column remains", async () => {
    render(<DataTable rows={rows} columns={[{...columns[0],hideable:false},columns[1]]} rowKey={row => row.id} preferencesKey="required" />);
    await act(async () => { host?.querySelector<HTMLButtonElement>('[aria-label="Columns"]')?.dispatchEvent(new MouseEvent("pointerdown",{bubbles:true,button:0})); });
    const risk = [...document.querySelectorAll<HTMLElement>('[role="menuitemcheckbox"]')].find(item => item.textContent === "Risk");
    await act(async () => { risk?.click(); });
    expect([...host!.querySelectorAll("th")].map(cell => cell.textContent)).toEqual(["Name"]);
  });
});

describe("DataTable preferences", () => {
  it("preserves server row order while requesting a changed sort", () => {
    const onSortChange = vi.fn();
    const serverRows: Row[] = [{id:"high",name:"z",risk:90,owner:"x"}, {id:"low",name:"a",risk:10,owner:"x"}];
    render(<DataTable rows={serverRows} columns={[{...columns[0],sort:(a,b)=>a.name.localeCompare(b.name)}]} rowKey={r=>r.id} manualSorting defaultSort={{id:"name",dir:"desc"}} onSortChange={onSortChange} />);
    expect([...host!.querySelectorAll("tbody td")].map(el=>el.textContent)).toEqual(["z","a"]);
    act(()=>host?.querySelector<HTMLButtonElement>('th[data-column-id="name"] button')?.click());
    expect(onSortChange).toHaveBeenCalledWith({id:"name",dir:"asc"});
    expect([...host!.querySelectorAll("tbody td")].map(el=>el.textContent)).toEqual(["z","a"]);
  });

  it("keeps text and numeric headers aligned with their cells, including sortable and centered columns", () => {
    render(<DataTable rows={rows} columns={[
      { ...columns[0], kind: "name", sort: (a, b) => a.name.localeCompare(b.name) },
      { ...columns[1], kind: "count", sort: (a, b) => a.risk - b.risk },
      { ...columns[2], kind: "status", align: "center" },
    ]} rowKey={(row) => row.id} />);
    for (const [index, align] of ["left", "right", "center"].entries()) {
      expect((host?.querySelectorAll("th")[index] as HTMLElement).style.textAlign).toBe(align);
      expect((host?.querySelectorAll("tbody td")[index] as HTMLElement).style.textAlign).toBe(align);
    }
    const header = host?.querySelector<HTMLElement>('th[data-column-id="risk"]');
    act(() => header?.querySelector("button")?.click());
    expect(header?.getAttribute("aria-sort")).toBe("descending");
    expect(host?.querySelectorAll("col")).toHaveLength(3);
  });

  it("retains native sizing for legacy CSS widths and recomputes semantic columns after hiding one", () => {
    render(<DataTable rows={rows} columns={[
      { ...columns[0], width: "60%" }, columns[1], columns[2],
    ]} rowKey={(row) => row.id} />);
    expect(host?.querySelector("table")?.getAttribute("data-layout")).toBe("auto");
    const semantic: Column<Row>[] = [{ ...columns[0], kind: "name" }, { ...columns[1], kind: "count" }, { ...columns[2], kind: "status" }];
    act(() => root?.render(<DataTable rows={rows} columns={semantic} hiddenColumnIds={["owner"]} rowKey={(row) => row.id} selectable selected={new Set()} />));
    expect(host?.querySelector("table")?.getAttribute("data-layout")).toBe("semantic");
    expect(host?.querySelectorAll("col")).toHaveLength(3);
    expect(host?.querySelectorAll("th")).toHaveLength(3);
    expect(host?.querySelectorAll("tbody td")).toHaveLength(3);
  });

  it("applies global table styling and keyboard activation to clickable rows", () => {
    const onRowClick = vi.fn();
    render(
      <DataTable rows={rows} columns={columns} rowKey={(row) => row.id} onRowClick={onRowClick} />,
    );
    const table = host?.querySelector(".app-data-table");
    const row = host?.querySelector("tbody tr");
    expect(table).not.toBeNull();
    expect(row?.getAttribute("tabindex")).toBe("0");
    act(() => row?.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true })));
    expect(onRowClick).toHaveBeenCalledWith(rows[0]);
  });

  it("restores hidden columns and density from the table preference key", () => {
    localStorage.setItem(
      storageKey("unit-findings"),
      JSON.stringify({ hiddenColumnIds: ["owner"], density: "compact" }),
    );

    render(
      <DataTable
        rows={rows}
        columns={columns}
        rowKey={(row) => row.id}
        preferencesKey="unit-findings"
        testId="unit-table"
      />,
    );

    expect(host?.textContent).toContain("Name");
    expect(host?.textContent).toContain("api");
    expect(host?.textContent).not.toContain("Owner");
    expect(host?.textContent).not.toContain("platform");
    expect(document.querySelector("[data-testid='unit-table-columns-trigger']")).not.toBeNull();
    expect(host?.querySelector("tbody tr")?.className).toContain("h-6");
  });

  it("keeps non-hideable columns visible even when stored preferences hide them", () => {
    localStorage.setItem(
      storageKey("unit-required"),
      JSON.stringify({ hiddenColumnIds: ["name", "owner"] }),
    );

    render(
      <DataTable
        rows={rows}
        columns={[
          { ...columns[0], hideable: false },
          columns[1],
          columns[2],
        ]}
        rowKey={(row) => row.id}
        preferencesKey="unit-required"
      />,
    );

    expect(host?.textContent).toContain("Name");
    expect(host?.textContent).toContain("api");
    expect(host?.textContent).not.toContain("Owner");
    expect(host?.textContent).not.toContain("platform");
  });

  it("rechecks page export freshness at click time without needing a rerender", () => {
    let fresh = true;
    const canExport = vi.fn(() => fresh);
    const createURL = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:guarded-table");
    const revokeURL = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    const blob = vi.spyOn(globalThis, "Blob");
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    render(<DataTable rows={rows} columns={columns} rowKey={row => row.id} exportFileName="guarded-page" testId="guarded-page" canExport={canExport} />);
    const exportButton = host!.querySelector<HTMLButtonElement>('[data-testid="guarded-page-export-csv"]')!;
    expect(exportButton.disabled).toBe(false);
    expect(canExport).toHaveBeenCalled();
    canExport.mockClear();

    fresh = false;
    act(() => exportButton.click());
    expect(canExport).toHaveBeenCalledOnce();
    expect(blob).not.toHaveBeenCalled();
    expect(createURL).not.toHaveBeenCalled();
    expect(click).not.toHaveBeenCalled();

    fresh = true;
    act(() => exportButton.click());
    expect(canExport).toHaveBeenCalledTimes(2);
    expect(blob).toHaveBeenCalledOnce();
    expect(createURL).toHaveBeenCalledOnce();
    expect(click).toHaveBeenCalledOnce();
    expect(revokeURL).toHaveBeenCalledWith("blob:guarded-table");
    expect(blob).toHaveBeenCalledWith(["Name,Risk,Owner\napi,42,platform"], { type: "text/csv;charset=utf-8" });
  });

  it("disables page CSV when the supplied evidence guard is already unavailable", () => {
    render(<DataTable rows={rows} columns={columns} rowKey={row => row.id} exportFileName="stale-page" testId="stale-page" canExport={() => false} />);
    expect(host?.querySelector<HTMLButtonElement>('[data-testid="stale-page-export-csv"]')?.disabled).toBe(true);
  });

  it("exports visible columns with stable CSV values", async () => {
    let exportedBlob: Blob | undefined;
    let exportedName = "";
    const originalCreateObjectURL = URL.createObjectURL;
    const originalRevokeObjectURL = URL.revokeObjectURL;
    const createURL = vi.fn((blob: Blob) => {
      exportedBlob = blob as Blob;
      return "blob:unit-table";
    });
    const revokeURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, writable: true, value: createURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, writable: true, value: revokeURL });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function clickAnchor(this: HTMLAnchorElement) {
      exportedName = this.download;
    });
    localStorage.setItem(
      storageKey("unit-export"),
      JSON.stringify({ hiddenColumnIds: ["owner"] }),
    );

    try {
      render(
        <DataTable
          rows={rows}
          columns={[
            columns[0],
            { ...columns[1], exportValue: (row) => `risk:${row.risk}` },
            columns[2],
          ]}
          rowKey={(row) => row.id}
          preferencesKey="unit-export"
          exportFileName="unit-export"
          testId="unit-export-table"
        />,
      );

      act(() => {
        host?.querySelector<HTMLButtonElement>("[data-testid='unit-export-table-export-csv']")?.click();
      });

      await expect(exportedBlob?.text()).resolves.toBe("Name,Risk\napi,risk:42");
      expect(exportedName).toBe("unit-export.csv");
      expect(createURL).toHaveBeenCalledTimes(1);
      expect(revokeURL).toHaveBeenCalledWith("blob:unit-table");
    } finally {
      restoreUrlFunction("createObjectURL", originalCreateObjectURL);
      restoreUrlFunction("revokeObjectURL", originalRevokeObjectURL);
      click.mockRestore();
    }
  });
});

function render(ui: ReactNode) {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    root?.render(<TablePreferencesProvider identity={{ org_id: "org", user_id: "user" }}>{ui}</TablePreferencesProvider>);
  });
}

function restoreUrlFunction(name: "createObjectURL" | "revokeObjectURL", value: typeof URL.createObjectURL | typeof URL.revokeObjectURL | undefined) {
  if (value) {
    Object.defineProperty(URL, name, { configurable: true, writable: true, value });
    return;
  }
  delete (URL as unknown as Record<string, unknown>)[name];
}

function storageKey(table: string, org = "org", user = "user") {
  return `constellation.table.${JSON.stringify([org, user, table])}.v1`;
}

it("isolates preferences across identities without copying stale columns or density", () => {
  localStorage.setItem(storageKey("scoped"), JSON.stringify({ hiddenColumnIds: ["owner", "removed-column"], density: "compact" }));
  const table = <DataTable rows={rows} columns={columns} rowKey={(row) => row.id} preferencesKey="scoped" />;
  render(table);
  expect(host?.textContent).not.toContain("Owner");
  act(() => root?.render(<TablePreferencesProvider identity={{ org_id: "other-org", user_id: "user" }}>{table}</TablePreferencesProvider>));
  expect(host?.textContent).toContain("Owner");
  expect(host?.querySelector("tbody tr")?.className).not.toContain("h-6");
  expect(JSON.parse(localStorage.getItem(storageKey("scoped", "other-org"))!).hiddenColumnIds).toEqual([]);
  act(() => root?.render(<TablePreferencesProvider identity={{ org_id: "org", user_id: "other-user" }}>{table}</TablePreferencesProvider>));
  expect(host?.textContent).toContain("Owner");
  expect(JSON.parse(localStorage.getItem(storageKey("scoped"))!).hiddenColumnIds).toEqual(["owner"]);
});

it("does not adopt legacy preferences with unknown ownership", () => {
  localStorage.setItem("constellation.table.legacy.v1", JSON.stringify({ hiddenColumnIds: ["owner"], density: "compact" }));
  render(<DataTable rows={rows} columns={columns} rowKey={(row) => row.id} preferencesKey="legacy" />);
  expect(host?.textContent).toContain("Owner");
  expect(host?.querySelector("tbody tr")?.className).not.toContain("h-6");
});

it("keeps bounded detail inventories scrollable without changing default pagination", () => {
  const manyRows = Array.from({ length: 200 }, (_, index) => ({ ...rows[0], id: String(index), name: `Row ${index}` }));
  render(<DataTable rows={manyRows} columns={columns} rowKey={(row) => row.id} />);
  expect(host?.querySelectorAll("tbody tr")).toHaveLength(100);
  expect(host?.textContent).toContain("Page 1 of 2");
  act(() => root?.render(<DataTable rows={manyRows} columns={columns} rowKey={(row) => row.id} pagination={false} sourceLimit={200} />));
  expect(host?.querySelectorAll("tbody tr")).toHaveLength(200);
  expect(host?.textContent).not.toContain("Page 1 of");
  expect(host?.textContent).toContain("Showing 1–200 of 200 matching loaded rows.");
  expect(host?.textContent).toContain("Server fetch limit: 200 rows");
});
it('migrates only new metadata hides once, retains layout choices and preserves an explicit later show', async () => {
  const migration = { id: 'observation-v1', hideColumnIds: ['instance', 'first-seen'] };
  const extra: Column<Row>[] = [...columns.map((column, index) => ({ ...column, kind: (index === 0 ? 'name' : index === 1 ? 'count' : 'text') as Column<Row>['kind'] })), { id: 'instance', kind: 'id', header: 'Instance', cell: row => row.id }, { id: 'first-seen', kind: 'date', header: 'First observed', cell: () => '2026-01-01T00:00:00.123456Z' }];
  localStorage.setItem(storageKey('migration'), JSON.stringify({ density: 'compact', hiddenColumnIds: ['owner'], columnWidths: { name: 280 }, columnOrder: ['risk', 'name', 'owner'], columnPinning: { start: ['name'], end: [] } }));
  const view = (chooser = false, org = 'org') => <TablePreferencesProvider identity={{ org_id: org, user_id: 'user' }}><DataTable rows={rows} columns={extra.map(column => column.id === 'first-seen' ? { ...column, hideable: !chooser } : column)} rowKey={row => row.id} preferencesKey='migration' preferenceMigration={migration} /></TablePreferencesProvider>;
  render(view());
  let stored = JSON.parse(localStorage.getItem(storageKey('migration'))!); expect(stored.hiddenColumnIds).toEqual(['owner', 'instance', 'first-seen']); expect(stored.density).toBe('compact'); expect(stored.columnWidths.name).toBe(280); expect(stored.columnOrder.slice(0, 3)).toEqual(['risk', 'name', 'owner']); expect(stored.columnPinning).toEqual({ start: ['name'], end: [] }); expect(stored.preferenceMigrations).toEqual(['observation-v1']);
  act(() => root?.render(view(true))); expect(host?.querySelector('th[data-column-id="first-seen"]')).not.toBeNull(); expect(host?.querySelector('th[data-column-id="instance"]')).toBeNull(); expect(JSON.parse(localStorage.getItem(storageKey('migration'))!).hiddenColumnIds).toContain('first-seen');
  act(() => root?.render(view())); expect(host?.querySelector('th[data-column-id="first-seen"]')).toBeNull();
  await act(async () => host?.querySelector<HTMLButtonElement>('[aria-label="Columns"]')?.dispatchEvent(new MouseEvent('pointerdown', { bubbles: true, button: 0 })));
  const choice = [...document.querySelectorAll<HTMLElement>('[role="menuitemcheckbox"]')].find(item => item.textContent === 'First observed')!; await act(async () => choice.click());
  expect(host?.querySelector('th[data-column-id="first-seen"]')).not.toBeNull();
  act(() => root?.render(view(false, 'other-org'))); expect(host?.querySelector('th[data-column-id="first-seen"]')).not.toBeNull(); // New owner has no legacy hidden list.
  act(() => root?.render(view())); expect(host?.querySelector('th[data-column-id="first-seen"]')).not.toBeNull(); stored = JSON.parse(localStorage.getItem(storageKey('migration'))!); expect(stored.hiddenColumnIds).toEqual(['owner', 'instance']); expect(stored.preferenceMigrations).toEqual(['observation-v1']);
});
