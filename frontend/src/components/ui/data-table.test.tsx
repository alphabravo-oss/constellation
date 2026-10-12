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

afterEach(() => {
  if (root) {
    act(() => root?.unmount());
  }
  host?.remove();
  root = undefined;
  host = undefined;
  document.body.innerHTML = "";
  localStorage.clear();
});

describe("DataTable preferences", () => {
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
