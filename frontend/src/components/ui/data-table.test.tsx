import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

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
  it("restores hidden columns and density from the table preference key", () => {
    localStorage.setItem(
      "constellation.table.unit-findings.v1",
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
      "constellation.table.unit-required.v1",
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
      "constellation.table.unit-export.v1",
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
    root?.render(ui);
  });
}

function restoreUrlFunction(name: "createObjectURL" | "revokeObjectURL", value: typeof URL.createObjectURL | typeof URL.revokeObjectURL | undefined) {
  if (value) {
    Object.defineProperty(URL, name, { configurable: true, writable: true, value });
    return;
  }
  delete (URL as unknown as Record<string, unknown>)[name];
}
