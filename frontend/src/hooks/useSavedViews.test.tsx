import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";

import {
  appendSavedView,
  readSavedViews,
  useSavedViews,
  writeSavedViews,
  type SavedViewBase,
} from "./useSavedViews";

interface TestView extends SavedViewBase {
  query: string;
  severity: string;
}

let root: Root | undefined;
let host: HTMLDivElement | undefined;

afterEach(() => {
  if (root) {
    act(() => root?.unmount());
  }
  host?.remove();
  root = undefined;
  host = undefined;
  localStorage.clear();
  document.body.innerHTML = "";
});

describe("saved view persistence", () => {
  it("reads only valid saved view records", () => {
    localStorage.setItem("views", JSON.stringify([
      { id: "one", name: "Critical", query: "kev:true", severity: "critical" },
      { id: 2, name: "bad" },
      "not a view",
    ]));

    expect(readSavedViews<TestView>("views")).toEqual([
      { id: "one", name: "Critical", query: "kev:true", severity: "critical" },
    ]);
  });

  it("appends trimmed named views with a caller-provided id", () => {
    const next = appendSavedView<TestView>(
      [],
      "  High KEV  ",
      { query: "kev:true", severity: "high" },
      () => "view-1",
    );

    expect(next).toEqual([
      { id: "view-1", name: "High KEV", query: "kev:true", severity: "high" },
    ]);
  });

  it("persists saves and deletes through the hook", () => {
    writeSavedViews<TestView>("hook-views", [
      { id: "existing", name: "Existing", query: "status:open", severity: "medium" },
    ]);

    render(<SavedViewHarness storageKey="hook-views" />);

    expect(screenText()).toContain("Existing");
    act(() => click("save"));
    expect(screenText()).toContain("Saved");
    expect(readSavedViews<TestView>("hook-views")).toHaveLength(2);

    act(() => click("delete-existing"));
    expect(screenText()).not.toContain("Existing");
    expect(readSavedViews<TestView>("hook-views").map((view) => view.name)).toEqual(["Saved"]);
  });

  it("reloads when the storage key changes without overwriting the target key", () => {
    writeSavedViews<TestView>("views-a", [
      { id: "a", name: "First", query: "namespace:a", severity: "low" },
    ]);
    writeSavedViews<TestView>("views-b", [
      { id: "b", name: "Second", query: "namespace:b", severity: "high" },
    ]);

    render(<SavedViewHarness storageKey="views-a" />);
    expect(screenText()).toContain("First");

    act(() => {
      root?.render(<SavedViewHarness storageKey="views-b" />);
    });

    expect(screenText()).toContain("Second");
    expect(screenText()).not.toContain("First");
    expect(readSavedViews<TestView>("views-a")).toEqual([
      { id: "a", name: "First", query: "namespace:a", severity: "low" },
    ]);
    expect(readSavedViews<TestView>("views-b")).toEqual([
      { id: "b", name: "Second", query: "namespace:b", severity: "high" },
    ]);
  });
});

function SavedViewHarness({ storageKey }: { storageKey: string }) {
  const { views, saveView, deleteView } = useSavedViews<TestView>(storageKey);
  return (
    <div>
      <ul>
        {views.map((view) => <li key={view.id}>{view.name}</li>)}
      </ul>
      <button type="button" data-testid="save" onClick={() => saveView("Saved", { query: "severity:high", severity: "high" })}>
        Save
      </button>
      <button type="button" data-testid="delete-existing" onClick={() => deleteView("existing")}>
        Delete
      </button>
    </div>
  );
}

function render(ui: ReactNode) {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    root?.render(ui);
  });
}

function click(testID: string) {
  host?.querySelector<HTMLButtonElement>(`[data-testid="${testID}"]`)?.click();
}

function screenText() {
  return host?.textContent ?? "";
}
