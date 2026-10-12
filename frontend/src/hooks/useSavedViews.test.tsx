import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";

import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { operatorStorageKey } from "@/lib/operator-preferences";
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

const identity = { org_id: "org", user_id: "user" };
const scoped = (key: string, org = "org", user = "user") => operatorStorageKey(key, { org_id: org, user_id: user })!;
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
    writeSavedViews<TestView>(scoped("hook-views"), [
      { id: "existing", name: "Existing", query: "status:open", severity: "medium" },
    ]);

    render(<SavedViewHarness storageKey="hook-views" />);

    expect(screenText()).toContain("Existing");
    act(() => click("save"));
    expect(screenText()).toContain("Saved");
    expect(readSavedViews<TestView>(scoped("hook-views"))).toHaveLength(2);

    act(() => click("delete-existing"));
    expect(screenText()).not.toContain("Existing");
    expect(readSavedViews<TestView>(scoped("hook-views")).map((view) => view.name)).toEqual(["Saved"]);
  });

  it("reloads when the storage key changes without overwriting the target key", () => {
    writeSavedViews<TestView>(scoped("views-a"), [
      { id: "a", name: "First", query: "namespace:a", severity: "low" },
    ]);
    writeSavedViews<TestView>(scoped("views-b"), [
      { id: "b", name: "Second", query: "namespace:b", severity: "high" },
    ]);

    render(<SavedViewHarness storageKey="views-a" />);
    expect(screenText()).toContain("First");

    act(() => {
      root?.render(<TablePreferencesProvider identity={identity}><SavedViewHarness storageKey="views-b" /></TablePreferencesProvider>);
    });

    expect(screenText()).toContain("Second");
    expect(screenText()).not.toContain("First");
    expect(readSavedViews<TestView>(scoped("views-a"))).toEqual([
      { id: "a", name: "First", query: "namespace:a", severity: "low" },
    ]);
    expect(readSavedViews<TestView>(scoped("views-b"))).toEqual([
      { id: "b", name: "Second", query: "namespace:b", severity: "high" },
    ]);
  });
  it("isolates organization and user changes without adopting ownerless views", () => {
    writeSavedViews<TestView>("private", [{ id: "legacy", name: "Ownerless", query: "secret", severity: "high" }]);
    render(<SavedViewHarness storageKey="private" />);
    expect(screenText()).not.toContain("Ownerless");
    act(() => click("save"));
    expect(screenText()).toContain("Saved");
    act(() => root?.render(<TablePreferencesProvider identity={{ org_id: "other", user_id: "user" }}><SavedViewHarness storageKey="private" /></TablePreferencesProvider>));
    expect(screenText()).not.toContain("Saved");
    expect(readSavedViews(scoped("private", "other"))).toEqual([]);
    act(() => root?.render(<TablePreferencesProvider identity={{ org_id: "org", user_id: "other" }}><SavedViewHarness storageKey="private" /></TablePreferencesProvider>));
    expect(screenText()).not.toContain("Saved");
    expect(readSavedViews(scoped("private", "org", "other"))).toEqual([]);
    expect(readSavedViews(scoped("private"))).toHaveLength(1);
    act(() => root?.render(<TablePreferencesProvider identity={identity}><SavedViewHarness storageKey="private" /></TablePreferencesProvider>));
    expect(screenText()).toContain("Saved");
  });
  it("migrates an explicitly owned legacy key once without replacing current views", () => {
    const legacyKey = "network:cluster:user";
    writeSavedViews<TestView>(legacyKey, [{ id: "existing", name: "Owned", query: "namespace:app", severity: "high" }]);
    render(<SavedViewHarness storageKey="network" legacyKey={legacyKey} />);
    expect(screenText()).toContain("Owned");
    act(() => click("delete-existing"));
    expect(readSavedViews(scoped("network"))).toEqual([]);
    act(() => root?.render(<TablePreferencesProvider identity={identity}><SavedViewHarness storageKey="network" legacyKey={legacyKey} /></TablePreferencesProvider>));
    expect(screenText()).not.toContain("Owned");
  });
  it("keeps unauthenticated drafts in memory without writing shared storage", () => {
    render(<TablePreferencesProvider identity={null}><SavedViewHarness storageKey="private" /></TablePreferencesProvider>);
    act(() => click("save"));
    expect(screenText()).toContain("Saved");
    expect(localStorage.length).toBe(0);
  });

});

function SavedViewHarness({ storageKey, legacyKey }: { storageKey: string; legacyKey?: string }) {
  const { views, saveView, deleteView } = useSavedViews<TestView>(storageKey, { legacyUserScopedKey: legacyKey });
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
    root?.render(<TablePreferencesProvider identity={identity}>{ui}</TablePreferencesProvider>);
  });
}

function click(testID: string) {
  host?.querySelector<HTMLButtonElement>(`[data-testid="${testID}"]`)?.click();
}

function screenText() {
  return host?.textContent ?? "";
}
