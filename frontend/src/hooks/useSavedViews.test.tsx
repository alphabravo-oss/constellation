import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

beforeEach(() => { (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true; });

afterEach(() => {
  if (root) {
    act(() => root?.unmount());
  }
  host?.remove();
  root = undefined;
  host = undefined;
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
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

it("reports storage write failure and retains existing views instead of claiming a save/delete", () => {
  writeSavedViews<TestView>(scoped("failure"), [{ id: "existing", name: "Existing", query: "api", severity: "high" }]);
  render(<FailureHarness />);
  const restore = blockStorage("write");
  act(() => host!.querySelector<HTMLButtonElement>('[data-testid="failure-save"]')!.click());
  expect(screenText()).toContain("could not be stored"); expect(screenText()).toContain("Existing"); expect([...host!.querySelectorAll("span")].some(item => item.textContent === "Saved")).toBe(false); expect(screenText()).not.toContain("private quota details");
  act(() => host!.querySelector<HTMLButtonElement>('[data-testid="failure-delete"]')!.click()); expect(screenText()).toContain("Existing");
  restore(); act(() => host!.querySelector<HTMLButtonElement>('[data-testid="failure-save"]')!.click()); expect(screenText()).toContain("Saved"); expect(screenText()).not.toContain("could not be stored");
});
it("persists synchronously before immediate unmount and combines same-turn saves", () => {
  render(<SynchronousHarness />);
  act(() => host!.querySelector<HTMLButtonElement>('[data-testid="sync-save"]')!.click());
  expect(readSavedViews<TestView>(scoped("sync")).map(view => view.name)).toEqual(["First", "Second"]);
});
it("does not overwrite storage if current views cannot be read during a write", () => {
  writeSavedViews<TestView>(scoped("failure"), [{ id: "existing", name: "Existing", query: "api", severity: "high" }]); render(<FailureHarness />);
  const restore = blockStorage("read");
  act(() => host!.querySelector<HTMLButtonElement>('[data-testid="failure-save"]')!.click()); expect(screenText()).toContain("could not be stored"); expect(screenText()).toContain("Existing");
  restore(); expect(readSavedViews<TestView>(scoped("failure"))).toHaveLength(1);
});
it("filters malformed saved payloads with a supplied validator and performs no mount writes", () => {
  localStorage.setItem(scoped("validated"), JSON.stringify([{ id: "ok", name: "Valid", query: "api", severity: "high" }, { id: "bad", name: "Broken", query: [], severity: null }]));
  const original = localStorage; let writes = 0; vi.stubGlobal("localStorage", { getItem: original.getItem.bind(original), setItem: (key: string, value: string) => { writes++; original.setItem(key, value); } }); render(<ValidatedHarness />);
  expect(screenText()).toContain("Valid"); expect(screenText()).not.toContain("Broken"); expect(screenText()).toContain("1 saved view record was rejected"); expect(writes).toBe(0); vi.unstubAllGlobals();
});
function FailureHarness() {
  const { views, saveView, deleteView, persistenceError } = useSavedViews<TestView>("failure");
  return <div>{views.map(view => <span key={view.id}>{view.name}</span>)}{persistenceError}<button data-testid="failure-save" onClick={() => saveView("Saved", { query: "api", severity: "high" })}>save</button><button data-testid="failure-delete" onClick={() => deleteView("existing")}>delete</button></div>;
}
function SynchronousHarness() {
  const { saveView } = useSavedViews<TestView>("sync");
  return <button data-testid="sync-save" onClick={() => { saveView("First", { query: "api", severity: "high" }); saveView("Second", { query: "web", severity: "low" }); root!.unmount(); }}>save</button>;
}
const validTestView = (value: unknown): value is TestView => Boolean(value && typeof value === "object" && typeof (value as TestView).query === "string" && typeof (value as TestView).severity === "string");
function ValidatedHarness() { const { views, persistenceError } = useSavedViews<TestView>("validated", { validate: validTestView }); return <>{views.map(view => <span key={view.id}>{view.name}</span>)}{persistenceError}</>; }
it.each(["{broken", "{}", ""])("reports a rejected malformed collection without crashing or overwriting it: %s", raw => {
  localStorage.setItem(scoped("validated"), raw); render(<ValidatedHarness />);
  expect(screenText()).toContain("Saved view data was rejected"); expect(localStorage.getItem(scoped("validated"))).toBe(raw);
});
it.each(["organization", "user", "inventory"])("rejects held writer callbacks after the %s changes", condition => {
  render(<WriterHarness storageKey="held" />); const prior = currentWriter;
  const owner = condition === "organization" ? { org_id: "other", user_id: "user" } : condition === "user" ? { org_id: "org", user_id: "other" } : identity;
  const key = condition === "inventory" ? "another" : "held";
  act(() => root!.render(<TablePreferencesProvider identity={owner}><WriterHarness storageKey={key} /></TablePreferencesProvider>));
  act(() => { expect(prior.saveView("Stale", { query: "prior", severity: "high" }).ok).toBe(false); expect(prior.setViews([{ id: "stale", name: "Stale", query: "prior", severity: "high" }]).ok).toBe(false); });
  expect(localStorage.length).toBe(0);
  act(() => { expect(currentWriter.saveView("Current", { query: "now", severity: "low" }).ok).toBe(true); });
  expect(readSavedViews(operatorStorageKey(key, owner)!).map(view => view.name)).toEqual(["Current"]);
});
it("ignores malformed JSON and duplicate saved IDs without writing on read", () => {
  localStorage.setItem("broken", "{broken"); expect(readSavedViews("broken")).toEqual([]);
  localStorage.setItem("duplicate", JSON.stringify([{ id: "same", name: "First" }, { id: "same", name: "Second" }, { id: " ", name: "Blank ID" }, { id: "blank-name", name: "  " }]));
  expect(readSavedViews("duplicate").map(view => view.name)).toEqual(["First"]);
});
let currentWriter: ReturnType<typeof useSavedViews<TestView>>;
function WriterHarness({ storageKey }: { storageKey: string }) { currentWriter = useSavedViews<TestView>(storageKey); return null; }

function blockStorage(mode: "read" | "write") { const original = localStorage; vi.stubGlobal("localStorage", { getItem: mode === "read" ? () => { throw new Error("private read details"); } : original.getItem.bind(original), setItem: mode === "write" ? () => { throw new Error("private quota details"); } : original.setItem.bind(original) }); return () => vi.unstubAllGlobals(); }
it("accepts inline payload validation without replaying mount persistence or resetting saves", () => {
  render(<InlineValidatedHarness />); act(() => host!.querySelector<HTMLButtonElement>('[data-testid="inline-save"]')!.click()); expect(screenText()).toContain("Inline saved"); expect(readSavedViews(scoped("inline"))).toHaveLength(1);
});
function InlineValidatedHarness() { const { views, saveView } = useSavedViews<TestView>("inline", { validate: (value): value is TestView => validTestView(value) }); return <>{views.map(view => <span key={view.id}>{view.name}</span>)}<button data-testid="inline-save" onClick={() => saveView("Inline saved", { query: "api", severity: "high" })}>save</button></>; }
