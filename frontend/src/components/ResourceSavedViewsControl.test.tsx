import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import {
  createMemoryHistory,
  type RouterHistory,
} from "@tanstack/react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { TestRouter } from "@/test/router";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { operatorStorageKey } from "@/lib/operator-preferences";
import {
  captureResourceView,
  resourceViewKey,
  type ResourceSavedView,
  type ResourceViewKind,
} from "@/lib/resource-saved-views";
import { ResourceSavedViewsControl } from "./ResourceSavedViewsControl";
let root: Root, host: HTMLDivElement, history: RouterHistory;
let identity = { org_id: "org", user_id: "user" };
let inventory: ResourceViewKind = "assets";
let overrides: Record<string, string> = {};
const key = (kind = inventory, owner = identity) =>
  operatorStorageKey(resourceViewKey(kind), owner)!;
const view = (name = "Reviewed"): ResourceSavedView => ({
  ...captureResourceView(inventory, new URLSearchParams("q=needle"))!,
  id: name,
  name,
});
beforeEach(() => {
  (
    globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }
  ).IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear();
  inventory = "assets";
  identity = { org_id: "org", user_id: "user" };
  overrides = {};
});
afterEach(() => {
  act(() => root?.unmount());
  host?.remove();
  vi.unstubAllGlobals();
  localStorage.clear();
  document.body.innerHTML = "";
});
async function rerender() {
  await act(async () =>
    root.render(
      <TablePreferencesProvider identity={{ ...identity }}>
        <TestRouter history={history}>
          <ResourceSavedViewsControl
            inventory={inventory}
            clusterId="cluster"
            ready
            overrides={overrides}
          />
        </TestRouter>
      </TablePreferencesProvider>,
    ),
  );
}
async function render(
  url = "/clusters/cluster/assets?page=3&selected=exact&context=kept#evidence",
) {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  history = createMemoryHistory({ initialEntries: [url] });
  await rerender();
}
async function open() {
  const trigger = [...host.querySelectorAll<HTMLButtonElement>("button")].find(
    (b) => b.textContent?.includes("Views"),
  )!;
  await act(async () => {
    trigger.focus();
    trigger.dispatchEvent(
      new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }),
    );
  });
  await vi.waitFor(() =>
    expect(document.querySelector('[aria-label="Saved views"]')).not.toBeNull(),
  );
}
it("opens dedicated authoring with exact return context and effective platform preference", async () => {
  inventory = "deployments";
  overrides = { hide_platform: "false" };
  await render(
    "/clusters/cluster/deployments?namespace=prod&page=3&selected=exact&context=kept#evidence",
  );
  await act(async () =>
    [...host.querySelectorAll<HTMLButtonElement>("button")]
      .find((b) => b.textContent?.trim() === "Save view" || b.getAttribute("aria-label") === "Save deployment view" || b.getAttribute("data-export-label") === "Save deployment view")!
      .click(),
  );
  await vi.waitFor(() =>
    expect(history.location.pathname).toBe(
      "/clusters/cluster/deployments/views/new",
    ),
  );
  expect(new URLSearchParams(history.location.search).get("page")).toBe("3");
  expect(new URLSearchParams(history.location.search).get("selected")).toBe(
    "exact",
  );
  expect(
    new URLSearchParams(history.location.search).get("hide_platform"),
  ).toBe("false");
  expect(history.location.hash).toBe("#evidence");
});
it("applies a stored view with first-page reset and preserved unrelated navigation context", async () => {
  localStorage.setItem(key(), JSON.stringify([view()]));
  await render();
  await open();
  await act(async () =>
    document
      .querySelector<HTMLButtonElement>('[aria-label="Apply view Reviewed"]')!
      .click(),
  );
  await vi.waitFor(() =>
    expect(new URLSearchParams(history.location.search).get("q")).toBe(
      "needle",
    ),
  );
  const params = new URLSearchParams(history.location.search);
  expect(params.has("page")).toBe(false);
  expect(params.has("selected")).toBe(false);
  expect(params.get("context")).toBe("kept");
  expect(history.location.hash).toBe("#evidence");
  await act(async () => history.back());
  await vi.waitFor(() =>
    expect(new URLSearchParams(history.location.search).get("page")).toBe("3"),
  );
});
it("rejects malformed persisted payloads visibly while valid views remain usable", async () => {
  localStorage.setItem(
    key(),
    JSON.stringify([
      view(),
      {
        id: "bad",
        name: "Broken",
        schema: 1,
        inventory: "assets",
        filters: { kind: [] },
      },
    ]),
  );
  await render();
  expect(host.textContent).toContain("rejected");
  await open();
  expect(
    document.querySelector('[aria-label="Apply view Reviewed"]'),
  ).not.toBeNull();
  expect(document.querySelector('[aria-label="Apply view Broken"]')).toBeNull();
});
it("honestly retains a view after storage refuses deletion", async () => {
  localStorage.setItem(key(), JSON.stringify([view()]));
  await render();
  const original = localStorage;
  vi.stubGlobal("localStorage", {
    getItem: original.getItem.bind(original),
    setItem: () => {
      throw new Error("quota");
    },
  });
  await open();
  await act(async () =>
    document
      .querySelector<HTMLButtonElement>('[aria-label="Delete view Reviewed"]')!
      .click(),
  );
  expect(host.textContent).toContain("could not be stored");
  expect(host.textContent).toContain("(1)");
});
it("does not expose another owner or inventory's stored views", async () => {
  localStorage.setItem(key(), JSON.stringify([view("Owner A")]));
  await render();
  await open();
  expect(
    document.querySelector('[aria-label="Apply view Owner A"]'),
  ).not.toBeNull();
  await act(async () =>
    document.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
    ),
  );
  identity = { org_id: "other", user_id: "other" };
  await rerender();
  await open();
  expect(
    document.querySelector('[aria-label="Apply view Owner A"]'),
  ).toBeNull();
  expect(host.textContent).toContain("(0)");
});
