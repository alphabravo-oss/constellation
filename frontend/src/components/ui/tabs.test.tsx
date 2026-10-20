import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { afterEach, expect, it, vi } from "vitest";
import { TestRouter } from "@/test/router";
import { Tabs, useTabParam } from "./tabs";

let root: Root;
let host: HTMLDivElement;
let history: RouterHistory;

function Workspace() {
  const [tab, setTab] = useTabParam("tab", "inventory");
  return <Tabs value={tab} onValueChange={setTab} items={[
    { value: "inventory", label: "Inventory", content: <p>Inventory records</p> },
    { value: "health", label: "Health", content: <p>Health records</p> },
    { value: "versions", label: "Versions", content: <p>Version records</p> },
  ]} />;
}

async function render(url: string) {
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
  history = createMemoryHistory({ initialEntries: [url] });
  await act(async () => root.render(<TestRouter history={history}><Workspace /></TestRouter>));
  await vi.waitFor(() => expect(host.querySelector('[role="tab"]')).not.toBeNull());
}

async function select(label: string) {
  const trigger = [...host.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find((item) => item.textContent === label || item.getAttribute("aria-label") === label)!;
  // Radix activates tabs on keyboard focus as well as pointer-down.
  await act(async () => trigger.focus());
  await vi.waitFor(() => expect(trigger.getAttribute("aria-selected")).toBe("true"));
}

afterEach(() => { act(() => root?.unmount()); host?.remove(); });

it("restores URL tabs through Back/Forward while retaining filters and the fragment", async () => {
  await render("/components?q=scanner&role=enforcer#evidence");
  await select("Health");
  expect(history.location.search).toBe("?q=scanner&role=enforcer&tab=health");
  expect(history.location.hash).toBe("#evidence");
  expect(host.querySelector('[role="tabpanel"][data-state="active"]')?.textContent).toBe("Health records");
  await select("Versions");
  await act(async () => history.back());
  await vi.waitFor(() => expect(host.querySelector('[role="tab"][aria-selected="true"]')?.textContent).toBe("Health"));
  await act(async () => history.back());
  await vi.waitFor(() => expect(host.querySelector('[role="tab"][aria-selected="true"]')?.textContent).toBe("Inventory"));
  expect(history.location.search).toBe("?q=scanner&role=enforcer");
  await act(async () => history.forward());
  await vi.waitFor(() => expect(host.querySelector('[role="tab"][aria-selected="true"]')?.textContent).toBe("Health"));
});

it("loads a deep-linked tab and removes only its key when returning to the default", async () => {
  await render("/components?tab=versions&component=worker&context=dashboard");
  expect(host.querySelector('[role="tabpanel"][data-state="active"]')?.textContent).toBe("Version records");
  await select("Inventory");
  expect(history.location.search).toBe("?component=worker&context=dashboard");
  await act(async () => history.back());
  await vi.waitFor(() => expect(host.querySelector('[role="tab"][aria-selected="true"]')?.textContent).toBe("Versions"));
});
