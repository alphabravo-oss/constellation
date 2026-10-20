import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { operatorStorageKey } from "@/lib/operator-preferences";
import { FINDING_VIEWS_KEY, TIMELINE_VIEWS_KEY, type InventoryViewKind } from "@/lib/inventory-saved-views";
import { TestRouter } from "@/test/router";
import { FindingSavedViewFormPage, TimelineSavedViewFormPage } from "./InventorySavedViewFormPage";
const scope = vi.hoisted(() => ({ id: "cluster" as string | undefined, resolved: "cluster" as string | undefined, loading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: scope.id, cluster: scope.resolved ? { id: scope.resolved } : undefined, isLoading: scope.loading, error: scope.error }) }));
const kinds: InventoryViewKind[] = ["findings", "timeline"];
let identity: { org_id: string; user_id: string } | null;
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
const path = (kind: InventoryViewKind) => `/clusters/cluster/${kind}`;
const storageKey = (kind: InventoryViewKind, org = "org", user = "user") => operatorStorageKey(kind === "findings" ? FINDING_VIEWS_KEY : TIMELINE_VIEWS_KEY, { org_id: org, user_id: user })!;
beforeEach(() => { (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true; identity = { org_id: "org", user_id: "user" }; localStorage.clear(); });
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.unstubAllGlobals(); vi.restoreAllMocks(); localStorage.clear(); scope.id = "cluster"; scope.resolved = "cluster"; scope.loading = false; scope.error = null; });
async function renderPage(kind: InventoryViewKind, search = "", setup?: (qc: QueryClient) => void | Promise<void>) {
  host = document.createElement("div"); document.body.append(host); root = createRoot(host); history = createMemoryHistory({ initialEntries: [`${path(kind)}/views/new${search}`] }); client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); await setup?.(client); await rerender(kind);
}
async function rerender(kind: InventoryViewKind) { await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={identity ? { ...identity } : null}><TestRouter history={history}>{kind === "findings" ? <FindingSavedViewFormPage /> : <TimelineSavedViewFormPage />}</TestRouter></TablePreferencesProvider></QueryClientProvider>)); }
async function settle(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>("button")].find((item) => item.textContent === label || item.getAttribute("aria-label") === label)!;
async function name(value: string) { await act(async () => { const input = host.querySelector<HTMLInputElement>("#saved-view-name")!; Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); }); }
async function submit() { await act(async () => host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }))); }

it.each(kinds)("saves %s synchronously to the authenticated owner and returns with exact query/context/hash", async kind => {
  const context = kind === "findings" ? "?view=instances&kind=runtime&lifecycle=accepted&severity=high&fixable=1&q=api&group=asset&sort=age&order=asc&page=4&context=dashboard#evidence" : "?tab=custom&type=runtime_event,audit&severity=high&q=api&namespace=prod&workload=web&ref=rule&from=2026-10-10T00:00&to=2026-10-12T00:00&page=4&event=runtime_event:1&context=dashboard#evidence";
  await renderPage(kind, context); await name("  Investigation  ");
  expect(host.querySelector("details")!.open).toBe(false); expect(host.querySelector('a')!.getAttribute("href")).toBe(`${path(kind)}${new URL(history.location.href, "https://example.test").search ? `?${new URLSearchParams(new URL(history.location.href, "https://example.test").search)}` : ""}#evidence`);
  await submit();
  // Storage is inspectable immediately, before the router commits navigation.
  const saved = JSON.parse(localStorage.getItem(storageKey(kind))!); expect(saved).toHaveLength(1); expect(saved[0].name).toBe("Investigation"); expect(saved[0]).not.toHaveProperty("page"); expect(saved[0]).not.toHaveProperty("context");
  if (kind === "findings") expect(saved[0]).toMatchObject({ kind: "runtime", lifecycle: "accepted", query: "api", severity: "high", fixable: true, view: "instances", group: "asset", sort: "age", order: "asc" });
  else expect(saved[0]).toMatchObject({ category: "custom", sources: ["runtime_event", "audit"], namespace: "prod", workload: "web", reference: "rule", from: "2026-10-10T00:00", to: "2026-10-12T00:00" });
  await settle(() => expect(history.location.pathname).toBe(path(kind))); expect(history.location.hash).toBe("#evidence"); expect(new URLSearchParams(history.location.search).get("context")).toBe("dashboard"); expect(new URLSearchParams(history.location.search).get("page")).toBe("4");
  expect(localStorage.getItem(storageKey(kind, "another-org"))).toBeNull();
});
it.each(kinds)("Cancel leaves the %s draft unwritten and keeps filters and selected context", async kind => {
  await renderPage(kind, "?q=api&page=3&context=keep&event=runtime_event:1#event"); await name("Unwritten draft"); await act(async () => button("Cancel").click());
  await settle(() => expect(history.location.pathname).toBe(path(kind))); expect(localStorage.length).toBe(0); expect(new URLSearchParams(history.location.search).get("page")).toBe("3"); expect(history.location.hash).toBe("#event");
});
it.each(kinds)("requires a nonblank bounded %s view name", async kind => {
  await renderPage(kind); expect(button("Save").disabled).toBe(true); await name("   "); await submit(); expect(localStorage.length).toBe(0); await name("x".repeat(121)); await submit(); expect(localStorage.length).toBe(0);
});
it.each(kinds)("preserves %s draft and context after storage failure and can retry", async kind => {
  await renderPage(kind, "?q=api&context=keep"); await name("Retained draft");
  const original = localStorage; vi.stubGlobal("localStorage", { getItem: original.getItem.bind(original), setItem: () => { throw new Error("private quota details"); } }); await submit();
  expect(host.textContent).toContain("could not be stored"); expect(host.textContent).not.toContain("private quota details"); expect(host.querySelector<HTMLInputElement>("#saved-view-name")!.value).toBe("Retained draft"); expect(history.location.pathname).toContain("/views/new");
  vi.unstubAllGlobals(); await submit(); await settle(() => expect(history.location.pathname).toBe(path(kind))); expect(JSON.parse(localStorage.getItem(storageKey(kind))!)[0].name).toBe("Retained draft");
});
it.each(kinds)("prevents a duplicate %s write while navigation is committing", async kind => {
  await renderPage(kind); await name("One view"); await act(async () => { const form = host.querySelector("form")!; form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); }); expect(JSON.parse(localStorage.getItem(storageKey(kind))!)).toHaveLength(1);
});
it.each(kinds.flatMap(kind => ["missing", "foreign", "loading", "error-stale", "session"].map(condition => [kind, condition] as const)))("blocks %s form for %s scope", async (kind, condition) => {
  if (condition === "missing") scope.id = undefined; if (condition === "foreign") scope.resolved = "foreign"; if (condition === "loading") scope.loading = true; if (condition === "error-stale") scope.error = new Error("scope failed"); if (condition === "session") identity = null;
  await renderPage(kind); expect(host.querySelector("form")).toBeNull(); expect(localStorage.length).toBe(0);
});
it.each(kinds)("keeps a %s name draft through transient scope loss and blocks Save until recovery", async kind => {
  await renderPage(kind); await name("Retained scope draft"); scope.error = new Error("refresh failed"); await rerender(kind); expect(button("Save").disabled).toBe(true); await submit(); expect(localStorage.length).toBe(0); expect(host.querySelector<HTMLInputElement>("#saved-view-name")!.value).toBe("Retained scope draft");
  scope.error = null; await rerender(kind); expect(button("Save").disabled).toBe(false); await submit(); expect(JSON.parse(localStorage.getItem(storageKey(kind))!)[0].name).toBe("Retained scope draft");
});
it.each(kinds)("does not reuse a %s name draft for a different authenticated owner", async kind => {
  await renderPage(kind); await name("Prior owner draft"); identity = { org_id: "another-org", user_id: "another-user" }; await rerender(kind); expect(host.querySelector<HTMLInputElement>("#saved-view-name")!.value).toBe(""); expect(localStorage.length).toBe(0);
});
it.each(kinds)("rejects invalid %s filter payloads before offering a writable form", async kind => {
  await renderPage(kind, kind === "findings" ? "?kind=invalid" : "?tab=custom&type=invalid"); expect(host.textContent).toContain("current filters are invalid"); expect(host.querySelector("form")).toBeNull(); expect(localStorage.length).toBe(0);
});
it.each(kinds)("rechecks the latest cluster cache before a %s persistence action", async kind => {
  await renderPage(kind); await name("Guarded draft"); await act(async () => { client.setQueryData(["clusters"], { clusters: [] }); host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); }); expect(localStorage.length).toBe(0);
});
