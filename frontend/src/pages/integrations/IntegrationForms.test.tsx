import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { receivers, routing, systemConfigApi, type SystemConfigResponse } from "@/api/client";
import { RoutingRuleFormPage } from "./RoutingRuleFormPage";
import { RoutingConfigFormPage } from "./RoutingConfigFormPage";
import { SmtpSettingsFormPage } from "./SmtpSettingsFormPage";
import { parseRouting } from "@/lib/integration-routing";

/** Kit Select keeps a hidden native mirror right before its trigger. */
function nativeSelect(root: ParentNode, selector: string): HTMLSelectElement | null {
  const element = root.querySelector(selector);
  if (!element) return null;
  if (element.tagName === "SELECT") return element as HTMLSelectElement;
  const previous = element.previousElementSibling;
  return previous?.tagName === "SELECT" ? previous as HTMLSelectElement : null;
}
const route = vi.hoisted(() => ({ index: "0" as string | undefined, search: "revision=4", navigate: vi.fn() }));
vi.mock("@/api/client", () => ({ routing: { get: vi.fn(), put: vi.fn() }, receivers: { list: vi.fn() }, systemConfigApi: { get: vi.fn(), patch: vi.fn() } }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(route.search), vi.fn()] }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ routeIndex: route.index }), useNavigate: () => route.navigate, Link: ({ children, href }: { children: ReactNode; href?: string }) => <a href={href}>{children}</a> }));
// monaco-editor ships only an ESM `module` entry (no `main`/`exports`), which vitest's node-side
// resolver cannot see; the loader wiring in src/lib/monaco is irrelevant with the editor mocked.
vi.mock("@/lib/monaco", () => ({}));
vi.mock("@monaco-editor/react", () => ({ default: ({ value, onChange, options }: { value: string; onChange: (value: string) => void; options?: { readOnly?: boolean } }) => <textarea aria-label="Routing YAML" value={value} disabled={options?.readOnly} onChange={(e) => onChange(e.target.value)} /> }));
(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const saved = { yaml: "route:\n  receiver: external-default\n  group_wait: 30s\n  routes:\n    - receiver: external-sink\n      match: {severity: critical}\n      matchers: ['owner=platform']\n      group_interval: 5m\ninhibit_rules: []\n", revision: 4, updated_at: "" };
const config = { revision: 7, config: { smtp: { host: "smtp.example.test", port: 587, username: "alerts", password: "***REDACTED***", from: "alerts@example.test", starttls: true } } } as unknown as SystemConfigResponse;
let root: Root; let host: HTMLDivElement; let client: QueryClient;
beforeEach(() => { route.index = "0"; route.search = "revision=4"; vi.mocked(routing.get).mockResolvedValue(saved); vi.mocked(receivers.list).mockResolvedValue({ receivers: [], delivery_history: [] }); vi.mocked(systemConfigApi.get).mockResolvedValue(config); });
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); });
async function renderPage(page = "rule") { host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); await act(async () => root.render(<QueryClientProvider client={client}>{page === "rule" ? <RoutingRuleFormPage /> : page === "raw" ? <RoutingConfigFormPage /> : <SmtpSettingsFormPage />}</QueryClientProvider>)); }
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
function button(text: string) { return [...host.querySelectorAll("button")].find((b) => b.textContent?.trim() === text || b.getAttribute("aria-label") === text || b.getAttribute("data-export-label") === text)!; }
async function click(text: string) { await act(async () => button(text).click()); }
async function change(selector: string, value: string) { await act(async () => { const el = (nativeSelect(host, selector) ?? host.querySelector<HTMLSelectElement | HTMLInputElement | HTMLTextAreaElement>(selector))!; const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value); el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? "change" : "input", { bubbles: true })); }); }
async function ready() { await settled(() => expect(host.querySelector("form")).not.toBeNull()); }
it.each(["stale", "missing-index", "invalid-index", "missing-revision"])("blocks a %s route edit instead of editing another route", async (scenario) => {
  if (scenario === "stale") route.search = "revision=3"; else if (scenario === "missing-index") route.index = "8"; else if (scenario === "invalid-index") route.index = "-1"; else route.search = "";
  await renderPage(); await settled(() => expect(host.querySelector('[data-testid="error-state"]')).not.toBeNull()); expect(host.querySelector("form")).toBeNull(); expect(routing.put).not.toHaveBeenCalled();
});
it.each(["rule", "raw", "smtp"])("does not expose a blank %s form after an initial fetch failure", async (page) => {
  vi.mocked(routing.get).mockRejectedValue(new Error("private transport")); vi.mocked(systemConfigApi.get).mockRejectedValue(new Error("private transport")); await renderPage(page); await settled(() => expect(host.querySelector('[data-testid="error-state"]')).not.toBeNull()); expect(host.querySelector("form")).toBeNull(); expect(host.textContent).not.toContain("private transport");
});
it("saves a route using its loaded revision and preserves advanced fields and external names", async () => {
  vi.mocked(routing.put).mockResolvedValue({ status: "ok", revision: 5 }); await renderPage(); await ready(); await settled(() => expect(button("Save route").disabled).toBe(false)); expect(nativeSelect(host, "#route-receiver")?.value).toBe("external-sink"); await change("#route-value-0", "high"); await click("Save route");
  await settled(() => expect(route.navigate).toHaveBeenCalledWith({ href: "/settings/integrations?tab=routes" })); const [text, revision] = vi.mocked(routing.put).mock.calls[0]; expect(revision).toBe(4); const parsed = parseRouting(text); expect(parsed.ok).toBe(true); if (parsed.ok) { expect(parsed.model.routes[0]).toMatchObject({ receiver: "external-sink", match: { severity: "high" }, matchers: ["owner=platform"], raw: { group_interval: "5m" } }); expect(parsed.model.rootRaw).toEqual({ group_wait: "30s" }); expect(parsed.model.docRaw).toEqual({ inhibit_rules: [] }); }
});
it("creates and persists a route on one Save without a separate list-page draft", async () => {
  route.index = undefined; route.search = ""; vi.mocked(routing.put).mockResolvedValue({ status: "ok", revision: 5 }); await renderPage(); await ready(); await settled(() => expect(button("Save route").disabled).toBe(false)); await click("Add condition"); await change("#route-label-0", "team"); await change("#route-value-0", "security"); await click("Save route"); await settled(() => expect(routing.put).toHaveBeenCalledTimes(1)); const parsed = parseRouting(vi.mocked(routing.put).mock.calls[0][0]); if (!parsed.ok) throw new Error(parsed.reason); expect(parsed.model.routes).toHaveLength(2); expect(parsed.model.routes[1].match).toEqual({ team: "security" });
});
it("retains route edits and blocks Save after a refreshed revision changes", async () => {
  await renderPage(); await ready(); await change("#route-value-0", "unsaved"); await act(async () => { client.setQueryData(["routing-yaml"], { ...saved, revision: 5 }); }); await settled(() => expect(button("Save route").disabled).toBe(true)); expect(host.querySelector<HTMLInputElement>("#route-value-0")?.value).toBe("unsaved"); expect(host.textContent).toContain("Your draft is preserved");
});
it("preserves raw nested YAML across refresh errors and saves its exact text with a revision", async () => {
  const nested = "route:\n  receiver: external\n  routes:\n    - receiver: outer\n      routes:\n        - receiver: inner\ncustom_metadata:\n  keep: true\n"; vi.mocked(routing.get).mockResolvedValue({ ...saved, yaml: nested }); await renderPage("raw"); await ready(); expect(host.querySelector("details")?.open).toBe(true); await change("textarea", `${nested}# unsaved comment\n`); vi.mocked(routing.get).mockRejectedValue(new Error("private")); await act(async () => { await client.invalidateQueries({ queryKey: ["routing-yaml"] }); }); await settled(() => expect(host.textContent).toContain("Could not refresh routing")); expect(host.querySelector("textarea")?.value).toBe(`${nested}# unsaved comment\n`); expect(button("Save routing").disabled).toBe(true);
  vi.mocked(routing.get).mockResolvedValue({ ...saved, yaml: nested }); await act(async () => { await client.invalidateQueries({ queryKey: ["routing-yaml"] }); }); await settled(() => expect(button("Save routing").disabled).toBe(false)); vi.mocked(routing.put).mockRejectedValue({ response: { status: 412 } }); await click("Save routing"); await settled(() => expect(host.textContent).toContain("Reopen the latest saved revision")); expect(routing.put).toHaveBeenCalledWith(`${nested}# unsaved comment\n`, 4); expect(host.querySelector("textarea")?.value).toBe(`${nested}# unsaved comment\n`); expect(button("Save routing").disabled).toBe(true);
});
it("keeps a failed raw Save and never exposes transport details", async () => {
  vi.mocked(routing.put).mockRejectedValue(new Error("private transport")); await renderPage("raw"); await ready(); await change("textarea", `${saved.yaml}# draft\n`); await click("Save routing"); await settled(() => expect(host.textContent).toContain("Could not save routing. Your draft is preserved")); expect(host.querySelector("textarea")?.value).toContain("# draft"); expect(host.textContent).not.toContain("private transport"); expect(route.navigate).not.toHaveBeenCalled();
});
it("uses the loaded SMTP revision and preserves the redacted password", async () => {
  vi.mocked(systemConfigApi.patch).mockResolvedValue(config); await renderPage("smtp"); await ready(); expect(host.querySelector("details")?.open).toBe(false); await change("#smtp-host", "smtp.updated.test"); await click("Save email settings"); await settled(() => expect(systemConfigApi.patch).toHaveBeenCalledWith({ smtp: { ...config.config.smtp as object, host: "smtp.updated.test" } }, 7)); await settled(() => expect(route.navigate).toHaveBeenCalledWith({ href: "/settings/integrations" }));
});
it("keeps SMTP edits after background refresh and atomic conflict", async () => {
  await renderPage("smtp"); await ready(); await change("#smtp-host", "smtp.draft.test"); await act(async () => { client.setQueryData(["system-config"], { ...config, config: { smtp: { host: "changed.test" } } }); }); await settled(() => expect(host.querySelector<HTMLInputElement>("#smtp-host")?.value).toBe("smtp.draft.test")); vi.mocked(systemConfigApi.patch).mockRejectedValue({ response: { status: 412 } }); await click("Save email settings"); await settled(() => expect(host.textContent).toContain("Reopen the latest settings")); expect(host.querySelector<HTMLInputElement>("#smtp-host")?.value).toBe("smtp.draft.test"); expect(button("Save email settings").disabled).toBe(true);
});
it("validates SMTP ports and cancels without writing", async () => { await renderPage("smtp"); await ready(); await change("#smtp-port", "70000"); expect(button("Save email settings").disabled).toBe(true); await click("Cancel"); expect(systemConfigApi.patch).not.toHaveBeenCalled(); });
