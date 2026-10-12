import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { findings, type Finding } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { FindingAcceptRiskFormPage, FindingSuppressFormPage, FindingCommentFormPage } from "./FindingActionFormPage";
import { FindingDetailPage } from "./FindingDetailPage";
const route = vi.hoisted(() => ({ fid: "finding", clusterId: "cluster" as string | undefined, resolvedClusterId: "cluster" as string | undefined, loading: false, error: null as Error | null, navigate: vi.fn() }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: route.clusterId, cluster: route.resolvedClusterId ? { id: route.resolvedClusterId } : undefined, isLoading: route.loading, error: route.error }) }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ fid: route.fid }), useNavigate: () => route.navigate, Link: ({ children, href, to: _to, ...props }: { children: ReactNode; href?: string; to?: string }) => <a href={href} {...props}>{children}</a> }));
vi.mock("@/api/client", () => ({ findings: { get: vi.fn(), acceptRisk: vi.fn(), suppress: vi.fn(), addComment: vi.fn(), listComments: vi.fn() } }));
const identity = { org_id: "org", user_id: "11111111-1111-1111-1111-111111111111" };
const finding: Finding = { id: "finding", cluster_id: "cluster", title: "Saved finding", kind: "vulnerability", external_id: "CVE-test", severity: "high", risk_score: 75, lifecycle: "open", asset_id: "asset", attack_techniques: [], first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-01T00:00:00Z" };
const kinds = ["accept", "suppress", "comment"] as const;
type Kind = typeof kinds[number];
const page = (kind: Kind | "detail") => kind === "accept" ? <FindingAcceptRiskFormPage /> : kind === "suppress" ? <FindingSuppressFormPage /> : kind === "comment" ? <FindingCommentFormPage /> : <FindingDetailPage />;
let root: Root; let host: HTMLDivElement; let client: QueryClient;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  vi.mocked(findings.get).mockResolvedValue(finding); vi.mocked(findings.acceptRisk).mockResolvedValue({ status: "ok" }); vi.mocked(findings.suppress).mockResolvedValue({ status: "ok" });
  vi.mocked(findings.addComment).mockResolvedValue({ id: "comment", finding_id: "finding", author_id: identity.user_id, body: "comment", created_at: "2026-01-01T00:00:00Z" });
  vi.mocked(findings.listComments).mockResolvedValue({ comments: [] });
});
afterEach(() => {
  act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); vi.restoreAllMocks();
  route.fid = "finding"; route.clusterId = "cluster"; route.resolvedClusterId = "cluster"; route.loading = false; route.error = null;
});
async function renderPage(kind: Kind | "detail", beforeRender?: (queryClient: QueryClient) => void | Promise<void>) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await beforeRender?.(client); await rerenderPage(kind);
}
async function rerenderPage(kind: Kind | "detail") { await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={identity}>{page(kind)}</TablePreferencesProvider></QueryClientProvider>)); }
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function change(selector: string, value: string) { await act(async () => { const input = host.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)!; const prototype = input.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); }); }
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>("button")].find((item) => item.textContent?.trim() === label)!;
async function submit() { await act(async () => host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }))); }
function noWrites() { expect(findings.acceptRisk).not.toHaveBeenCalled(); expect(findings.suppress).not.toHaveBeenCalled(); expect(findings.addComment).not.toHaveBeenCalled(); }
async function draft(kind: Kind) { await renderPage(kind); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await change("#finding-action-text", "  Retained justification and controls  "); }

it.each(kinds)("saves the dedicated %s action against its confirmed entity and returns to its cluster detail", async (kind) => {
  await draft(kind); await submit(); await settled(() => expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/findings/finding" }));
  expect(findings.get).toHaveBeenCalledWith("finding");
  if (kind === "accept") { expect(findings.acceptRisk).toHaveBeenCalledWith("finding", { reason: "Retained justification and controls", accepted_until: expect.any(String) }); const expiry = new Date(vi.mocked(findings.acceptRisk).mock.calls[0][1].accepted_until).getTime(); expect(expiry).toBeGreaterThan(Date.now()); expect(expiry).toBeLessThanOrEqual(Date.now() + 30 * 86400_000); }
  else if (kind === "suppress") expect(findings.suppress).toHaveBeenCalledWith("finding", { reason: "Retained justification and controls" });
  else expect(findings.addComment).toHaveBeenCalledWith("finding", { body: "Retained justification and controls" });
});
it.each(kinds)("Cancel and back links leave the %s draft without writes", async (kind) => {
  await draft(kind); expect(host.querySelector('a[href="/clusters/cluster/findings/finding"]')).not.toBeNull(); await act(async () => button("Cancel").click());
  expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/findings/finding" }); noWrites();
});
it.each(kinds.flatMap((kind) => ["missing-id", "missing-cluster", "foreign-cluster", "loading", "error-stale"].map((scenario) => [kind, scenario] as const)))("blocks initial %s authoring for %s scope", async (kind, scenario) => {
  if (scenario === "missing-id") route.fid = "";
  if (scenario === "missing-cluster") route.clusterId = undefined;
  if (scenario === "foreign-cluster") route.resolvedClusterId = "foreign";
  if (scenario === "loading") route.loading = true;
  if (scenario === "error-stale") route.error = new Error("private scope details");
  await renderPage(kind); expect(host.querySelector("form")).toBeNull(); expect(findings.get).not.toHaveBeenCalled(); noWrites(); expect(host.textContent).not.toContain("private scope details");
});
it.each(kinds.flatMap((kind) => ["failed", "missing", "wrong-id", "foreign", "unscoped"].map((scenario) => [kind, scenario] as const)))("blocks initial %s authoring when the exact entity load is %s", async (kind, scenario) => {
  if (scenario === "failed") vi.mocked(findings.get).mockRejectedValue(new Error("private entity details"));
  else vi.mocked(findings.get).mockResolvedValue(scenario === "missing" ? undefined as unknown as Finding : { ...finding, ...(scenario === "wrong-id" ? { id: "another" } : scenario === "foreign" ? { cluster_id: "foreign" } : { cluster_id: undefined }) });
  await renderPage(kind); await settled(() => expect(host.textContent).toContain("This finding could not be loaded in the selected cluster"));
  expect(host.querySelector("form")).toBeNull(); noWrites(); expect(host.textContent).not.toContain("private entity details");
});
it.each(kinds)("does not freeze stale cached entity data before its initial refresh for %s", async (kind) => {
  let resolve!: (value: Finding) => void;
  vi.mocked(findings.get).mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
  await renderPage(kind, (queryClient) => { queryClient.setQueryData(["finding", "cluster", "finding"], { ...finding, title: "Old cached title" }); });
  expect(host.querySelector("form")).toBeNull();
  await act(async () => resolve({ ...finding, title: "Fresh confirmed title" }));
  await settled(() => expect(host.querySelector("form")).not.toBeNull()); expect(host.textContent).toContain("Fresh confirmed title"); expect(host.textContent).not.toContain("Old cached title");
});
it.each(kinds)("preserves %s drafts after a failed save and remote record refresh", async (kind) => {
  if (kind === "accept") vi.mocked(findings.acceptRisk).mockRejectedValue(new Error("private mutation details")); else if (kind === "suppress") vi.mocked(findings.suppress).mockRejectedValue(new Error("private mutation details")); else vi.mocked(findings.addComment).mockRejectedValue(new Error("private mutation details"));
  await draft(kind); await act(async () => client.setQueryData(["finding", "cluster", "finding"], { ...finding, title: "Changed remotely" }));
  expect(host.querySelector<HTMLTextAreaElement>("#finding-action-text")!.value).toBe("  Retained justification and controls  ");
  await submit(); await settled(() => expect(host.textContent).toContain("Could not save this finding action. Your draft is preserved"));
  expect(host.querySelector<HTMLTextAreaElement>("#finding-action-text")!.value).toBe("  Retained justification and controls  "); expect(route.navigate).not.toHaveBeenCalled(); expect(host.textContent).not.toContain("private mutation details");
});
it.each(kinds.flatMap((kind) => ["error", "foreign", "missing", "loading"].map((scenario) => [kind, scenario] as const)))("preserves the %s draft and blocks writes during transient %s cluster resolution", async (kind, scenario) => {
  await draft(kind);
  if (scenario === "error") route.error = new Error("private scope details"); if (scenario === "foreign") route.resolvedClusterId = "foreign"; if (scenario === "missing") route.resolvedClusterId = undefined; if (scenario === "loading") route.loading = true;
  await rerenderPage(kind); expect(button("Save").disabled).toBe(true); await submit(); noWrites(); expect(host.querySelector<HTMLTextAreaElement>("#finding-action-text")!.value).toContain("Retained justification");
  route.error = null; route.resolvedClusterId = "cluster"; route.loading = false; await rerenderPage(kind); await settled(() => expect(button("Save").disabled).toBe(false));
  expect(host.querySelector<HTMLTextAreaElement>("#finding-action-text")!.value).toContain("Retained justification");
});
it.each(kinds)("retains the %s draft through real entity refresh failure and recovery", async (kind) => {
  await draft(kind); let reject!: (error: Error) => void;
  vi.mocked(findings.get).mockImplementationOnce(() => new Promise((_done, fail) => { reject = fail; }));
  await act(async () => { void client.invalidateQueries({ queryKey: ["finding"] }); });
  await settled(() => expect(button("Save").disabled).toBe(true)); await submit(); noWrites();
  await act(async () => reject(new Error("private refresh details"))); await settled(() => expect(host.textContent).toContain("Current finding or cluster scope is unavailable"));
  expect(host.querySelector<HTMLTextAreaElement>("#finding-action-text")!.value).toContain("Retained justification");
  await act(async () => button("Retry").click()); await settled(() => expect(button("Save").disabled).toBe(false));
});
it.each(kinds)("blocks stale %s writes when exact entity scope changes before observer notification", async (kind) => {
  await draft(kind);
  await act(async () => { client.setQueryData(["finding", "cluster", "finding"], { ...finding, cluster_id: "foreign" }); host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  await settled(() => expect(host.textContent).toContain("Your draft is preserved")); noWrites();
});
it.each(kinds)("rechecks cached cluster identity before %s writes", async (kind) => {
  await draft(kind);
  await act(async () => { client.setQueryData(["clusters"], { clusters: [] }); host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  await settled(() => expect(host.textContent).toContain("Could not save this finding action")); noWrites();
});
it.each(kinds)("starts a new %s draft when the route changes entity", async (kind) => {
  await draft(kind); route.fid = "another"; vi.mocked(findings.get).mockResolvedValue({ ...finding, id: "another", title: "Another entity" }); await rerenderPage(kind);
  await settled(() => expect(host.textContent).toContain("Another entity")); expect(host.querySelector<HTMLTextAreaElement>("#finding-action-text")!.value).toBe(""); expect(host.querySelector('a[href="/clusters/cluster/findings/another"]')).not.toBeNull(); expect(host.querySelector('a[href="/clusters/cluster/findings/finding"]')).toBeNull(); noWrites();
});
it("validates risk justification and expiry instead of silently clamping dates", async () => {
  await renderPage("accept"); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await change("#finding-action-text", "too short"); await submit(); noWrites(); expect(button("Save").disabled).toBe(true);
  await change("#finding-action-text", "Valid rationale with controls");
  for (const value of ["", "2020-01-01T00:00", "2099-01-01T00:00"]) { await change("#finding-action-expiry", value); expect(button("Save").disabled).toBe(true); await submit(); noWrites(); }
  await change("#finding-action-expiry", new Date(Date.now() + 86400_000).toISOString().slice(0, 16)); expect(button("Save").disabled).toBe(false);
});
it("validates an optional approver, prevents self approval and preserves the advanced draft on failed save", async () => {
  await draft("accept"); expect(host.querySelector("details")!.open).toBe(false); await act(async () => host.querySelector("summary")!.click());
  for (const value of ["not-a-uuid", identity.user_id]) { await change("#finding-action-approver", value); expect(button("Save").disabled).toBe(true); await submit(); noWrites(); }
  const approver = "22222222-2222-2222-2222-222222222222"; await change("#finding-action-approver", approver);
  vi.mocked(findings.acceptRisk).mockRejectedValue(new Error("policy rejected")); await submit(); await settled(() => expect(host.textContent).toContain("Could not save this finding action"));
  expect(findings.acceptRisk).toHaveBeenCalledWith("finding", expect.objectContaining({ approver_id: approver })); expect(host.querySelector<HTMLInputElement>("#finding-action-approver")!.value).toBe(approver);
});
it.each(["suppress", "comment"] as const)("requires a nonblank %s reason/body", async (kind) => {
  await draft(kind); await change("#finding-action-text", "   "); expect(button("Save").disabled).toBe(true); await submit(); noWrites();
});
it("enforces the backend comment byte limit for unicode drafts", async () => {
  await draft("comment"); await change("#finding-action-text", "😀".repeat(4001)); expect(button("Save").disabled).toBe(true); await submit(); noWrites();
  await change("#finding-action-text", "😀".repeat(4000)); expect(button("Save").disabled).toBe(false);
});
it("keeps detail history read-only and links to dedicated actions in the same cluster", async () => {
  vi.mocked(findings.listComments).mockResolvedValue({ comments: [{ id: "history", finding_id: "finding", author_id: identity.user_id, body: "Saved history", created_at: "2026-01-01T00:00:00Z" }] });
  await renderPage("detail"); await settled(() => expect(host.textContent).toContain("Saved history"));
  expect(host.querySelector("form,textarea,input")).toBeNull();
  for (const path of ["accept-risk", "suppress", "comments/new"]) expect(host.querySelector(`a[href="/clusters/cluster/findings/finding/${path}"]`)).not.toBeNull();
  expect(host.querySelector('a[href="/clusters/cluster/findings"]')).not.toBeNull(); noWrites();
});
it("distinguishes failed history from an empty thread and retries it", async () => {
  vi.mocked(findings.listComments).mockRejectedValueOnce(new Error("private comments details"));
  await renderPage("detail"); await settled(() => expect(host.textContent).toContain("Comment history could not be loaded")); expect(host.textContent).not.toContain("No comments yet");
  await act(async () => button("Retry comments").click()); await settled(() => expect(host.textContent).toContain("No comments yet"));
});
it("keeps detail exception and asset links within the confirmed cluster", async () => {
  vi.mocked(findings.get).mockResolvedValue({ ...finding, lifecycle: "accepted", accepted_until: "2099-01-01T00:00:00Z" }); await renderPage("detail");
  await settled(() => expect(host.querySelector('[data-testid="finding-exception-link"]')).not.toBeNull());
  expect(host.querySelector('[data-testid="finding-exception-link"]')!.getAttribute("href")).toContain("/clusters/cluster/exceptions?");
  expect(host.querySelector('[data-testid="finding-affected-asset-risk"]')!.getAttribute("href")).toBe("/clusters/cluster/risk/asset/asset");
});
it("does not expose detail or action links for a foreign entity", async () => {
  vi.mocked(findings.get).mockResolvedValue({ ...finding, cluster_id: "foreign" }); await renderPage("detail");
  await settled(() => expect(host.textContent).toContain("This finding could not be loaded in the selected cluster")); expect(findings.listComments).not.toHaveBeenCalled(); expect(host.querySelector('a[href$="accept-risk"]')).toBeNull();
});
it.each(kinds)("blocks initial %s authoring until the cached cluster refresh settles", async (kind) => {
  let resolve!: (value: { clusters: Array<{ id: string }> }) => void;
  await renderPage(kind, (queryClient) => {
    queryClient.setQueryData(["clusters"], { clusters: [{ id: "cluster" }] });
    void queryClient.fetchQuery({ queryKey: ["clusters"], queryFn: () => new Promise<{ clusters: Array<{ id: string }> }>((done) => { resolve = done; }) }).catch(() => {});
  });
  expect(host.querySelector("form")).toBeNull(); expect(findings.get).not.toHaveBeenCalled();
  await act(async () => resolve({ clusters: [{ id: "cluster" }] })); await settled(() => expect(host.querySelector("form")).not.toBeNull());
});
it.each(kinds)("does not expose initial %s authoring with a failed cached registry and stale cluster identity", async (kind) => {
  await renderPage(kind, async (queryClient) => {
    queryClient.setQueryData(["clusters"], { clusters: [{ id: "cluster" }] });
    await queryClient.fetchQuery({ queryKey: ["clusters"], queryFn: () => Promise.reject(new Error("registry failed")) }).catch(() => {});
  });
  expect(host.querySelector("form")).toBeNull(); expect(findings.get).not.toHaveBeenCalled(); noWrites();
});
it.each(kinds)("does not initialize %s authoring when cluster scope fails during the initial entity request", async (kind) => {
  let resolve!: (value: Finding) => void;
  vi.mocked(findings.get).mockImplementationOnce(() => new Promise((done) => { resolve = done; })); await renderPage(kind);
  route.error = new Error("scope failed"); await rerenderPage(kind); await act(async () => resolve(finding));
  expect(host.querySelector("form")).toBeNull(); noWrites(); route.error = null; await rerenderPage(kind); await settled(() => expect(host.querySelector("form")).not.toBeNull());
});
it.each(kinds)("preserves %s draft and blocks Save during an actual cluster registry refresh", async (kind) => {
  await draft(kind); let resolve!: (value: { clusters: Array<{ id: string }> }) => void;
  await act(async () => {
    client.setQueryData(["clusters"], { clusters: [{ id: "cluster" }] });
    void client.fetchQuery({ queryKey: ["clusters"], queryFn: () => new Promise<{ clusters: Array<{ id: string }> }>((done) => { resolve = done; }) }).catch(() => {});
  });
  await settled(() => expect(button("Save").disabled).toBe(true)); await submit(); noWrites(); expect(host.querySelector<HTMLTextAreaElement>("#finding-action-text")!.value).toContain("Retained justification");
  await act(async () => resolve({ clusters: [{ id: "cluster" }] })); await settled(() => expect(button("Save").disabled).toBe(false));
});
it.each(kinds)("blocks %s writes if a refresh begins before query observer notification", async (kind) => {
  await draft(kind); let resolve!: (value: Finding) => void;
  vi.mocked(findings.get).mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
  await act(async () => { void client.invalidateQueries({ queryKey: ["finding"] }); host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  await settled(() => expect(button("Save").disabled).toBe(true)); noWrites(); await act(async () => resolve(finding));
});
it("updates detail action and asset links when the active entity and cluster change", async () => {
  await renderPage("detail"); await settled(() => expect(host.querySelector('a[href="/clusters/cluster/findings/finding/accept-risk"]')).not.toBeNull());
  route.fid = "another"; route.clusterId = "another-cluster"; route.resolvedClusterId = "another-cluster";
  vi.mocked(findings.get).mockResolvedValue({ ...finding, id: "another", cluster_id: "another-cluster", asset_id: "another-asset", lifecycle: "accepted" });
  await rerenderPage("detail"); await settled(() => expect(host.querySelector('a[href="/clusters/another-cluster/findings/another/accept-risk"]')).not.toBeNull());
  expect(host.querySelector('a[href="/clusters/cluster/findings/finding/accept-risk"]')).toBeNull();
  expect(host.querySelector('a[href="/clusters/another-cluster/findings"]')).not.toBeNull();
  expect(host.querySelector('[data-testid="finding-affected-asset-detail"]')!.getAttribute("href")).toBe("/clusters/another-cluster/assets/another-asset");
  expect(host.querySelector('[data-testid="finding-exception-link"]')!.getAttribute("href")).toContain("/clusters/another-cluster/exceptions?");
  noWrites();
});
