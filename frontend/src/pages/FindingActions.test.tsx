import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { findings, type Finding } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { FindingAcceptRiskFormPage, FindingSuppressFormPage, FindingCommentFormPage } from "./FindingActionFormPage";
import { FindingDetailPage } from "./FindingDetailPage";
const route = vi.hoisted(() => ({ fid: "finding", clusterId: "cluster" as string | undefined, resolvedClusterId: "cluster" as string | undefined, loading: false, error: null as Error | null, navigate: vi.fn(), search: "first_seen_at=2026-01-01T00%3A00%3A00Z", setSearch: vi.fn() }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(route.search), route.setSearch] }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: route.clusterId, cluster: route.resolvedClusterId ? { id: route.resolvedClusterId } : undefined, isLoading: route.loading, error: route.error }) }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ fid: route.fid }), useNavigate: () => route.navigate, Link: ({ children, href, to: _to, ...props }: { children: ReactNode; href?: string; to?: string }) => <a href={href} {...props}>{children}</a> }));
vi.mock("@/api/client", () => ({ findings: { get: vi.fn(), instance: vi.fn(), instanceAcceptRisk: vi.fn(), instanceSuppress: vi.fn(), instanceAddComment: vi.fn(), instanceComments: vi.fn() } }));
const identity = { org_id: "org", user_id: "11111111-1111-1111-1111-111111111111" };
const finding: Finding = { id: "finding", cluster_id: "cluster", row_id: "finding:1767225600", revision: "4", title: "Saved finding", kind: "vulnerability", external_id: "CVE-test", severity: "high", risk_score: 75, lifecycle: "open", asset_id: "asset", attack_techniques: [], first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-01T00:00:00Z" };
const kinds = ["accept", "suppress", "comment"] as const;
type Kind = typeof kinds[number];
const page = (kind: Kind | "detail") => kind === "accept" ? <FindingAcceptRiskFormPage /> : kind === "suppress" ? <FindingSuppressFormPage /> : kind === "comment" ? <FindingCommentFormPage /> : <FindingDetailPage />;
let root: Root; let host: HTMLDivElement; let client: QueryClient;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  vi.mocked(findings.instance).mockResolvedValue(finding); vi.mocked(findings.instanceAcceptRisk).mockResolvedValue({ ...finding, status: "ok", row_id: finding.row_id!, revision: "5", source_cluster_id: "cluster", target_cluster_id: null }); vi.mocked(findings.instanceSuppress).mockResolvedValue({ ...finding, status: "ok", row_id: finding.row_id!, revision: "5", source_cluster_id: "cluster", target_cluster_id: null });
  vi.mocked(findings.instanceAddComment).mockResolvedValue({ ...finding, row_id: finding.row_id!, revision: "4", source_cluster_id: "cluster", target_cluster_id: null, id: "comment", finding_id: "finding", author_id: identity.user_id, body: "comment", created_at: "2026-01-01T00:00:00Z" });
  vi.mocked(findings.instanceComments).mockResolvedValue({ row_id: finding.row_id!, first_seen_at: finding.first_seen_at, revision: "4", comments: [], legacy_comments: [], legacy_history_scope: "uuid" });
});
afterEach(() => {
  act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); vi.restoreAllMocks();
  route.fid = "finding"; route.clusterId = "cluster"; route.resolvedClusterId = "cluster"; route.loading = false; route.error = null; route.search = "first_seen_at=2026-01-01T00%3A00%3A00Z";
});
async function renderPage(kind: Kind | "detail", beforeRender?: (queryClient: QueryClient) => void | Promise<void>) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await beforeRender?.(client); await rerenderPage(kind);
}
async function rerenderPage(kind: Kind | "detail") { await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={identity}>{page(kind)}</TablePreferencesProvider></QueryClientProvider>)); }
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function change(selector: string, value: string) { await act(async () => { const input = host.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)!; const prototype = input.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); }); }
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>("button")].find((item) => item.textContent?.trim() === label || item.getAttribute("aria-label") === label)!;
async function submit() { await act(async () => host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }))); }
function noWrites() { expect(findings.instanceAcceptRisk).not.toHaveBeenCalled(); expect(findings.instanceSuppress).not.toHaveBeenCalled(); expect(findings.instanceAddComment).not.toHaveBeenCalled(); }
async function draft(kind: Kind) { await renderPage(kind); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await change("#finding-action-text", "  Retained justification and controls  "); }

it.each(kinds)("saves the dedicated %s action against its confirmed entity and returns to its cluster detail", async (kind) => {
  await draft(kind); await submit(); await settled(() => expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/findings/finding?first_seen_at=2026-01-01T00%3A00%3A00Z" }));
  expect(findings.instance).toHaveBeenCalledWith("finding", { first_seen_at: finding.first_seen_at, cluster_id: "cluster" });
  if (kind === "accept") { expect(findings.instanceAcceptRisk).toHaveBeenCalledWith("finding", { first_seen_at: finding.first_seen_at, cluster_id: "cluster" }, { reviewed_revision: "4", reason: "Retained justification and controls", accepted_until: expect.any(String) }); const expiry = new Date(vi.mocked(findings.instanceAcceptRisk).mock.calls[0][2].accepted_until).getTime(); expect(expiry).toBeGreaterThan(Date.now()); expect(expiry).toBeLessThanOrEqual(Date.now() + 30 * 86400_000); }
  else if (kind === "suppress") expect(findings.instanceSuppress).toHaveBeenCalledWith("finding", { first_seen_at: finding.first_seen_at, cluster_id: "cluster" }, { reviewed_revision: "4", reason: "Retained justification and controls" });
  else expect(findings.instanceAddComment).toHaveBeenCalledWith("finding", { first_seen_at: finding.first_seen_at, cluster_id: "cluster" }, { reviewed_revision: "4", body: "Retained justification and controls" });
});
it.each(kinds)("Cancel and back links leave the %s draft without writes", async (kind) => {
  await draft(kind); expect(host.querySelector('a[href="/clusters/cluster/findings/finding?first_seen_at=2026-01-01T00%3A00%3A00Z"]')).not.toBeNull(); await act(async () => button("Cancel").click());
  expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/findings/finding?first_seen_at=2026-01-01T00%3A00%3A00Z" }); noWrites();
});
it.each(kinds.flatMap((kind) => ["missing-id", "missing-cluster", "foreign-cluster", "loading", "error-stale"].map((scenario) => [kind, scenario] as const)))("blocks initial %s authoring for %s scope", async (kind, scenario) => {
  if (scenario === "missing-id") route.fid = "";
  if (scenario === "missing-cluster") route.clusterId = undefined;
  if (scenario === "foreign-cluster") route.resolvedClusterId = "foreign";
  if (scenario === "loading") route.loading = true;
  if (scenario === "error-stale") route.error = new Error("private scope details");
  await renderPage(kind); expect(host.querySelector("form")).toBeNull(); expect(findings.instance).not.toHaveBeenCalled(); noWrites(); expect(host.textContent).not.toContain("private scope details");
});
it.each(kinds.flatMap((kind) => ["failed", "missing", "wrong-id", "foreign", "unscoped"].map((scenario) => [kind, scenario] as const)))("blocks initial %s authoring when the exact entity load is %s", async (kind, scenario) => {
  if (scenario === "failed") vi.mocked(findings.instance).mockRejectedValue(new Error("private entity details"));
  else vi.mocked(findings.instance).mockResolvedValue(scenario === "missing" ? undefined as unknown as Finding : { ...finding, ...(scenario === "wrong-id" ? { id: "another" } : scenario === "foreign" ? { cluster_id: "foreign" } : { cluster_id: undefined }) });
  await renderPage(kind); await settled(() => expect(host.textContent).toContain("This finding could not be loaded in the selected cluster"));
  expect(host.querySelector("form")).toBeNull(); noWrites(); expect(host.textContent).not.toContain("private entity details");
});
it.each(kinds)("does not freeze stale cached entity data before its initial refresh for %s", async (kind) => {
  let resolve!: (value: Finding) => void;
  vi.mocked(findings.instance).mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
  await renderPage(kind, (queryClient) => { queryClient.setQueryData(["finding", `${identity.org_id}:${identity.user_id}`, "cluster", "finding", finding.first_seen_at], { ...finding, title: "Old cached title" }); });
  expect(host.querySelector("form")).toBeNull();
  await act(async () => resolve({ ...finding, title: "Fresh confirmed title" }));
  await settled(() => expect(host.querySelector("form")).not.toBeNull()); expect(host.textContent).toContain("Fresh confirmed title"); expect(host.textContent).not.toContain("Old cached title");
});
it.each(kinds)("preserves %s drafts after a failed save and remote record refresh", async (kind) => {
  if (kind === "accept") vi.mocked(findings.instanceAcceptRisk).mockRejectedValue(new Error("private mutation details")); else if (kind === "suppress") vi.mocked(findings.instanceSuppress).mockRejectedValue(new Error("private mutation details")); else vi.mocked(findings.instanceAddComment).mockRejectedValue(new Error("private mutation details"));
  await draft(kind); await act(async () => client.setQueryData(["finding", `${identity.org_id}:${identity.user_id}`, "cluster", "finding", finding.first_seen_at], { ...finding, title: "Changed remotely" }));
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
  vi.mocked(findings.instance).mockImplementationOnce(() => new Promise((_done, fail) => { reject = fail; }));
  await act(async () => { void client.invalidateQueries({ queryKey: ["finding"] }); });
  await settled(() => expect(button("Save").disabled).toBe(true)); await submit(); noWrites();
  await act(async () => reject(new Error("private refresh details"))); await settled(() => expect(host.textContent).toContain("Current finding or cluster scope is unavailable"));
  expect(host.querySelector<HTMLTextAreaElement>("#finding-action-text")!.value).toContain("Retained justification");
  await act(async () => button("Retry").click()); await settled(() => expect(button("Save").disabled).toBe(false));
});
it.each(kinds)("blocks stale %s writes when exact entity scope changes before observer notification", async (kind) => {
  await draft(kind);
  await act(async () => { client.setQueryData(["finding", `${identity.org_id}:${identity.user_id}`, "cluster", "finding", finding.first_seen_at], { ...finding, cluster_id: "foreign" }); host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  await settled(() => expect(host.textContent).toContain("Your draft is preserved")); noWrites();
});
it.each(kinds)("rechecks cached cluster identity before %s writes", async (kind) => {
  await draft(kind);
  await act(async () => { client.setQueryData(["clusters"], { clusters: [] }); host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  await settled(() => expect(host.textContent).toContain("Could not save this finding action")); noWrites();
});
it.each(kinds)("starts a new %s draft when the route changes entity", async (kind) => {
  await draft(kind); route.fid = "another"; vi.mocked(findings.instance).mockResolvedValue({ ...finding, id: "another", row_id: "another:1767225600", title: "Another entity" }); await rerenderPage(kind);
  await settled(() => expect(host.textContent).toContain("Another entity")); expect(host.querySelector<HTMLTextAreaElement>("#finding-action-text")!.value).toBe(""); expect(host.querySelector('a[href="/clusters/cluster/findings/another?first_seen_at=2026-01-01T00%3A00%3A00Z"]')).not.toBeNull(); expect(host.querySelector('a[href="/clusters/cluster/findings/finding?first_seen_at=2026-01-01T00%3A00%3A00Z"]')).toBeNull(); noWrites();
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
  vi.mocked(findings.instanceAcceptRisk).mockRejectedValue(new Error("policy rejected")); await submit(); await settled(() => expect(host.textContent).toContain("Could not save this finding action"));
  expect(findings.instanceAcceptRisk).toHaveBeenCalledWith("finding", expect.any(Object), expect.objectContaining({ approver_id: approver })); expect(host.querySelector<HTMLInputElement>("#finding-action-approver")!.value).toBe(approver);
});
it.each(["suppress", "comment"] as const)("requires a nonblank %s reason/body", async (kind) => {
  await draft(kind); await change("#finding-action-text", "   "); expect(button("Save").disabled).toBe(true); await submit(); noWrites();
});
it("enforces the backend comment byte limit for unicode drafts", async () => {
  await draft("comment"); await change("#finding-action-text", "😀".repeat(4001)); expect(button("Save").disabled).toBe(true); await submit(); noWrites();
  await change("#finding-action-text", "😀".repeat(4000)); expect(button("Save").disabled).toBe(false);
});
it("keeps detail history read-only and links to dedicated actions in the same cluster", async () => {
  vi.mocked(findings.instanceComments).mockResolvedValue({ row_id: finding.row_id!, first_seen_at: finding.first_seen_at, revision: "4", legacy_comments: [], legacy_history_scope: "uuid", comments: [{ id: "history", finding_id: "finding", author_id: identity.user_id, body: "Saved history", created_at: "2026-01-01T00:00:00Z" }] });
  await renderPage("detail"); await settled(() => expect(host.textContent).toContain("Saved history"));
  expect(host.querySelector("form,textarea,input")).toBeNull();
  for (const path of ["accept-risk", "suppress", "comments/new"]) expect(host.querySelector(`a[href="/clusters/cluster/findings/finding/${path}?first_seen_at=2026-01-01T00%3A00%3A00Z"]`)).not.toBeNull();
  expect(host.querySelector('a[href="/clusters/cluster/findings"]')).not.toBeNull(); noWrites();
});
it("distinguishes failed history from an empty thread and retries it", async () => {
  vi.mocked(findings.instanceComments).mockRejectedValueOnce(new Error("private comments details"));
  await renderPage("detail"); await settled(() => expect(host.textContent).toContain("Comment history could not be loaded")); expect(host.textContent).not.toContain("No comments yet");
  await act(async () => button("Retry comments").click()); await settled(() => expect(host.textContent).toContain("No comments yet"));
});
it("keeps detail exception and asset links within the confirmed cluster", async () => {
  vi.mocked(findings.instance).mockResolvedValue({ ...finding, lifecycle: "accepted", accepted_until: "2099-01-01T00:00:00Z" }); await renderPage("detail");
  await settled(() => expect(host.querySelector('[data-testid="finding-exception-link"]')).not.toBeNull());
  expect(host.querySelector('[data-testid="finding-exception-link"]')!.getAttribute("href")).toContain("/clusters/cluster/exceptions?");
  expect(host.querySelector('[data-testid="finding-affected-asset-risk"]')!.getAttribute("href")).toBe("/clusters/cluster/risk/asset/asset");
});
it("does not expose detail or action links for a foreign entity", async () => {
  vi.mocked(findings.instance).mockResolvedValue({ ...finding, cluster_id: "foreign" }); await renderPage("detail");
  await settled(() => expect(host.textContent).toContain("This finding could not be loaded in the selected cluster")); expect(findings.instanceComments).not.toHaveBeenCalled(); expect(host.querySelector('a[href$="accept-risk"]')).toBeNull();
});
it.each(kinds)("blocks initial %s authoring until the cached cluster refresh settles", async (kind) => {
  let resolve!: (value: { clusters: Array<{ id: string }> }) => void;
  await renderPage(kind, (queryClient) => {
    queryClient.setQueryData(["clusters"], { clusters: [{ id: "cluster" }] });
    void queryClient.fetchQuery({ queryKey: ["clusters"], queryFn: () => new Promise<{ clusters: Array<{ id: string }> }>((done) => { resolve = done; }) }).catch(() => {});
  });
  expect(host.querySelector("form")).toBeNull(); expect(findings.instance).not.toHaveBeenCalled();
  await act(async () => resolve({ clusters: [{ id: "cluster" }] })); await settled(() => expect(host.querySelector("form")).not.toBeNull());
});
it.each(kinds)("does not expose initial %s authoring with a failed cached registry and stale cluster identity", async (kind) => {
  await renderPage(kind, async (queryClient) => {
    queryClient.setQueryData(["clusters"], { clusters: [{ id: "cluster" }] });
    await queryClient.fetchQuery({ queryKey: ["clusters"], queryFn: () => Promise.reject(new Error("registry failed")) }).catch(() => {});
  });
  expect(host.querySelector("form")).toBeNull(); expect(findings.instance).not.toHaveBeenCalled(); noWrites();
});
it.each(kinds)("does not initialize %s authoring when cluster scope fails during the initial entity request", async (kind) => {
  let resolve!: (value: Finding) => void;
  vi.mocked(findings.instance).mockImplementationOnce(() => new Promise((done) => { resolve = done; })); await renderPage(kind);
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
  vi.mocked(findings.instance).mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
  await act(async () => { void client.invalidateQueries({ queryKey: ["finding"] }); host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  await settled(() => expect(button("Save").disabled).toBe(true)); noWrites(); await act(async () => resolve(finding));
});
it("updates detail action and asset links when the active entity and cluster change", async () => {
  await renderPage("detail"); await settled(() => expect(host.querySelector('a[href="/clusters/cluster/findings/finding/accept-risk?first_seen_at=2026-01-01T00%3A00%3A00Z"]')).not.toBeNull());
  route.fid = "another"; route.clusterId = "another-cluster"; route.resolvedClusterId = "another-cluster";
  vi.mocked(findings.instance).mockResolvedValue({ ...finding, id: "another", row_id: "another:1767225600", cluster_id: "another-cluster", asset_id: "another-asset", lifecycle: "accepted" });
  await rerenderPage("detail"); await settled(() => expect(host.querySelector('a[href="/clusters/another-cluster/findings/another/accept-risk?first_seen_at=2026-01-01T00%3A00%3A00Z"]')).not.toBeNull());
  expect(host.querySelector('a[href="/clusters/cluster/findings/finding/accept-risk?first_seen_at=2026-01-01T00%3A00%3A00Z"]')).toBeNull();
  expect(host.querySelector('a[href="/clusters/another-cluster/findings"]')).not.toBeNull();
  expect(host.querySelector('[data-testid="finding-affected-asset-detail"]')!.getAttribute("href")).toBe("/clusters/another-cluster/assets/another-asset");
  expect(host.querySelector('[data-testid="finding-exception-link"]')!.getAttribute("href")).toContain("/clusters/another-cluster/exceptions?");
  noWrites();
});
it('requires a single exact selector and never falls back after an exact lookup fails', async () => {
  route.search = 'first_seen_at=2026-01-01T00%3A00%3A00Z&first_seen_at=2026-01-01T00%3A00%3A00.000001Z';
  await renderPage('suppress'); expect(host.textContent).toContain('Select one valid observation'); expect(findings.instance).not.toHaveBeenCalled(); expect(findings.get).not.toHaveBeenCalled();
  route.search = 'first_seen_at=2026-01-01T00%3A00%3A00.000001Z'; vi.mocked(findings.instance).mockRejectedValue({ response: { status: 404 } }); await rerenderPage('suppress');
  await settled(() => expect(host.textContent).toContain('This finding could not be loaded')); expect(findings.get).not.toHaveBeenCalled(); noWrites();
});
it('offers an observation chooser for ambiguous legacy UUID links instead of opening a draft', async () => {
  route.search = ''; vi.mocked(findings.get).mockRejectedValue({ response: { status: 409, data: { code: 'ambiguous_finding_id' } } });
  await renderPage('accept'); await settled(() => expect(host.textContent).toContain('multiple retained observations'));
  const link = host.querySelector('a[href*="q=id%3Afinding"]')!; expect(link.getAttribute('href')).toContain('lifecycle=all'); expect(host.querySelector('form')).toBeNull(); expect(findings.instance).not.toHaveBeenCalled(); noWrites();
});
it('rejects another recurrence even when UUID and cluster match', async () => {
  vi.mocked(findings.instance).mockResolvedValue({ ...finding, first_seen_at: '2026-01-01T00:00:00.000001Z', row_id: 'finding:1767225600.000001' });
  await renderPage('suppress'); await settled(() => expect(host.textContent).toContain('This finding could not be loaded')); expect(host.querySelector('form')).toBeNull(); noWrites();
});
it('blocks duplicate writes after a response confirms a different recurrence', async () => {
  await draft('suppress'); vi.mocked(findings.instanceSuppress).mockResolvedValue({ ...finding, status: 'ok', row_id: 'finding:1767225600.000001', first_seen_at: '2026-01-01T00:00:00.000001Z', revision: '5', source_cluster_id: 'cluster', target_cluster_id: null });
  await submit(); await settled(() => expect(host.textContent).toContain('could not be confirmed')); expect(button('Save').disabled).toBe(true); await submit(); expect(findings.instanceSuppress).toHaveBeenCalledOnce(); expect(route.navigate).not.toHaveBeenCalled(); expect(host.querySelector<HTMLTextAreaElement>('textarea')!.value).toContain('Retained justification');
});
it('does not navigate after an exact write returns to an unmounted observation', async () => {
  let resolve!: (response: Awaited<ReturnType<typeof findings.instanceSuppress>>) => void;
  await draft('suppress'); vi.mocked(findings.instanceSuppress).mockImplementation(() => new Promise(done => { resolve = done; })); await submit();
  route.search = 'first_seen_at=2026-01-01T00%3A00%3A00.000001Z'; vi.mocked(findings.instance).mockResolvedValue({ ...finding, first_seen_at: '2026-01-01T00:00:00.000001Z', row_id: 'finding:1767225600.000001' }); await rerenderPage('suppress');
  await settled(() => expect(host.querySelector<HTMLTextAreaElement>('textarea')!.value).toBe(''));
  await act(async () => resolve({ ...finding, status: 'ok', row_id: finding.row_id!, revision: '5', source_cluster_id: 'cluster', target_cluster_id: null })); expect(route.navigate).not.toHaveBeenCalled();
});
it('keeps earlier UUID-only comments separate from the selected observation', async () => {
  vi.mocked(findings.instanceComments).mockResolvedValue({ row_id: finding.row_id!, first_seen_at: finding.first_seen_at, revision: '4', comments: [], legacy_comments: [{ id: 'old', finding_id: finding.id, author_id: identity.user_id, body: 'Earlier unqualified discussion', created_at: finding.first_seen_at }], legacy_history_scope: 'uuid' });
  await renderPage('detail'); await settled(() => expect(host.textContent).toContain('Earlier discussion for this finding ID')); expect(host.querySelector('[data-testid="comments-list"]')!.textContent).not.toContain('Earlier unqualified discussion'); expect(host.querySelector('details')?.open).toBe(false);
});
it('holds a stale revision after 409 until explicit refresh, preserving the draft and reviewing the new lifecycle', async () => {
  await draft('suppress'); vi.mocked(findings.instanceSuppress).mockRejectedValueOnce({ response: { status: 409, data: { code: 'stale_finding_revision' } } });
  await submit(); await settled(() => expect(host.textContent).toContain('This observation changed after review')); expect(button('Save').disabled).toBe(true);
  await submit(); expect(findings.instanceSuppress).toHaveBeenCalledOnce(); expect(host.querySelector<HTMLTextAreaElement>('textarea')!.value).toContain('Retained justification');
  let resolve!: (response: Finding) => void; vi.mocked(findings.instance).mockImplementationOnce(() => new Promise(done => { resolve = done; })); await act(async () => button('Refresh observation').click());
  await settled(() => expect(button('Save').disabled).toBe(true)); expect(host.querySelector<HTMLTextAreaElement>('textarea')!.value).toContain('Retained justification');
  await act(async () => resolve({ ...finding, lifecycle: 'triaged', revision: '5' })); await settled(() => expect(button('Save').disabled).toBe(false)); expect(host.textContent).toContain('triaged'); expect(host.textContent).toContain('Reviewed revision5');
  vi.mocked(findings.instanceSuppress).mockResolvedValue({ ...finding, status: 'ok', row_id: finding.row_id!, revision: '6', source_cluster_id: 'cluster', target_cluster_id: null }); await submit();
  await settled(() => expect(findings.instanceSuppress).toHaveBeenCalledTimes(2)); expect(findings.instanceSuppress).toHaveBeenLastCalledWith('finding', { first_seen_at: finding.first_seen_at, cluster_id: 'cluster' }, { reviewed_revision: '5', reason: 'Retained justification and controls' });
});
it('keeps saving paused when an explicit stale-review refresh fails or returns another recurrence', async () => {
  await draft('suppress'); vi.mocked(findings.instanceSuppress).mockRejectedValueOnce({ response: { status: 409 } }); await submit(); await settled(() => expect(button('Refresh observation')).toBeDefined());
  vi.mocked(findings.instance).mockResolvedValue({ ...finding, row_id: 'finding:1767225600.000001', first_seen_at: '2026-01-01T00:00:00.000001Z', revision: '5' }); await act(async () => button('Refresh observation').click());
  await settled(() => expect(host.textContent).toContain('Could not refresh the observation')); expect(button('Save').disabled).toBe(true); expect(host.querySelector<HTMLTextAreaElement>('textarea')!.value).toContain('Retained justification'); await submit(); expect(findings.instanceSuppress).toHaveBeenCalledOnce(); expect(route.navigate).not.toHaveBeenCalled();
});
it('blocks a duplicate comment when its response arrives after source invalidation and recovery', async () => {
  let resolve!: (receipt: Awaited<ReturnType<typeof findings.instanceAddComment>>) => void;
  await draft('comment'); vi.mocked(findings.instanceAddComment).mockImplementationOnce(() => new Promise(done => { resolve = done; })); await submit();
  await settled(() => expect(findings.instanceAddComment).toHaveBeenCalledOnce());
  await act(async () => { await client.invalidateQueries({ queryKey: ['finding'] }); });
  await settled(() => expect(host.textContent).not.toContain('Current finding or cluster scope is unavailable'));
  await act(async () => resolve({ id: 'created-comment', finding_id: finding.id, author_id: identity.user_id, body: 'Retained justification and controls', created_at: finding.first_seen_at, row_id: finding.row_id!, first_seen_at: finding.first_seen_at, revision: finding.revision!, source_cluster_id: 'cluster', target_cluster_id: null }));
  await settled(() => expect(host.textContent).toContain('The saved observation could not be confirmed')); expect(button('Save').disabled).toBe(true); expect(host.querySelector<HTMLTextAreaElement>('textarea')!.value).toContain('Retained justification'); expect(route.navigate).not.toHaveBeenCalled();
  await submit(); expect(findings.instanceAddComment).toHaveBeenCalledOnce();
});
