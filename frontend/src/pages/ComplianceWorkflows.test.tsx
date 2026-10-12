import { act, cloneElement, type ReactElement, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { compliance, type ComplianceCheck, type ComplianceChecksParams, type ComplianceChecksResponse, type ComplianceScheduleDB } from "@/api/client";
import { CompliancePage } from "./CompliancePage";
import { ComplianceExemptionFormPage } from "./ComplianceExemptionFormPage";
import { ComplianceScheduleFormPage } from "./ComplianceScheduleFormPage";

const route = vi.hoisted(() => ({ clusterId: "cluster" as string | undefined, cluster: { id: "cluster" } as { id: string } | undefined, loading: false, error: null as Error | null, search: "framework=cis&control_id=1.2&filter=a&filter=b", navigate: vi.fn(), setSearch: vi.fn() }));
vi.mock("@/api/client", () => ({ compliance: { frameworks: vi.fn(), checks: vi.fn(), summary: vi.fn(), listExemptions: vi.fn(), createExemption: vi.fn(), revokeExemption: vi.fn(), evidence: vi.fn(), listDBSchedules: vi.fn(), createSchedule: vi.fn(), runScheduleNow: vi.fn(), deleteSchedule: vi.fn(), scheduleRuns: vi.fn(), downloadRunArtifact: vi.fn(), exportChecksCSV: vi.fn() } }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: route.clusterId, cluster: route.cluster, isLoading: route.loading, error: route.error }) }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(route.search), route.setSearch] }));
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => route.navigate, Link: ({ children, href }: { children: ReactNode; href?: string }) => <a href={href}>{children}</a> }));
let root: Root; let host: HTMLDivElement; let client: QueryClient;
let mounted: ReactNode;
const check = { framework: "cis", control_id: "1.2", title: "Control title", status: "fail", effective_status: "fail", severity: "high", evidence: "Collected evidence", remediation: "Fix this control" } as ComplianceCheck;
const inherited = { id: "organization", name: "Shared schedule", framework: "cis", enabled: true, cron_expression: "0 2 * * *", timezone: "UTC", delivery: [], report_format: "pdf", report_template: "compliance-detailed", last_status: "succeeded" } as unknown as ComplianceScheduleDB;
const options = { schedules: [inherited], summary: { total: 1, enabled: 1, disabled: 0 }, frameworks: ["cis", "pci"], report_formats: ["pdf", "json", "sarif", "csv"] };
function listResponse(params: ComplianceChecksParams, rows: ComplianceCheck[]): ComplianceChecksResponse {
 const summary = { total: rows.length, pass: 0, fail: 0, manual: 0, exempted: 0, not_applicable: 0, graded: 0, ungraded: 0 };
 for (const row of rows) { const status = row.effective_status || row.status; if (status in summary) summary[status as keyof typeof summary]++; if (["pass", "fail"].includes(status)) summary.graded++; else summary.ungraded++; }
 return { checks: rows.map((row, index) => ({ ...row, id: `evidence-${index}`, cluster_id: params.cluster_id })), cluster_id: params.cluster_id, framework: params.framework === "all" ? "" : params.framework || "", profile: params.profile || "", control_id: params.control_id || "", status: params.status || "", q: params.q || "", sort: params.sort, order: params.order, limit: 100, offset: params.offset || 0, total: rows.length, has_more: false, summary };
}
beforeEach(() => {
  route.clusterId = "cluster"; route.cluster = { id: "cluster" }; route.loading = false; route.error = null; route.search = "framework=cis&control_id=1.2&filter=a&filter=b";
  route.setSearch.mockImplementation((next: URLSearchParams | ((current: URLSearchParams) => URLSearchParams)) => { route.search = (typeof next === "function" ? next(new URLSearchParams(route.search)) : next).toString(); });
  vi.mocked(compliance.frameworks).mockResolvedValue({ frameworks: [{ id: "cis", name: "CIS", category: "Security" }, { id: "pci", name: "PCI", category: "Regulatory" }] });
  vi.mocked(compliance.checks).mockImplementation(async params => typeof params === "object" ? listResponse(params, [check]) : { checks: [check] });
  vi.mocked(compliance.summary).mockResolvedValue({ frameworks: [{ framework: "cis", total: 2, pass: 1, fail: 1, manual: 0, exempted: 0, pass_pct: 50 }] });
  vi.mocked(compliance.listExemptions).mockResolvedValue({ exemptions: [] });
  vi.mocked(compliance.listDBSchedules).mockResolvedValue(options);
  vi.mocked(compliance.evidence).mockResolvedValue({ items: [], summary: { total: 0, pass: 0, fail: 0, manual: 0, exempted: 0, not_applicable: 0 } });
});
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); });
async function renderPage(node: ReactNode) {
  mounted = node; host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}>{node}</QueryClientProvider>));
}
async function rerender() { await act(async () => root.render(<QueryClientProvider client={client}>{cloneElement(mounted as ReactElement)}</QueryClientProvider>)); }
async function settled(checkResult: () => void) { await vi.waitFor(async () => { await act(async () => {}); checkResult(); }); }
async function edit(selector: string, value: string) {
  const field = host.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)!;
  const prototype = field.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : field.tagName === "SELECT" ? window.HTMLSelectElement.prototype : HTMLInputElement.prototype;
  await act(async () => { Object.getOwnPropertyDescriptor(prototype, "value")!.set!.call(field, value); field.dispatchEvent(new Event(field.tagName === "SELECT" ? "change" : "input", { bubbles: true })); });
}
async function click(label: string) {
  const button = [...host.querySelectorAll("button")].find((item) => item.textContent?.trim() === label || item.getAttribute("aria-label") === label);
  expect(button).toBeDefined(); await act(async () => button!.click());
}
async function submit() { await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); }); }

const surfaces = [{ name: "list", page: <CompliancePage /> }, { name: "exemption", page: <ComplianceExemptionFormPage /> }, { name: "schedule", page: <ComplianceScheduleFormPage /> }];
describe.each(surfaces)("$name scope", ({ page }) => {
  it.each(["missing", "unresolved", "failed", "loading"])("blocks %s scope before compliance requests", async (scenario) => {
    if (scenario === "missing") { route.clusterId = undefined; route.cluster = undefined; }
    else if (scenario === "unresolved") route.cluster = { id: "another" };
    else if (scenario === "failed") route.error = new Error("private scope detail");
    else route.loading = true;
    await renderPage(page);
    expect(host.querySelector("form")).toBeNull();
    for (const api of [compliance.frameworks, compliance.checks, compliance.summary, compliance.listDBSchedules, compliance.evidence]) expect(api).not.toHaveBeenCalled();
    expect(host.textContent).not.toContain("private scope detail");
  });
});

describe("exemption form", () => {
  it.each(["failed", "missing", "other-control", "other-framework"])("blocks a %s control lookup", async (scenario) => {
    if (scenario === "failed") vi.mocked(compliance.checks).mockRejectedValue(new Error("private"));
    else vi.mocked(compliance.checks).mockResolvedValue({ checks: scenario === "missing" ? [] : scenario === "other-control" ? [{ ...check, control_id: "other" }] : [{ ...check, framework: "pci" }] });
    await renderPage(<ComplianceExemptionFormPage />); await settled(() => expect(host.textContent).toContain("could not be loaded for the selected cluster"));
    expect(host.querySelector("form")).toBeNull(); expect(compliance.createExemption).not.toHaveBeenCalled(); expect(compliance.checks).toHaveBeenCalledWith("cis", "cluster", { control_id: "1.2" });
  });
  it("validates reason and expiry, retains draft on refresh and failed save", async () => {
    vi.mocked(compliance.createExemption).mockRejectedValue(new Error("private transport detail"));
    await renderPage(<ComplianceExemptionFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull());
    await edit("textarea", "short"); await submit(); expect(compliance.createExemption).not.toHaveBeenCalled();
    await edit("textarea", "  Compensating controls approved  "); await edit("#exemption-expires", "2000-01-01T12:00"); await submit(); expect(compliance.createExemption).not.toHaveBeenCalled();
    await edit("#exemption-expires", "2099-01-01T12:00");
    await act(async () => { client.setQueryData(["compliance", "checks", "cis", "cluster", "1.2"], { checks: [{ ...check, evidence: "Changed elsewhere" }] }); });
    expect(host.querySelector("textarea")?.value).toBe("  Compensating controls approved  ");
    await submit(); await settled(() => expect(host.textContent).toContain("Your draft is preserved"));
    expect(compliance.createExemption).toHaveBeenCalledWith({ cluster_id: "cluster", framework: "cis", control_id: "1.2", reason: "Compensating controls approved", expires_at: new Date("2099-01-01T12:00").toISOString() });
    expect(route.navigate).not.toHaveBeenCalled(); expect(host.textContent).not.toContain("private transport detail");
  });
  it("retains draft but blocks Save after failed control or cluster refresh", async () => {
    vi.mocked(compliance.checks).mockResolvedValueOnce({ checks: [check] }).mockRejectedValue(new Error("offline"));
    await renderPage(<ComplianceExemptionFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await edit("textarea", "A retained approval rationale");
    await act(async () => { await client.invalidateQueries({ queryKey: ["compliance", "checks", "cis", "cluster", "1.2"] }); });
    await settled(() => expect(host.textContent).toContain("Could not refresh this control")); expect(host.querySelector("textarea")?.value).toBe("A retained approval rationale");
    await submit(); expect(compliance.createExemption).not.toHaveBeenCalled();
    route.error = new Error("scope offline"); await rerender(); expect(host.querySelector("textarea")?.value).toBe("A retained approval rationale"); expect(host.textContent).toContain("Current cluster scope is unavailable");
  });
  it("returns Save, Cancel, and Back to the scoped framework with repeated filters", async () => {
    vi.mocked(compliance.createExemption).mockResolvedValue({ id: "new", exemptions: [] });
    await renderPage(<ComplianceExemptionFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull());
    const backTo = "/clusters/cluster/compliance?framework=cis&filter=a&filter=b&tab=frameworks";
    expect(host.querySelector("a")?.getAttribute("href")).toBe(backTo); await click("Cancel"); expect(route.navigate).toHaveBeenCalledWith({ href: backTo }); expect(compliance.createExemption).not.toHaveBeenCalled();
    await edit("textarea", "Approved compensating controls"); await submit(); await settled(() => expect(route.navigate).toHaveBeenCalledTimes(2)); expect(route.navigate).toHaveBeenLastCalledWith({ href: backTo });
  });
  it("keeps the draft but blocks creation when refreshed control becomes exempted", async () => {
    await renderPage(<ComplianceExemptionFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await edit("textarea", "Approved compensating controls");
    await act(async () => { client.setQueryData(["compliance", "checks", "cis", "cluster", "1.2"], { checks: [{ ...check, effective_status: "exempted" }] }); });
    await settled(() => expect(host.textContent).toContain("no longer eligible"));
    expect(host.querySelector("textarea")?.value).toBe("Approved compensating controls"); await submit(); expect(compliance.createExemption).not.toHaveBeenCalled();
  });
});

describe("schedule form", () => {
  it("blocks authoring when report options fail", async () => {
    vi.mocked(compliance.listDBSchedules).mockRejectedValue(new Error("private")); await renderPage(<ComplianceScheduleFormPage />);
    await settled(() => expect(host.textContent).toContain("Schedule options could not be loaded")); expect(host.querySelector("form")).toBeNull(); expect(compliance.createSchedule).not.toHaveBeenCalled();
  });
  it("preserves all delivery kinds, format, timezone and custom cadence in a failed draft", async () => {
    vi.mocked(compliance.createSchedule).mockRejectedValue(new Error("private transport detail"));
    await renderPage(<ComplianceScheduleFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull()); expect(host.querySelector("details")?.open).toBe(false);
    await edit("#schedule-name", "  Monthly evidence  ");
    await edit("#delivery-kind-0", "email"); await edit("#delivery-target-0", "audit@example.com");
    await click("Add target"); await edit("#delivery-kind-1", "s3"); await edit("#delivery-bucket-1", "evidence"); await edit("#delivery-prefix-1", "audit/");
    await click("Add target"); await edit("#delivery-kind-2", "webhook"); await edit("#delivery-url-2", "https://example.com/hook");
    await click("Add target"); await edit("#delivery-kind-3", "file"); await edit("#delivery-target-3", "file:///reports/");
    await edit("#schedule-cadence", "custom"); expect(host.querySelector("details")?.open).toBe(true);
    await edit("#schedule-cron", "30 4 * * 2"); await edit("#schedule-timezone", "America/New_York"); await edit("#schedule-format", "sarif");
    await submit(); await settled(() => expect(host.textContent).toContain("Your draft is preserved"));
    expect(compliance.createSchedule).toHaveBeenCalledWith({ name: "Monthly evidence", description: "", cluster_id: "cluster", framework: "cis", cron_expression: "30 4 * * 2", timezone: "America/New_York", delivery: [{ kind: "email", target: "audit@example.com" }, { kind: "s3", target: "", bucket: "evidence", prefix: "audit/" }, { kind: "webhook", target: "", url: "https://example.com/hook" }, { kind: "file", target: "file:///reports/" }], report_format: "sarif", report_template: "compliance-detailed" });
    expect(host.querySelector<HTMLInputElement>("#schedule-name")!.value).toBe("  Monthly evidence  "); expect(host.textContent).not.toContain("private transport detail"); expect(route.navigate).not.toHaveBeenCalled();
  });
  it("retains draft and disables Save after report-option refresh failure", async () => {
    vi.mocked(compliance.listDBSchedules).mockResolvedValueOnce(options).mockRejectedValue(new Error("offline"));
    await renderPage(<ComplianceScheduleFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await edit("#schedule-name", "Retained schedule");
    await act(async () => { await client.invalidateQueries({ queryKey: ["compliance", "db-schedules", "cluster"] }); });
    await settled(() => expect(host.textContent).toContain("Could not refresh schedule options")); expect(host.querySelector<HTMLInputElement>("#schedule-name")!.value).toBe("Retained schedule");
    await submit(); expect(compliance.createSchedule).not.toHaveBeenCalled();
    route.error = new Error("offline scope"); await rerender(); expect(host.querySelector<HTMLInputElement>("#schedule-name")!.value).toBe("Retained schedule");
  });
  it("cancels without a write and returns Save to the scoped schedules tab", async () => {
    vi.mocked(compliance.createSchedule).mockResolvedValue({ ...inherited, id: "new", cluster_id: "cluster" }); await renderPage(<ComplianceScheduleFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull());
    const backTo = "/clusters/cluster/compliance?framework=cis&control_id=1.2&filter=a&filter=b&tab=schedules";
    expect(host.querySelector("a")?.getAttribute("href")).toBe(backTo); await click("Cancel"); expect(route.navigate).toHaveBeenCalledWith({ href: backTo }); expect(compliance.createSchedule).not.toHaveBeenCalled();
    await edit("#schedule-name", "New schedule"); await submit(); await settled(() => expect(route.navigate).toHaveBeenCalledTimes(2)); expect(route.navigate).toHaveBeenLastCalledWith({ href: backTo });
  });
});

describe("compliance workspaces", () => {
  it("opens a primary controls table and navigates to the dedicated exemption form", async () => {
    route.search = "framework=cis&filter=a&filter=b";
    await renderPage(<CompliancePage />); await settled(() => expect(host.querySelector("table")).not.toBeNull());
    expect(host.querySelector("form")).toBeNull(); expect(host.querySelector("details")?.open).toBe(false); expect(host.textContent).not.toContain("Scheduled Evidence");
    expect(compliance.evidence).not.toHaveBeenCalled(); expect(compliance.listDBSchedules).not.toHaveBeenCalled();
    await click("Exempt"); expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/compliance/exemptions/new?framework=cis&filter=a&filter=b&control_id=1.2&tab=controls" });
    await edit("#compliance-framework", "pci"); expect(route.setSearch).toHaveBeenCalled(); expect(route.search).toContain("framework=pci"); expect(route.search).toContain("filter=a&filter=b");
  });
  it("keeps independent checked totals and offers a retry on a failed source summary", async () => {
    vi.mocked(compliance.summary).mockRejectedValue(new Error("private")); await renderPage(<CompliancePage />);
    await settled(() => expect(host.textContent).toContain("Framework labels or the source summary could not be refreshed")); expect(host.querySelector("#compliance-framework")).not.toBeNull(); expect(host.textContent).not.toContain("private");
  });
  it("shows evidence failure instead of empty success", async () => {
    route.search = "tab=evidence"; vi.mocked(compliance.evidence).mockRejectedValue(new Error("private"));
    await renderPage(<CompliancePage />); await settled(() => expect(host.textContent).toContain("Compliance evidence could not be loaded"));
    expect(host.textContent).not.toContain("No collected compliance evidence"); expect(compliance.evidence).toHaveBeenCalledWith({ cluster_id: "cluster", limit: 500 });
  });
  it("keeps inherited schedule scope, run/history/download actions, and standalone creation", async () => {
    route.search = "tab=schedules&filter=a&filter=b";
    vi.mocked(compliance.listDBSchedules).mockResolvedValue({ ...options, schedules: [inherited, { ...inherited, id: "local", name: "Local schedule", cluster_id: "cluster" }, { ...inherited, id: "foreign", name: "Foreign schedule", cluster_id: "other" }] });
    vi.mocked(compliance.runScheduleNow).mockResolvedValue({ schedule: inherited, queued: true, message: "queued" });
    vi.mocked(compliance.scheduleRuns).mockResolvedValue({ runs: [{ id: "run", org_id: "org", framework: "cis", started_at: "2026-10-12T00:00:00Z", status: "succeeded", summary: { pass: 1, fail: 0, manual: 0 }, artifact_signature: "signature", artifact_uri: "artifact", triggered_by: "manual" }] });
    vi.mocked(compliance.downloadRunArtifact).mockResolvedValue(undefined);
    await renderPage(<CompliancePage />); await settled(() => expect(host.textContent).toContain("Shared schedule"));
    expect(host.textContent).toContain("Organization schedule · applies across clusters"); expect(host.textContent).toContain("Cluster schedule"); expect(host.textContent).not.toContain("Foreign schedule"); expect(host.querySelector("form")).toBeNull();
    await act(async () => host.querySelector<HTMLButtonElement>('[data-testid="schedule-run-organization"]')!.click()); await settled(() => expect(host.textContent).toContain("Compliance run queued")); expect(compliance.runScheduleNow).toHaveBeenCalledWith("organization");
    await act(async () => host.querySelector<HTMLButtonElement>('[data-testid="schedule-runs-toggle-organization"]')!.click()); await settled(() => expect(host.textContent).toContain("Signature recorded"));
    await click("Download"); expect(compliance.downloadRunArtifact).toHaveBeenCalledWith("run");
    await click("New schedule"); expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/compliance/schedules/new?tab=schedules&filter=a&filter=b" });
  });
});

it("retains an exemption draft when the control disappears on refresh", async () => {
  await renderPage(<ComplianceExemptionFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await edit("textarea", "A draft approval that must survive");
  await act(async () => { client.setQueryData(["compliance", "checks", "cis", "cluster", "1.2"], { checks: [] }); });
  await settled(() => expect(host.textContent).toContain("no longer available")); expect(host.querySelector("textarea")?.value).toBe("A draft approval that must survive");
  await submit(); expect(compliance.createExemption).not.toHaveBeenCalled();
});

it.each(["frameworks", "formats"])("retains a schedule draft when refreshed %s disappear", async (scenario) => {
  await renderPage(<ComplianceScheduleFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await edit("#schedule-name", "A schedule draft that must survive");
  await act(async () => {
    if (scenario === "frameworks") client.setQueryData(["compliance", "frameworks"], { frameworks: [] });
    else client.setQueryData(["compliance", "db-schedules", "cluster"], { ...options, report_formats: [] });
  });
  await settled(() => expect(host.textContent).toContain("Current frameworks or report formats are unavailable")); expect(host.querySelector<HTMLInputElement>("#schedule-name")!.value).toBe("A schedule draft that must survive");
  await submit(); expect(compliance.createSchedule).not.toHaveBeenCalled();
});

it("aggregates matching evidence and creates one exemption for the entire control", async () => {
  const controls = [
    { ...check, evidence: "Failed workload api" },
    { ...check, status: "pass" as const, effective_status: "pass" as const, evidence: "Passing workload worker" },
    { ...check, status: "manual" as const, effective_status: "manual" as const, evidence: "Manual workload db" },
    { ...check, effective_status: "exempted" as const, evidence: "Already exempted workload job" },
    { ...check, framework: "pci", evidence: "Foreign framework evidence" },
    { ...check, control_id: "9.9", evidence: "Other control evidence" },
  ];
  vi.mocked(compliance.checks).mockResolvedValue({ checks: controls });
  vi.mocked(compliance.createExemption).mockResolvedValue({ id: "new", exemptions: [] });
  await renderPage(<ComplianceExemptionFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  expect(host.textContent).toContain("Entire control in cluster"); expect(host.textContent).toContain("4 loaded evidence rows · 1 unexempted failure");
  expect(host.textContent).toContain("including future results until expiry"); expect(host.querySelectorAll('[data-testid="exemption-control-evidence"] li')).toHaveLength(4);
  for (const evidence of ["Failed workload api", "Passing workload worker", "Manual workload db", "Already exempted workload job"]) expect(host.textContent).toContain(evidence);
  expect(host.textContent).not.toContain("Foreign framework evidence"); expect(host.textContent).not.toContain("Other control evidence");
  await edit("textarea", "Approved whole control acceptance"); await edit("#exemption-expires", "2099-01-01T12:00"); await submit();
  await settled(() => expect(compliance.createExemption).toHaveBeenCalledTimes(1));
  expect(compliance.createExemption).toHaveBeenCalledWith({ cluster_id: "cluster", framework: "cis", control_id: "1.2", reason: "Approved whole control acceptance", expires_at: new Date("2099-01-01T12:00").toISOString() });
});

it("retains an exemption draft and allows multiple evidence rows after refresh", async () => {
  vi.mocked(compliance.createExemption).mockResolvedValue({ id: "new", exemptions: [] });
  await renderPage(<ComplianceExemptionFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await edit("textarea", "A retained whole control acceptance");
  await act(async () => { client.setQueryData(["compliance", "checks", "cis", "cluster", "1.2"], { checks: [check, { ...check, evidence: "Another workload failure" }] }); });
  await settled(() => expect(host.textContent).toContain("2 loaded evidence rows · 2 unexempted failures")); expect(host.querySelector("textarea")?.value).toBe("A retained whole control acceptance");
  await submit(); await settled(() => expect(compliance.createExemption).toHaveBeenCalledTimes(1));
});

it.each(["passed", "manual", "exempted", "unknown-effective-status"])("blocks exemptions when all matching evidence is %s", async (scenario) => {
  const ineligible = scenario === "passed" ? { ...check, status: "pass" as const, effective_status: "pass" as const }
    : scenario === "manual" ? { ...check, status: "manual" as const, effective_status: "manual" as const }
    : scenario === "exempted" ? { ...check, effective_status: "exempted" as const }
    : { ...check, effective_status: "unknown" as ComplianceCheck["effective_status"] };
  vi.mocked(compliance.checks).mockResolvedValue({ checks: [ineligible, ineligible] });
  await renderPage(<ComplianceExemptionFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  expect(host.textContent).toContain("no longer eligible"); await edit("textarea", "An ineligible control approval"); await submit(); expect(compliance.createExemption).not.toHaveBeenCalled();
});

it("renders repeated control evidence as distinct table rows without duplicate React keys", async () => {
  vi.mocked(compliance.checks).mockImplementation(async params => listResponse(params as ComplianceChecksParams, [check, check, { ...check, evidence: "Another target" }]));
  const errors = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    await renderPage(<CompliancePage />); await settled(() => expect(host.querySelectorAll('[data-testid="compliance-controls-table"] tbody tr')).toHaveLength(3));
    expect(errors.mock.calls.some((args) => args.some((message) => typeof message === "string" && message.includes("same key")))).toBe(false);
    await act(async () => { const [key] = client.getQueriesData<ComplianceChecksResponse>({ queryKey: ["compliance", "checks"] })[0]; const params = key[key.length - 1] as ComplianceChecksParams; client.setQueryData(key, listResponse(params, [check, { ...check, evidence: "Another target" }, check])); });
    await settled(() => expect(host.querySelectorAll('[data-testid="compliance-controls-table"] tbody tr')).toHaveLength(3));
    expect(errors.mock.calls.some((args) => args.some((message) => typeof message === "string" && message.includes("same key")))).toBe(false);
  } finally { errors.mockRestore(); }
});

 it("loads the exact control beyond legacy framework bounds and uses the full failure total", async () => {
  vi.mocked(compliance.checks).mockResolvedValue({ checks: [{ ...check, status: "pass", effective_status: "pass" }], total: 501, summary: { fail: 1 } });
  await renderPage(<ComplianceExemptionFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  expect(compliance.checks).toHaveBeenCalledWith("cis", "cluster", { control_id: "1.2" });
  expect(host.textContent).toContain("501 evidence rows · 1 unexempted failures"); expect(host.textContent).not.toContain("no longer eligible");
  await edit("textarea", "A whole control approval rationale"); await submit(); await settled(() => expect(compliance.createExemption).toHaveBeenCalledOnce());
 });
