import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { imageScanResults, type ImageScanResult, type ImageScanFinding, type ImpactedWorkload } from "@/api/client";
import { downloadCsv } from "@/lib/csv";
import { TestRouter } from "@/test/router";
import { ImageScanDetailPage } from "./ImageScanDetailPage";

const scope = vi.hoisted(() => ({ ready: true, loading: false }));
vi.mock("./entity-detail-scope", () => ({ useEntityClusterScope: () => ({ ...scope, clusterId: "cluster", retry: vi.fn() }) }));
vi.mock("@/api/client", () => ({ imageScanResults: { get: vi.fn(), layers: vi.fn(), packages: vi.fn(), secrets: vi.fn(), fileRisks: vi.fn(), signature: vi.fn(), configChecks: vi.fn() } }));
vi.mock("@/lib/csv", async importOriginal => ({ ...await importOriginal<typeof import("@/lib/csv")>(), downloadCsv: vi.fn() }));
const result: ImageScanResult = { image_ref_normalized: "example.com/app:latest", image_repository: "example.com/app", image_signed: false, severity_counts: {}, critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, info_count: 0, impacted_count: 0, first_seen_at: "2026-10-12T00:00:00Z", updated_at: "2026-10-12T00:00:00Z", id: "result", image_ref: "example.com/app:latest", image_digest: "sha256:test", scanner_profile: "default", package_count: 105, layer_count: 0, secret_count: 7, file_risk_count: 7, finding_count: 0, max_risk_score: 0, last_scanned_at: "2026-10-12T00:00:00Z", signature_status: "unsigned", engine_status: { syft: "succeeded", trivy: "succeeded", grype: "failed" } };
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  scope.ready = true; scope.loading = false;
  vi.mocked(imageScanResults.get).mockResolvedValue({ image_scan_result: result, findings: [], impacted_workloads: [] });
  vi.mocked(imageScanResults.layers).mockResolvedValue({ image_scan_result_id: "result", format: "constellation-image-layers-v1", sha256: "layers", layer_count: 0, created_at: "2026-10-12T00:00:00Z", layer_metadata: { layers: [] } });
  vi.mocked(imageScanResults.packages).mockResolvedValue({ image_scan_result_id: "result", package_layers: [{ layer_digest: "sha256:layer", package_count: 105, packages: Array.from({ length: 105 }, (_, i) => ({ name: `package-${i}`, version: "1.2.3", locations: [{ path: `/opt/package-${i}`, layer_digest: "sha256:layer" }] })) }], layer_package_count: 105 } as Awaited<ReturnType<typeof imageScanResults.packages>>);
  vi.mocked(imageScanResults.secrets).mockResolvedValue({ image_scan_result_id: "result", secret_scan: { secrets: Array.from({ length: 7 }, (_, i) => ({ rule_id: `secret-${i}`, path: `/app/secret-${i}`, severity: "high", start_line: 10, end_line: 12 })) } } as Awaited<ReturnType<typeof imageScanResults.secrets>>);
  vi.mocked(imageScanResults.fileRisks).mockResolvedValue({ image_scan_result_id: "result", file_risk: { findings: Array.from({ length: 7 }, (_, i) => ({ path: `/usr/bin/risk-${i}`, mode: "4755", uid: 0, gid: 0, reason: "Unexpected privilege", severity: "high", risk_types: ["setuid"] })) } } as Awaited<ReturnType<typeof imageScanResults.fileRisks>>);
  vi.mocked(imageScanResults.configChecks).mockResolvedValue({ image_scan_result_id: "result", config_checks: { checks: [{ id: "check", title: "Use a non-root user", status: "fail", remediation: "Configure USER", detail: "Image user is root" }] } } as Awaited<ReturnType<typeof imageScanResults.configChecks>>);
  vi.mocked(imageScanResults.signature).mockResolvedValue({ image_scan_result_id: "result", signature_scan: { status: "unsigned" } } as Awaited<ReturnType<typeof imageScanResults.signature>>);
});
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); });
async function render(search = "?tab=evidence") {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  history = createMemoryHistory({ initialEntries: [`/clusters/cluster/images/result${search}`] });
  await act(async () => root.render(<QueryClientProvider client={client}><TestRouter path="/clusters/$id/images/$resultId" history={history}><ImageScanDetailPage /></TestRouter></QueryClientProvider>));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function tab(name: string) { const trigger = [...host.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find((x) => x.textContent === name || x.getAttribute("aria-label") === name || x.getAttribute("data-export-label") === name)!; await act(async () => trigger.focus()); await settled(() => expect(trigger.getAttribute("aria-selected")).toBe("true")); }
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>("button")].find((x) => x.textContent === label || x.getAttribute("aria-label") === label || x.getAttribute("data-export-label") === label)!;

it("exposes all layer-linked packages and all secrets/file risks through shared paging", async () => {
  await render("?tab=evidence&context=keep#proof");
  await settled(() => expect(host.textContent).toContain("package-99"));
  expect(host.textContent).not.toContain("package-104");
  await act(async () => button("Next").click());
  expect(host.textContent).toContain("package-104");
  await tab("Secrets"); await settled(() => expect(host.textContent).toContain("secret-6"));
  expect(host.textContent).toContain("10-12");
  expect(new URLSearchParams(history.location.search).get("evidence")).toBe("secrets");
  expect(history.location.hash).toBe("#proof");
  await tab("File risks"); await settled(() => expect(host.textContent).toContain("/usr/bin/risk-6"));
  expect(host.textContent).toContain("4755 · 0:0");
  await act(async () => history.back()); await settled(() => expect(host.textContent).toContain("secret-6"));
  expect(new URLSearchParams(history.location.search).get("context")).toBe("keep");
});

it("shows reported failed zero-count inspections rather than clean empty evidence", async () => {
  vi.mocked(imageScanResults.get).mockResolvedValue({ image_scan_result: { ...result, layer_count: 0, file_risk_count: 0 }, findings: [], impacted_workloads: [] });
  vi.mocked(imageScanResults.layers).mockResolvedValue({ image_scan_result_id: "result", layer_metadata: { status: "error", reason: "manifest unavailable" } } as Awaited<ReturnType<typeof imageScanResults.layers>>);
  vi.mocked(imageScanResults.fileRisks).mockResolvedValue({ image_scan_result_id: "result", file_risk: { status: "error", reason: "filesystem unavailable" } } as Awaited<ReturnType<typeof imageScanResults.fileRisks>>);
  vi.mocked(imageScanResults.configChecks).mockResolvedValue({ image_scan_result_id: "result", config_checks: { status: "error", reason: "config unavailable" } } as Awaited<ReturnType<typeof imageScanResults.configChecks>>);
  await render("?tab=evidence&evidence=layers"); await settled(() => expect(host.textContent).toContain("Inspection failed. manifest unavailable"));
  expect(host.textContent).toContain("Findings may be incomplete");
  await tab("File risks"); await settled(() => expect(host.textContent).toContain("Inspection failed. filesystem unavailable"));
  await tab("Config checks"); await settled(() => expect(host.textContent).toContain("Inspection failed. config unavailable"));
  expect(host.textContent).not.toContain("image predates this scan feature");
});

it.each(["packages", "secrets", "signature"] as const)("keeps failed %s reads unavailable, including failed refresh with cached evidence", async method => {
  await render(`?tab=evidence&evidence=${method}`); await settled(() => expect(imageScanResults[method]).toHaveBeenCalled());
  vi.mocked(imageScanResults[method]).mockRejectedValue(new Error("source offline"));
  await act(async () => { await client.invalidateQueries({ queryKey: [`image-scan-${method}`] }); });
  await settled(() => expect(host.textContent).toContain("unavailable."));
  expect(host.querySelectorAll("tbody tr")).toHaveLength(0);
  expect(button("Retry evidence")).toBeDefined();
});

it("rejects foreign artifact identity without rendering its data", async () => {
  vi.mocked(imageScanResults.secrets).mockResolvedValue({ image_scan_result_id: "foreign", secret_scan: { secrets: [{ rule_id: "foreign-secret" }] } } as Awaited<ReturnType<typeof imageScanResults.secrets>>);
  await render("?tab=evidence&evidence=secrets"); await settled(() => expect(host.textContent).toContain("Secret evidence unavailable"));
  expect(host.textContent).not.toContain("foreign-secret");
});
it("waits for exact cluster resolution and rejects a different scan result", async () => {
  scope.ready = false; await render(); expect(imageScanResults.get).not.toHaveBeenCalled(); expect(host.textContent).toContain("Image scan evidence unavailable");
});
it("does not substitute a different scan response", async () => {
  vi.mocked(imageScanResults.get).mockResolvedValue({ image_scan_result: { ...result, id: "foreign", image_repository: "foreign-image" }, findings: [], impacted_workloads: [] });
  await render(); await settled(() => expect(host.textContent).toContain("Image scan evidence unavailable")); expect(host.textContent).not.toContain("foreign-image");
});
it("filters unavailable fix versions honestly and preserves zero CVSS", async () => {
  const findings = ["1.2", "", "false", "not-fixed", "WONT-FIX", "won't-fix"].map((fixed, i) => ({ id: `f-${i}`, title: `finding-${i}`, external_id: `CVE-${i}`, fixed_version: fixed, cvss_base: 0, risk_score: 0, severity: "low" } as ImageScanFinding));
  vi.mocked(imageScanResults.get).mockResolvedValue({ image_scan_result: { ...result, finding_count: 6 }, findings, impacted_workloads: [] });
  await render(""); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(6));
  expect(host.querySelector('td[data-column-id="cvss"]')?.textContent ?? host.textContent).toContain("0.0");
  await act(async () => host.querySelector<HTMLInputElement>('[data-testid="image-scan-fixable-toggle"]')!.click());
  expect(host.querySelectorAll("tbody tr")).toHaveLength(1); expect(host.textContent).toContain("finding-0");
  expect(host.textContent).toContain("contains the full scan");
});

it("keeps distinct workload links sharing a deployment and image stable across refresh", async () => {
  const warn = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    const base: ImpactedWorkload = { cluster_id: "cluster", deployment_id: "deployment", workload_id: "pod-one", namespace: "payments", name: "api", kind: "Deployment", image_ref: "example.com/app:latest", image_ref_normalized: "example.com/app:latest", risk_score: 1, finding_count: 1, critical_count: 0, high_count: 0, last_seen_at: "2026-10-12T00:00:00Z" };
    const second = { ...base, workload_id: "pod-two", risk_score: 2 };
    vi.mocked(imageScanResults.get).mockResolvedValue({ image_scan_result: result, findings: [], impacted_workloads: [base, second] });
    await render("?tab=workloads"); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(2));
    vi.mocked(imageScanResults.get).mockResolvedValue({ image_scan_result: result, findings: [], impacted_workloads: [second] });
    await act(async () => button("Refresh").click()); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(1));
    expect(host.querySelector("tbody tr td:last-child")?.textContent).toBe("2");
    expect(host.querySelector("tbody a")?.getAttribute("href")).toBe("/clusters/cluster/deployments/deployment");
    expect(warn.mock.calls.flat().map(String).join(" ")).not.toMatch(/same key|unique.*key/i);
  } finally { warn.mockRestore(); }
});

it.each(["tagged", "reference-with-digest", "digest-only"] as const)("keeps %s detail headings and identity readable until raw identity is requested", async kind => {
  const digest = `sha256:${"b".repeat(64)}`;
  const named = "registry.example.test/team/app:v2";
  const reference = kind === "digest-only" ? digest : `${named}@${digest}`;
  const record = { ...result, image_digest: digest, image_ref: reference, image_ref_normalized: reference, image_repository: kind === "tagged" ? "registry.example.test/team/app" : kind === "digest-only" ? digest : "", image_tag: kind === "tagged" ? "v2" : "", source_ref: reference };
  vi.mocked(imageScanResults.get).mockResolvedValue({ image_scan_result: record, findings: [], impacted_workloads: [] });
  await render("");
  await settled(() => expect(host.querySelector("h1")?.textContent).toBe(kind === "digest-only" ? "Unnamed image" : named));
  expect(host.textContent).not.toContain("sha256:");
  expect(imageScanResults.get).toHaveBeenCalledWith("result");
  await tab("Identity and exports");
  const identity = [...host.querySelectorAll("section")].find(item => item.querySelector("h2")?.textContent === "Image identity")!;
  const shown = identity.cloneNode(true) as HTMLElement;
  shown.querySelectorAll("details:not([open])").forEach(item => item.remove());
  expect(shown.textContent).not.toContain("sha256:");
  const source = [...identity.querySelectorAll<HTMLDetailsElement>("details")].find(item => item.querySelector("summary")?.textContent.includes("Source reference"))!;
  expect(source.open).toBe(false);
  expect(source.querySelector("code")?.textContent).toBe(reference);
  const disclosure = [...identity.querySelectorAll<HTMLDetailsElement>("details")].find(item => item.querySelector("summary")?.textContent === "Show digest")!;
  expect(disclosure.open).toBe(false);
  expect(disclosure.querySelector("code")?.textContent).toBe(digest);
  await act(async () => disclosure.querySelector("summary")!.click());
  expect(disclosure.open).toBe(true);
  expect(disclosure.querySelector("code")?.textContent).toBe(digest);
  const raw = [...identity.querySelectorAll<HTMLDetailsElement>("details")].find(item => item.querySelector("summary")?.textContent.includes("Raw image reference"))!;
  expect(raw.open).toBe(false);
  await act(async () => raw.querySelector("summary")!.click());
  expect(raw.open).toBe(true);
  expect(raw.querySelector("code")?.textContent).toBe(reference);
  expect(record.image_ref).toBe(reference);
  expect(record.image_digest).toBe(digest);
});


async function revealStoredDigests(area: Element, expected: string[]) {
  const disclosures = [...area.querySelectorAll<HTMLDetailsElement>("details")].filter(item => item.querySelector("summary")?.textContent === "Show digest");
  expect(disclosures.map(item => item.querySelector("code")?.textContent)).toEqual(expected);
  expect(disclosures.every(item => !item.open)).toBe(true);
  const shown = area.cloneNode(true) as HTMLElement;
  shown.querySelectorAll("details:not([open])").forEach(item => item.remove());
  expect(shown.textContent).not.toContain("sha256:");
  for (const [index, disclosure] of disclosures.entries()) {
    await act(async () => disclosure.querySelector("summary")!.click());
    expect(disclosure.open).toBe(true);
    expect(disclosure.querySelector("code")?.textContent).toBe(expected[index]);
  }
}

it("keeps provenance bundle hashes collapsed until explicitly opened", async () => {
  const reported = `sha256:${"c".repeat(64)}`;
  const fallback = `sha256:${"d".repeat(64)}`;
  vi.mocked(imageScanResults.get).mockResolvedValue({ image_scan_result: { ...result, vulndb_bundle_hash: reported, bundle_metadata: { payload_hash: fallback } }, findings: [], impacted_workloads: [] });
  await render("?tab=details");
  await settled(() => expect(host.textContent).toContain("Scan provenance and exports"));
  const bundle = () => [...host.querySelectorAll("section")].find(item => item.querySelector("h2")?.textContent === "Scan provenance and exports")!;
  await revealStoredDigests(bundle(), [reported]);
  vi.mocked(imageScanResults.get).mockResolvedValue({ image_scan_result: { ...result, bundle_metadata: { payload_hash: fallback } }, findings: [], impacted_workloads: [] });
  await act(async () => button("Refresh").click());
  await settled(() => expect(bundle().querySelector("code")?.textContent).toBe(fallback));
  await revealStoredDigests(bundle(), [fallback]);
});

it("keeps package, file-risk and image-layer hashes collapsed while preserving layer CSV identity", async () => {
  const first = `sha256:${"a".repeat(64)}`, second = `sha256:${"b".repeat(64)}`, diff = `sha256:${"c".repeat(64)}`;
  vi.mocked(imageScanResults.get).mockResolvedValue({ image_scan_result: { ...result, package_count: 3, file_risk_count: 3, layer_count: 2 }, findings: [], impacted_workloads: [] });
  vi.mocked(imageScanResults.packages).mockResolvedValue({ image_scan_result_id: "result", package_layers: [
    { layer_index: 0, layer_digest: first, package_count: 1, packages: [{ name: "owned-package-zero", version: "1.2.3", ecosystem: "apk", locations: [{ path: "/not-selected", layer_digest: second }, { path: "/owned/package-zero", layer_digest: first }] }] },
    { layer_digest: second, package_count: 1, packages: [{ name: "owned-package-unknown", ecosystem: "deb", locations: [{ real_path: "/owned/package-unknown" }] }] },
    { layer_index: 7, package_count: 1, packages: [{ name: "owned-package-seven", locations: [{ access_path: "/owned/package-seven" }] }] },
  ], layer_package_count: 3 } as Awaited<ReturnType<typeof imageScanResults.packages>>);
  vi.mocked(imageScanResults.fileRisks).mockResolvedValue({ image_scan_result_id: "result", file_risk: { findings: [
    { path: "/owned/zero", reason: "Unexpected privilege", severity: "high", risk_types: ["setuid", "owner"], mode: "4755", uid: 0, gid: 0, layer_index: 0, layer_digest: first },
    { path: "/owned/unknown", type: "file", severity: "low", risk_types: ["writable"], mode: "0644", uid: 1000, gid: 1001, layer_digest: second },
    { path: "/owned/seven", layer_index: 7 },
  ] } } as Awaited<ReturnType<typeof imageScanResults.fileRisks>>);
  vi.mocked(imageScanResults.layers).mockResolvedValue({ image_scan_result_id: "result", layer_metadata: { layers: [
    { index: 0, digest: first, diff_id: diff, command: "RUN apk add curl" },
    { index: 7, digest: second, command: "COPY app /app" },
  ] } } as Awaited<ReturnType<typeof imageScanResults.layers>>);
  await render("?tab=evidence&evidence=packages");
  await settled(() => expect(host.textContent).toContain("owned-package-seven"));
  expect(host.textContent).toContain("Layer 0");
  expect(host.textContent).toContain("Layer index not reported");
  expect(host.textContent).toContain("Layer 7");
  await revealStoredDigests(host.querySelector('[data-testid="image-scan-artifact-evidence"]')!, [first, second]);
  await act(async () => button("Export CSV").click());
  expect(downloadCsv).toHaveBeenLastCalledWith("image-package-provenance", ["Layer", "Package", "Evidence path"], [
    [first, "owned-package-zero · 1.2.3", "/owned/package-zero"],
    [second, "owned-package-unknown · deb", "/owned/package-unknown"],
    ["7", "owned-package-seven · -", "/owned/package-seven"],
  ]);
  await tab("File risks");
  await settled(() => expect(host.textContent).toContain("/owned/seven"));
  await revealStoredDigests(host.querySelector('[data-testid="image-scan-artifact-evidence"]')!, [first, second]);
  await act(async () => button("Export CSV").click());
  expect(downloadCsv).toHaveBeenLastCalledWith("image-file-risk-evidence", ["Path", "Risk", "Mode", "Layer"], [
    ["/owned/zero · Unexpected privilege", "high · setuid, owner", "4755 · 0:0", first],
    ["/owned/unknown · file", "low · writable", "0644 · 1000:1001", second],
    ["/owned/seven · -", "info · -", "- · -:-", "7"],
  ]);
  await tab("Layers");
  await settled(() => expect(host.textContent).toContain("RUN apk add curl"));
  const layers = host.querySelector('[data-testid="image-scan-artifact-evidence"]')!;
  expect(layers.textContent).toContain("Layer 0");
  expect(layers.textContent).toContain("Layer 7");
  expect(layers.textContent).toContain("COPY app /app");
  expect([...layers.querySelectorAll("[title]")].some(item => [first, second, diff].includes(item.getAttribute("title")!))).toBe(false);
  await revealStoredDigests(layers, [first, diff, second]);
});

it.each(["named", "normalized-name", "digest-only", "reported-repository", "reported-digest"] as const)("keeps %s affected workload image references friendly without changing CSV identity", async kind => {
  const digest = `sha256:${"e".repeat(64)}`;
  const named = "registry.example.test/team/app:v2";
  const reference = kind === "named" ? `${named}@${digest}` : kind === "reported-digest" ? named : digest;
  const normalized = kind === "digest-only" || kind === "reported-repository" ? digest : kind === "reported-digest" ? named : `${named}@${digest}`;
  const workload: ImpactedWorkload = { cluster_id: "cluster", deployment_id: "deployment", workload_id: "pod", namespace: "payments", name: "api", kind: "Deployment", image_ref: reference, image_ref_normalized: normalized, image_repository: kind === "reported-repository" ? "registry.example.test/team/app" : undefined, image_tag: kind === "reported-repository" ? "v2" : undefined, image_digest: kind === "reported-repository" || kind === "reported-digest" ? digest : undefined, risk_score: 1, finding_count: 1, critical_count: 0, high_count: 0, last_seen_at: "2026-10-12T00:00:00Z" };
  vi.mocked(imageScanResults.get).mockResolvedValue({ image_scan_result: { ...result, image_ref: digest, image_ref_normalized: `${named}@${digest}`, image_repository: "" }, findings: [], impacted_workloads: [workload] });
  await render("?tab=workloads");
  await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(1));
  const cell = host.querySelector('td[data-column-id="image"]')!;
  expect(cell.querySelector("span")?.textContent).toBe(kind === "digest-only" ? "Unnamed image" : named);
  await revealStoredDigests(cell, [digest]);
  expect(host.querySelector("tbody a")?.getAttribute("href")).toBe("/clusters/cluster/deployments/deployment");
  await act(async () => button("Export CSV").click());
  expect(vi.mocked(downloadCsv).mock.calls.at(-1)![2][0][2]).toBe(reference);
  await tab("Identity and exports");
  const referenceField = [...host.querySelectorAll("dt")].find((item) => item.textContent === "Reference" || item.getAttribute("aria-label") === "Reference" || item.getAttribute("data-export-label") === "Reference")!;
  expect(referenceField.nextElementSibling?.textContent).toBe(named);
});
