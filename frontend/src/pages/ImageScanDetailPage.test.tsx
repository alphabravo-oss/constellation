import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { imageScanResults, type ImageScanResult } from "@/api/client";
import { ImageScanDetailPage } from "./ImageScanDetailPage";

vi.mock("@/api/client", () => ({ imageScanResults: { get: vi.fn(), layers: vi.fn(), packages: vi.fn(), secrets: vi.fn(), fileRisks: vi.fn(), signature: vi.fn(), configChecks: vi.fn() } }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams("tab=evidence"), vi.fn()] }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: "cluster", isLoading: false }) }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ resultId: "result" }), Link: ({ children, href }: { children: ReactNode; href?: string }) => <a href={href}>{children}</a> }));

let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); });

it("fetches failed zero-count artifacts and shows failures instead of clean empty reports", async () => {
  const result: ImageScanResult = { image_ref_normalized: "example.com/app:latest", image_repository: "example.com/app", image_signed: false, severity_counts: {}, critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, info_count: 0, impacted_count: 0, first_seen_at: "2026-10-12T00:00:00Z", updated_at: "2026-10-12T00:00:00Z", id: "result", image_ref: "example.com/app:latest", image_digest: "sha256:test", scanner_profile: "default", package_count: 0, layer_count: 0, secret_count: 0, file_risk_count: 0, finding_count: 0, max_risk_score: 0, last_scanned_at: "2026-10-12T00:00:00Z", engine_status: { syft: "succeeded", trivy: "succeeded", grype: "failed" } };
  vi.mocked(imageScanResults.get).mockResolvedValue({ image_scan_result: result, findings: [], impacted_workloads: [] });
  vi.mocked(imageScanResults.layers).mockResolvedValue({ layer_metadata: { status: "error", reason: "registry manifest metadata unavailable" } } as Awaited<ReturnType<typeof imageScanResults.layers>>);
  vi.mocked(imageScanResults.fileRisks).mockResolvedValue({ file_risk: { status: "error", reason: "image filesystem metadata unavailable" } } as Awaited<ReturnType<typeof imageScanResults.fileRisks>>);
  vi.mocked(imageScanResults.configChecks).mockResolvedValue({ config_checks: { status: "error", reason: "image config unavailable" } } as Awaited<ReturnType<typeof imageScanResults.configChecks>>);
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><ImageScanDetailPage /></QueryClientProvider>));
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 30)); });
  expect(imageScanResults.layers).toHaveBeenCalledWith("result");
  expect(imageScanResults.fileRisks).toHaveBeenCalledWith("result");
  expect(host.textContent).toContain("Findings may be incomplete");
  expect(host.textContent).toContain("Inspection failed. registry manifest metadata unavailable");
  expect(host.textContent).toContain("Inspection failed. image filesystem metadata unavailable");
  expect(host.textContent).toContain("Inspection failed. image config unavailable");
  expect(host.textContent).not.toContain("No layer metadata recorded");
  expect(host.textContent).not.toContain("image predates this scan feature");
  expect(host.textContent).not.toContain("VulnDB provenance");
});
