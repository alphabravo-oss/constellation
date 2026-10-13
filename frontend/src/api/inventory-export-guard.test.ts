import { afterEach, expect, it, vi } from "vitest";
import { api, assets, containers, findings, securityTimeline, baselines, compliance, componentsInventory, cve, deployments, fileProfiles, imageScanResults, network, nodes, registries, repositoryScans, runtimeEvents, runtimeThreats, scanJobs, serverlessFunctions, type ScanInventoryDownloadGuard } from "./client";

afterEach(() => vi.restoreAllMocks());
const exporters: Array<[string, (guard: ScanInventoryDownloadGuard) => Promise<unknown>]> = [
  ["assets", guard => assets.exportCsv({}, guard)],
  ["compliance artifact", guard => compliance.downloadRunArtifact("run", guard)],
  ["containers", guard => containers.exportCSV("cluster", {}, guard)],
  ["timeline", guard => securityTimeline.exportCSV({}, guard)],
  ["findings", guard => findings.exportCSV({}, guard)],
  ["asset findings", guard => assets.findingsCSV("asset", {}, guard)],
  ["node vulnerabilities", guard => nodes.exportVulnerabilitiesCSV("cluster", "node", {}, guard)],
  ["compliance evidence", guard => compliance.exportEvidenceCSV({}, guard)],
  ["deployment findings", guard => deployments.findingsCSV("deployment", { cluster_id: "cluster" }, guard)],
  ["baselines", guard => baselines.inventoryCSV({ cluster_id: "cluster" }, guard)],
  ["file profiles", guard => fileProfiles.inventoryCSV({ cluster_id: "cluster" }, guard)],
  ["conversations", guard => network.conversationsCSV({}, guard)],
  ["sessions", guard => network.sessionsCSV({}, guard)],
  ["threats", guard => runtimeThreats.exportCSV({}, guard)],
  ["scan jobs", guard => scanJobs.exportCSV({}, guard)],
  ["image scans", guard => imageScanResults.exportCSV({}, guard)],
  ["serverless", guard => serverlessFunctions.exportCSV({}, guard)],
  ["repository scans", guard => repositoryScans.exportCSV({}, guard)],
  ["CVE affected images", guard => cve.affectedInventoryCSV("CVE-2026-1000", "images", {}, guard)],
  ["runtime events", guard => runtimeEvents.exportCSV({}, guard)],
  ["nodes", guard => nodes.exportCSV("cluster", {}, guard)],
  ["compliance checks", guard => compliance.exportChecksCSV({}, guard)],
  ["components", guard => componentsInventory.exportCSV({}, guard)],
  ["registry images", guard => registries.imagesCSV("registry", {}, guard)],
];

it.each(exporters)("does not dispatch pending %s CSV after its scope becomes stale", async (_name, download) => {
  let respond!: () => void;
  vi.spyOn(api, "get").mockImplementation(() => new Promise(resolve => {
    respond = () => resolve({ data: new Blob(["ID\n1\n"]), headers: { "x-export-total": "1", "x-export-limit": _name === "timeline" ? "10000" : "100000", "x-export-truncated": "false" } });
  }));
  const createURL = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:export");
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  let current = true;
  const result = download(() => current);
  const rejected = expect(result).rejects.toThrow("Refresh the inventory");
  current = false;
  respond();
  await rejected;
  expect(createURL).not.toHaveBeenCalled();
  expect(click).not.toHaveBeenCalled();
});

it("allows direct-call exports without a scope callback", async () => {
  vi.spyOn(api, "get").mockResolvedValue({ data: new Blob(["ID\n1\n"]), headers: { "x-export-total": "1", "x-export-limit": "100000", "x-export-truncated": "false" } });
  vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:export"); vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  await expect(imageScanResults.exportCSV()).resolves.toEqual({ total: 1, exported: 1, limit: 100000, truncated: false });
  expect(click).toHaveBeenCalledOnce();
});
