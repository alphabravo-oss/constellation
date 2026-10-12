import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cve, type CVEResult, type CVESearchParams } from "@/api/client";
import { CVEPage } from "./CVEPage";
const route = vi.hoisted(() => ({ initial: "", latest: "" }));
vi.mock("@/lib/route-search", async () => {
  const { useState } = await import("react");
  return { useRouteSearchParams: () => {
    const [params, setParams] = useState(() => new URLSearchParams(route.initial));
    return [params, (next: URLSearchParams | ((current: URLSearchParams) => URLSearchParams)) => setParams(current => {
      const result = typeof next === "function" ? next(new URLSearchParams(current)) : next;
      route.latest = result.toString(); return new URLSearchParams(result);
    })];
  } };
});
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => vi.fn(), Link: ({ children, href }: { children: ReactNode; href?: string }) => <a href={href}>{children}</a> }));
vi.mock("@/api/client", () => ({ cve: { search: vi.fn(), stats: vi.fn().mockResolvedValue({ total: 1000, kev_listed: 20, epss_gt_50: 30, cvss_gt_70: 40 }), bundle: vi.fn().mockResolvedValue({ available: false }) } }));
let root: Root; let host: HTMLDivElement; let client: QueryClient;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  route.initial = ""; route.latest = "";
  vi.mocked(cve.search).mockImplementation(async arg => {
    const params = arg as CVESearchParams; const offset = params.offset ?? 0;
    return { results: Array.from({ length: offset === 0 ? 51 : 1 }, (_, index) => ({ cve_id: `CVE-page-${offset + index}`, cvss_base: 5, sources: [] } as unknown as CVEResult)), limit: params.limit!, offset };
  });
});
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.clearAllMocks(); });
async function render() {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><CVEPage /></QueryClientProvider>));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function click(label: string) { await act(async () => { [...host.querySelectorAll<HTMLElement>("button,[role=button]")].find(b => b.textContent?.trim() === label)!.click(); }); }
it("uses server lookahead to navigate beyond the first fifty records", async () => {
  await render(); await settled(() => expect(host.textContent).toContain("CVE-page-49"));
  expect(host.textContent).not.toContain("CVE-page-50");
  await click("Next"); await settled(() => expect(host.textContent).toContain("CVE-page-50"));
  expect(cve.search).toHaveBeenLastCalledWith(expect.objectContaining({ limit: 51, offset: 50 }));
  expect(new URLSearchParams(route.latest).get("page")).toBe("2");
  expect([...host.querySelectorAll("button")].find(b => b.textContent === "Next")?.disabled).toBe(true);
  const kevFilter = [...host.querySelectorAll<HTMLElement>("[role=button]")].find(el => el.textContent === "KEV-only")!;
  expect(kevFilter.tabIndex).toBe(0);
  await act(async () => kevFilter.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true })));
  await settled(() => expect(cve.search).toHaveBeenLastCalledWith(expect.objectContaining({ kev: true, offset: 0 })));
  expect(new URLSearchParams(route.latest).has("page")).toBe(false);
});
it("restores page, filters, and global sort from a shared URL", async () => {
  route.initial = "q=openssl&page=3&kev=true&severity=high&source=NVD&sort=published&dir=asc";
  await render(); await settled(() => expect(cve.search).toHaveBeenCalledWith(expect.objectContaining({ q: "openssl", offset: 100, kev: true, severity: "high", source: "NVD", sort: "published", dir: "asc" })));
  expect(host.querySelector<HTMLInputElement>('[data-testid="cve-search-input"]')?.value).toBe("openssl");
});
it("shows a retryable load failure instead of a false empty result", async () => {
  vi.mocked(cve.search).mockRejectedValue(new Error("private transport details"));
  await render(); await settled(() => expect(host.textContent).toContain("Could not load CVE results"));
  expect(host.textContent).not.toContain("No CVEs match"); expect(host.textContent).not.toContain("private transport details");
});
it("keeps the server order authoritative and follows sort changes in the header", async () => {
  vi.mocked(cve.search).mockResolvedValue({ results: [
    { cve_id: "CVE-server-first", cvss_base: 1, sources: [] },
    { cve_id: "CVE-server-second", cvss_base: 9, sources: [] },
  ] as unknown as CVEResult[], limit: 51, offset: 0 });
  await render();
  await settled(() => expect(host.querySelector('tbody tr')?.textContent).toContain("CVE-server-first"));
  expect(host.querySelector('th[data-column-id="cvss"]')?.getAttribute("aria-sort")).toBe("descending");
  await act(async () => { host.querySelector<HTMLButtonElement>('th[data-column-id="cvss"] button')?.click(); });
  await settled(() => expect(cve.search).toHaveBeenLastCalledWith(expect.objectContaining({sort:"cvss",dir:"asc",offset:0})));
  await settled(() => expect(host.querySelector('th[data-column-id="cvss"]')?.getAttribute("aria-sort")).toBe("ascending"));
  expect(host.querySelector('tbody tr')?.textContent).toContain("CVE-server-first");
});
