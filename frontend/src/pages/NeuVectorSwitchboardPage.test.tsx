import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { NeuVectorSwitchboardPage } from "./NeuVectorSwitchboardPage";

const scope = vi.hoisted(() => ({ clusterId: "cluster-a", isLoading: false }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@tanstack/react-router", () => ({ Link: ({ to, children }: { to: string; children: React.ReactNode }) => <a href={to}>{children}</a> }));
let root: Root;
let host: HTMLDivElement;
afterEach(() => { act(() => root?.unmount()); host?.remove(); });

it("keeps expert guidance collapsed and updates every cluster link after scope changes", async () => {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  await act(async () => root.render(<NeuVectorSwitchboardPage />));
  expect(host.querySelector('[data-slot="page-status"]')?.textContent).toContain("Navigation reference");
  const guidance = Array.from(host.querySelectorAll("details")).find(element => element.querySelector("summary")?.textContent?.startsWith("Advanced:"));
  expect(guidance?.open).toBe(false);
  expect(host.querySelector('[data-testid="neuvector-map-link-workloads-services-workloads"]')?.getAttribute("href")).toBe("/clusters/cluster-a/deployments");
  scope.clusterId = "cluster-b";
  await act(async () => root.render(<NeuVectorSwitchboardPage />));
  const clusterLinks = Array.from(host.querySelectorAll<HTMLAnchorElement>('a[href^="/clusters/"]'));
  expect(clusterLinks.length).toBeGreaterThan(20);
  expect(clusterLinks.every(link => link.getAttribute("href")!.startsWith("/clusters/cluster-b/"))).toBe(true);
  expect(guidance?.open).toBe(false);
});
