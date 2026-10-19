import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { ClusterSummary } from "@/api/client";
import { ClusterTile } from "./ClustersLandingPage";
vi.mock("@tanstack/react-router", () => ({ Link: ({children}: {children: React.ReactNode}) => <a>{children}</a>, useNavigate: () => vi.fn() }));
const cluster = {id:"one", name:"Cluster", distro:"k3s", state:"connected", deployments:3,
 stats:{critical_open:583,high_open:3804,open_findings:4387,total_findings:4387},
 exposure:{inventory_status:"fresh",current_critical:12,current_high:28,current_occurrences:136,historical_occurrences:1790,unverified_occurrences:2461}
} as ClusterSummary;
describe("cluster exposure",()=>{
 it("separates distinct current vulnerabilities from historical and unverified occurrences",()=>{
  const html=renderToStaticMarkup(<ClusterTile cluster={cluster}/>);
  expect(html).toContain("Current critical");expect(html).toContain(">12<");expect(html).toContain(">28<");
  expect(html).toContain("Total occurrences");expect(html).toContain("4,387");
  expect(html).toContain("Partial coverage");expect(html).not.toContain("<details open");
  expect(html).toContain("Historical findings");expect(html).toContain("1,790");expect(html).toContain("Unverified findings");expect(html).toContain("2,461");
  expect(html).toContain("counts may be incomplete");expect(html).not.toContain("Critical (open)");
 });
 it.each(["stale","missing"] as const)("does not present %s inventory as zero exposure",status=>{
  const html=renderToStaticMarkup(<ClusterTile cluster={{...cluster,exposure:{...cluster.exposure!,inventory_status:status}}}/>);
  expect(html).toContain(status === "stale" ? "Inventory out of date" : "Inventory unavailable");expect(html).not.toContain(">12<");
 });
 it("keeps old API responses explicitly unverified",()=>{
  expect(renderToStaticMarkup(<ClusterTile cluster={{...cluster,exposure:undefined}}/>)).toContain("Inventory unavailable");
 });
});
