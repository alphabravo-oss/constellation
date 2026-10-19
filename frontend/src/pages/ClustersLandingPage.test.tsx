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
  expect(html).toContain("4387 total critical/high finding occurrences");
  expect(html).toContain("1790 historical pod occurrences");expect(html).toContain("2461 unverified occurrences");
  expect(html).toContain("Current totals are incomplete");expect(html).not.toContain("Critical (open)");
 });
 it.each(["stale","missing"] as const)("does not present %s inventory as zero exposure",status=>{
  const html=renderToStaticMarkup(<ClusterTile cluster={{...cluster,exposure:{...cluster.exposure!,inventory_status:status}}}/>);
  expect(html).toContain("Current exposure is unverified");expect(html).not.toContain(">12<");
 });
 it("keeps old API responses explicitly unverified",()=>{
  expect(renderToStaticMarkup(<ClusterTile cluster={{...cluster,exposure:undefined}}/>)).toContain("inventory is unavailable");
 });
});
