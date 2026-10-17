import { expect, it } from "vitest";
import type { ScanJob, ScanJobInventoryResponse } from "@/api/client";
import { scanJobInventoryResponseValid } from "./scan-job-inventory";

const row: ScanJob = {id:"job",org_id:"org",target_id:"target",target_type:"image",target_ref:"image:latest",target_cluster_id:"cluster",registry_id:"registry",status:"failed",attempt_count:1,max_attempts:3,requested_at:"2026-10-12"};
const response = (): ScanJobInventoryResponse => ({jobs:[row],total:201,summary:{total:201,pending:0,running:0,paused:0,completed:0,failed:201,canceled:0},limit:100,offset:200,sort:"requested",order:"desc",has_more:false});
const request = {limit:100,offset:200,status:"failed",cluster_id:"cluster",registry_id:"registry"};

it("accepts a final server page beyond the previous 200-row cap with matching full counts", () => {
 expect(scanJobInventoryResponseValid(response(),request,"org")).toBe(true);
});
it("rejects foreign tenant, cluster and registry evidence without hiding it inside valid count metadata", () => {
 for (const foreign of [{org_id:"foreign"},{target_cluster_id:"foreign"},{registry_id:"foreign"}]) {
  expect(scanJobInventoryResponseValid({...response(),jobs:[{...row,...foreign}]},request,"org")).toBe(false);
 }
});
it("rejects unsupported lifecycle evidence and mismatched summaries, sort, offset or continuation", () => {
 for (const change of [{summary:{...response().summary,failed:200}},{sort:"target"},{offset:100},{has_more:true},{jobs:[{...row,status:"queued"}]},{jobs:[{...row,target_type:"unknown"}]}]) {
  expect(scanJobInventoryResponseValid({...response(),...change},request,"org")).toBe(false);
 }
});
it("requires the backend default 200-row contract when a caller omits pagination", () => {
 const empty:ScanJobInventoryResponse={jobs:[],total:0,summary:{total:0,pending:0,running:0,paused:0,completed:0,failed:0,canceled:0},limit:200,offset:0,sort:"requested",order:"desc",has_more:false};
 expect(scanJobInventoryResponseValid(empty,{})).toBe(true);
 expect(scanJobInventoryResponseValid({...empty,limit:100},{})).toBe(false);
});
