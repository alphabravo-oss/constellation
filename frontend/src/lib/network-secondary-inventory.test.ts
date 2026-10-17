import { expect, it } from "vitest";
import { capturePage, captureRow, streamPage, streamRow } from "@/test/network-secondary-inventory";
import { pcapInventoryMatches, streamInventoryMatches, normalizedCaptureIP } from "./network-secondary-inventory";
const streamRequest = { cluster_id: "cluster", from: "prod/api", to: "prod/db", hours: 24, limit: 100, offset: 0 };
const pcapRequest = { cluster_id: "cluster", limit: 100, offset: 0 };
it("accepts complete metadata for aggregate tuples and distinguishes raw NULL identities", () => {
 const rows = [streamRow(), { ...streamRow(), row_id: '["tcp", null, null, "allow"]', port: 0, application: "" }, { ...streamRow(), row_id: '["tcp", "", 0, "allow"]', port: 0, application: "" }];
 expect(streamInventoryMatches(streamPage(streamRequest, rows), streamRequest)).toBe(true);
});
it.each(["cluster", "pair", "page", "summary", "echo", "row", "identity", "role", "date", "duplicate", "sample"])("rejects invalid stream %s evidence", field => {
 const data = streamPage(streamRequest);
 if(field==="cluster")data.cluster_id="foreign";if(field==="pair")data.to="other";if(field==="page")data.offset=100;if(field==="summary")data.summary.bytes=-1;if(field==="echo")data.filters.peer="unexpected";if(field==="row")data.entries[0].bytes=NaN;if(field==="identity")data.entries[0].row_id='["udp","app-1",1,"allow"]';if(field==="role")data.entries[0].from_platform_role="invented";if(field==="date")data.entries[0].last_seen_at="bad";if(field==="duplicate")data.entries=[data.entries[0],data.entries[0]];if(field==="sample")data.source_complete=false;
 expect(streamInventoryMatches(data,streamRequest)).toBe(false);
});
it("accepts packet/file unknown and reported zero without conflating them",()=>{expect(pcapInventoryMatches(capturePage(pcapRequest,[captureRow(),{...captureRow("zero"),packet_count:0,file_size_bytes:0}]),pcapRequest,"org")).toBe(true);});
it.each(["cluster","org","page","summary","echo","identity","date","role","missing","negative","status","source","tuple"])("rejects invalid capture %s evidence",field=>{const data=capturePage(pcapRequest);if(field==="cluster")data.captures[0].cluster_id="other";if(field==="org")data.captures[0].org_id="other";if(field==="page")data.offset=100;if(field==="summary")data.summary.pending=0;if(field==="echo")data.filters.node="unexpected";if(field==="identity")data.captures[0].row_id="other";if(field==="date")data.captures[0].requested_at="bad";if(field==="role")data.captures[0].platform_role="guessed";if(field==="missing")Reflect.deleteProperty(data.captures[0],"packet_count");if(field==="negative")data.captures[0].packet_count=-1;if(field==="status")Object.assign(data.captures[0],{status:"unknown"});if(field==="source")data.source_complete=false;if(field==="tuple")data.filters.dst_port=443;expect(pcapInventoryMatches(data,pcapRequest,"org")).toBe(false);});
it("normalizes capture IPv6 exactly and rejects broadened tuple echoes",()=>{expect(normalizedCaptureIP("2001:0DB8:0000::1")).toBe("2001:db8::1");expect(normalizedCaptureIP("::ffff:192.0.2.1")).toBe("192.0.2.1");const request={...pcapRequest,src_ip:"2001:0DB8::1"};const data=capturePage(pcapRequest,[{...captureRow(),src_ip:"2001:db8::1"}]);data.filters.src_ip="2001:db8::1";expect(pcapInventoryMatches(data,request,"org")).toBe(true);data.captures[0].src_ip="2001:db8::2";expect(pcapInventoryMatches(data,request,"org")).toBe(false);});

it.each(["file_count", "file_size_mb"])("rejects malformed optional capture setting %s", field => { const data = capturePage(pcapRequest); Object.assign(data.captures[0], { [field]: "not a number" }); expect(pcapInventoryMatches(data, pcapRequest, "org")).toBe(false); Object.assign(data.captures[0], { [field]: -1 }); expect(pcapInventoryMatches(data, pcapRequest, "org")).toBe(false); });

it("preserves full uint32 threat IDs and explicit historical uncertainty including zero", () => {
  for (const threat_id of [0, 2147483647, 2147483648, 4294967295]) {
    const data = streamPage(streamRequest, [{ ...streamRow(), threat_id, threat_id_complete: false }]);
    data.summary.threat_id_incomplete = 1;
    data.totals.threat_id_incomplete = 1;
    expect(streamInventoryMatches(data, streamRequest)).toBe(true);
  }
});
it.each([-1, 4294967296, NaN])("rejects non-wire threat ID %s", threat_id => {
  expect(streamInventoryMatches(streamPage(streamRequest, [{ ...streamRow(), threat_id }]), streamRequest)).toBe(false);
});
it("rejects fabricated completeness flags and impossible incomplete totals", () => {
  const data = streamPage(streamRequest);
  Object.assign(data.entries[0], { threat_id_complete: "true" });
  expect(streamInventoryMatches(data, streamRequest)).toBe(false);
  data.entries[0].threat_id_complete = false;
  data.summary.threat_id_incomplete = data.total + 1;
  data.totals.threat_id_incomplete = data.total + 1;
  expect(streamInventoryMatches(data, streamRequest)).toBe(false);
});
