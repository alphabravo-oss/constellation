import { expect, it } from "vitest";
import { buildNetworkSavedViewSnapshot } from "./network-saved-views";
import { networkViewHref, networkViewSnapshotFromParams } from "./network-saved-view-route";
export const snapshot = buildNetworkSavedViewSnapshot({ workspaceTab: "conversations", hours: 168, namespace: "prod", group: "group-id", verdict: "block", verdictsVisible: { allow: false, alert: true, block: true }, protocolFilter: ["HTTP"], namespaceFilter: ["prod"], hidePlatformComponents: false, hiddenKinds: ["external"], scopeMode: "external", sessionFilters: { peer: "10.0.0.1", application: "https", port: "443" }, pcapFilters: { workload: "prod/api", bpf_filter: "tcp port 443" }, conversationFilters: { from: `prod/${"x".repeat(200)}`, to: "other/api", verdict_group: "blocked" } });
it.each(["network", "new", "import", "pcap"] as const)("preserves exact snapshot and canonical context for %s navigation", destination => {
  const href = networkViewHref("cluster /id", new URLSearchParams("context=dashboard&conversation_page=4&workload=prod/api&inspect_from=prod/ui"), "#evidence", destination, snapshot);
  const url = new URL(href, "https://example.test"); expect(url.pathname).toContain("/clusters/cluster%20%2Fid/network"); expect(url.hash).toBe("#evidence"); expect(url.searchParams.get("context")).toBe("dashboard"); expect(url.searchParams.get("conversation_page")).toBe("4"); expect(networkViewSnapshotFromParams(url.searchParams)).toEqual(snapshot);
});
it.each(["{broken", "null", "{}", JSON.stringify({ ...snapshot, hours: -1 }), JSON.stringify({ ...snapshot, schema_version: 99 })])("rejects malformed or unsupported snapshot URLs", raw => { expect(networkViewSnapshotFromParams(new URLSearchParams({ network_view: raw }))).toBeNull(); });
