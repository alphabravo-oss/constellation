import { describe, expect, it } from "vitest";

import {
  buildNetworkSavedViewSnapshot,
  buildNetworkSavedViewsExport,
  mergeNetworkSavedViews,
  networkActivitySavedViewsStorageKey,
  parseNetworkSavedViewsImport,
  previewNetworkSavedViewsImport,
  normalizeNetworkSavedViewSnapshot,
  suggestNetworkSavedViewName,
  type NetworkSavedView,
} from "./network-saved-views";

describe("network activity saved views", () => {
  it("captures and normalizes the full network filter state", () => {
    const snapshot = buildNetworkSavedViewSnapshot({
      workspaceTab: "threats",
      hours: 24,
      namespace: "  payments  ",
      group: "  payments-prod  ",
      verdict: "block",
      verdictsVisible: { allow: false, alert: true, block: true },
      protocolFilter: new Set(["http", "DNS", ""]),
      namespaceFilter: new Set(["prod", "default", "prod"]),
      hidePlatformComponents: false,
      hiddenKinds: new Set(["unmanaged", "bad-kind", "external"]),
      scopeMode: "external",
      sessionFilters: {
        protocol: "TCP",
        application: "  HTTPS  ",
        port: "443",
        peer: "  3.18.12.8  ",
        workload: "payments/frontend",
        node: "node-a",
      },
      pcapFilters: {
        status: "RUNNING",
        workload: " payments/api ",
        duration_s: 999,
        protocol: "UDP",
        src_ip: " 10.0.0.8 ",
        dst_ip: " 8.8.8.8 ",
        dst_port: "53",
        bpf_filter: " tcp[13] & 2 != 0 ",
        interface: " eth0 ",
        file_count: "4",
        file_size_mb: "25",
      },
    });

    expect(snapshot).toEqual({
      conversation_filters: { from: "", to: "", verdict_group: "" },
      schema_version: 2,
      workspace_tab: "threats",
      hours: 24,
      namespace: "payments",
      group: "payments-prod",
      verdict: "block",
      verdicts_visible: { allow: false, alert: true, block: true },
      protocols: ["DNS", "HTTP"],
      namespaces: ["default", "prod"],
      hide_platform_components: false,
      hidden_kinds: ["unmanaged", "external"],
      scope_mode: "external",
      session_filters: {
        protocol: "tcp",
        application: "HTTPS",
        port: "443",
        peer: "3.18.12.8",
        workload: "payments/frontend",
        node: "node-a",
      },
      pcap_filters: {
        status: "running",
        workload: "payments/api",
        duration_s: 300,
        protocol: "udp",
        src_ip: "10.0.0.8",
        dst_ip: "8.8.8.8",
        dst_port: "53",
        bpf_filter: "tcp[13] & 2 != 0",
        interface: "eth0",
        file_count: "4",
        file_size_mb: "25",
      },
    });
  });

  it("parses import bundles for the current cluster and skips invalid records", () => {
    const text = JSON.stringify({
      views: [
        {
          id: "view-1",
          name: "Blocked payments",
          cluster_id: "old-cluster",
          saved_at: "2026-08-23T00:00:00.000Z",
          filters: {
            workspace_tab: "map",
            hours: 168,
            namespace: "payments",
            verdict: "block",
            verdicts_visible: { allow: false, alert: true, block: true },
            protocols: ["tcp", "TCP"],
            namespaces: ["payments"],
            hide_kube_system: true,
            hidden_kinds: ["unmanaged"],
            scope_mode: "internal",
          },
        },
        { id: "broken", name: "Missing filters" },
        "not-a-view",
      ],
    });

    expect(parseNetworkSavedViewsImport(text, "cluster-1")).toEqual([
      {
        id: "view-1",
        name: "Blocked payments",
        cluster_id: "cluster-1",
        saved_at: "2026-08-23T00:00:00.000Z",
        filters: {
          conversation_filters: { from: "", to: "", verdict_group: "" },
          schema_version: 2,
          workspace_tab: "map",
          hours: 168,
          namespace: "payments",
          group: "",
          verdict: "block",
          verdicts_visible: { allow: false, alert: true, block: true },
          protocols: ["TCP"],
          namespaces: ["payments"],
          hide_platform_components: true,
          hidden_kinds: ["unmanaged"],
          scope_mode: "internal",
          session_filters: {
            protocol: "",
            application: "",
            port: "",
            peer: "",
            workload: "",
            node: "",
          },
          pcap_filters: {
            status: "",
            workload: "",
            duration_s: 30,
            protocol: "",
            src_ip: "",
            dst_ip: "",
            dst_port: "",
            bpf_filter: "",
            interface: "",
            file_count: "",
            file_size_mb: "",
          },
        },
      },
    ]);
  });

  it("round-trips exact directed conversation filters in a saved view", () => {
    const view = makeView("pair", "Exact blocked pair");
    view.filters.conversation_filters = { from: `prod/${"a".repeat(180)}`, to: "other/api", verdict_group: "blocked" };
    const bundle = buildNetworkSavedViewsExport("cluster-1", [view], "2026-10-12T00:00:00Z");
    expect(parseNetworkSavedViewsImport(JSON.stringify(bundle), "cluster-1")[0].filters.conversation_filters).toEqual(view.filters.conversation_filters);
  });

  it("merges imports without reusing an existing id", () => {
    const existing = makeView("view-1", "Existing");
    const imported = [makeView("view-1", "Imported"), makeView("view-2", "Second")];

    expect(mergeNetworkSavedViews([existing], imported, () => "view-new").map((view) => view.id)).toEqual([
      "view-1",
      "view-new",
      "view-2",
    ]);
  });

  it("builds cluster-scoped keys, export bundles, and operator-readable names", () => {
    const view = makeView("view-1", "Blocked");
    expect(networkActivitySavedViewsStorageKey("cluster-1", "user-1")).toBe("constellation:network-activity:saved-views:cluster-1:user-1");
    expect(buildNetworkSavedViewsExport("cluster-1", [view], "2026-08-23T00:00:00.000Z")).toMatchObject({
      schema_version: 2,
      kind: "constellation.networkActivity.savedViews",
      cluster_id: "cluster-1",
      exported_at: "2026-08-23T00:00:00.000Z",
      views: [view],
    });
    expect(suggestNetworkSavedViewName(view.filters)).toBe("Map 24h all namespaces all verdicts");
  });
});

it.each([
  { hours: 0 }, { workspace_tab: "unknown" }, { schema_version: 99 }, { protocols: {} }, { verdicts_visible: { allow: "false" } },
  { session_filters: { port: "invalid" } }, { pcap_filters: { dst_port: "70000" } }, { conversation_filters: { from: "prod/api", to: "prod/ui", verdict_group: "invented" } },
])("rejects a malformed snapshot instead of silently broadening filters: %j", invalid => {
  expect(normalizeNetworkSavedViewSnapshot({ ...makeView("id", "Named").filters, ...invalid })).toBeNull();
});
it("previews rejected records and a different source cluster before explicit rebinding", () => {
  const preview = previewNetworkSavedViewsImport(JSON.stringify({ ...buildNetworkSavedViewsExport("old-cluster", [makeView("id", "Named")]), views: [makeView("id", "Named"), { id: "bad", name: "Broken", filters: {} }] }), "new-cluster");
  expect(preview.rejected).toBe(1); expect(preview.sourceCluster).toBe("old-cluster"); expect(preview.views[0].cluster_id).toBe("new-cluster");
});
it.each(["{}", "{broken", JSON.stringify({ schema_version: 3, views: [] }), JSON.stringify({ kind: "other", views: [] })])("rejects invalid import envelopes with a meaningful error", text => { expect(() => previewNetworkSavedViewsImport(text, "cluster")).toThrow(); });
it("preserves long exact workload filters instead of truncating them", () => { const view = makeView("id", "Named"); const workload = `prod/${"api".repeat(100)}`; view.filters.session_filters.workload = workload; view.filters.pcap_filters.workload = workload; expect(normalizeNetworkSavedViewSnapshot(view.filters)?.session_filters.workload).toBe(workload); expect(parseNetworkSavedViewsImport(JSON.stringify([view]), "cluster")[0].filters.pcap_filters.workload).toBe(workload); });

function makeView(id: string, name: string): NetworkSavedView {
  return {
    id,
    name,
    cluster_id: "cluster-1",
    saved_at: "2026-08-23T00:00:00.000Z",
    filters: buildNetworkSavedViewSnapshot({
      workspaceTab: "map",
      hours: 24,
      namespace: "",
      group: "",
      verdict: "",
      verdictsVisible: { allow: true, alert: true, block: true },
      protocolFilter: [],
      namespaceFilter: [],
      hidePlatformComponents: true,
      hiddenKinds: ["unmanaged"],
      scopeMode: "both",
      sessionFilters: {},
      pcapFilters: {},
    }),
  };
}

it("preserves optional capture ledger search/namespace/node while keeping legacy snapshots unchanged", () => { const view = makeView("id", "Named"); const legacy = normalizeNetworkSavedViewSnapshot(view.filters)!; expect(legacy.pcap_filters).not.toHaveProperty("q"); const rich = { ...view.filters, pcap_filters: { ...view.filters.pcap_filters, q: " needle%_literal ", namespace: "custom-install", node: "node-a" } }; const normalized = normalizeNetworkSavedViewSnapshot(rich)!; expect(normalized.pcap_filters).toMatchObject({ q: "needle%_literal", namespace: "custom-install", node: "node-a" }); expect(parseNetworkSavedViewsImport(JSON.stringify([{ ...view, filters: rich }]), "cluster")[0].filters.pcap_filters).toMatchObject({ q: "needle%_literal", namespace: "custom-install", node: "node-a" }); expect(normalizeNetworkSavedViewSnapshot({ ...rich, pcap_filters: { ...rich.pcap_filters, node: 123 } })).toBeNull(); });
