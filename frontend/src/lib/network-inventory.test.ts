import { expect, it } from "vitest";
import type {
  NetworkConversations,
  NetworkSessionsResponse,
  RuntimeThreatPage,
} from "@/api/client";
import {
  conversationsValid,
  sessionsValid,
  threatsValid,
  type NetworkInventoryRequest,
} from "./network-inventory";
const at = "2026-10-12T12:00:00.123456Z";
const request: NetworkInventoryRequest = {
  cluster_id: "cluster",
  limit: 100,
  offset: 500,
  sort: "bytes",
  order: "desc",
  hide_platform: false,
};
const metadata = () => ({
  cluster_id: "cluster",
  limit: 100,
  offset: 500,
  sort: "bytes",
  order: "desc" as const,
  total: 501,
  has_more: false,
});
const conversation = (): NetworkConversations => ({
  ...metadata(),
  source: "rollups",
  source_complete: true,
  summary_scope: "matching_rollups",
  window_hours: 24,
  filters: {
    hours: 24,
    namespace: "",
    verdict: "",
    group: "",
    port: 0,
    peer: "",
    application: "",
    from: "",
    to: "",
    verdict_group: "",
    hide_platform: false,
  },
  summary: {
    total: 501,
    bytes: 900001,
    packets: 400000,
    edges: 700,
    blocked: 90,
    violating: 20,
    nodes: 503,
  },
  conversations: [
    {
      row_id: JSON.stringify(["Default/API", "external/example.com"]),
      from: "Default/API",
      to: "external/example.com",
      bytes: 12345,
      packets: 2345,
      edges: 2,
      last_seen: at,
      apps: ["dns", "http", "https", "ssl", "mysql"],
    },
  ],
  nodes: ["Default/API", "external/example.com"],
  node_kinds: { "Default/API": "workload", "external/example.com": "external" },
  edges: [],
});
const session = (): NetworkSessionsResponse => ({
  ...metadata(),
  filters: {
    cluster_id: "cluster",
    protocol: null,
    port: null,
    application: "",
    peer: "",
    workload: "",
    node: "",
    group: "",
    hours: 0,
    q: "",
    hide_platform: false,
  },
  summary: {
    total: 501,
    bytes: 900001,
    client_bytes: 700001,
    server_bytes: 200000,
    packets: 400000,
    threats: 40,
  },
  sessions: [
    {
      row_id: JSON.stringify(["cluster", "node", 12]),
      cluster_id: "cluster",
      id: 12,
      node: "node",
      platform_role: "",
      application: "HTTPS",
      ip_proto: "TCP",
      client_ip: "10.0.0.2",
      client_port: 32000,
      server_ip: "10.0.0.3",
      server_port: 443,
      client_state: "established",
      server_state: "established",
      client_bytes: 12345,
      server_bytes: 23456,
      client_pkts: 100,
      server_pkts: 99,
      age: 50,
      idle: 2,
      severity: 0,
      ingress: false,
      updated_at: at,
    },
  ],
});
const threat = (): RuntimeThreatPage => ({
  ...metadata(),
  sort: "at",
  window_hours: 24,
  filters: {
    severity_min: 0,
    workload_id: "",
    category: "",
    group: "",
    port: 0,
    peer: "",
    application: "",
    namespace: "",
    node: "",
    hide_platform: false,
    q: "",
  },
  summary: {
    total: 501,
    critical: 20,
    blocked: 100,
    ips: 201,
    dlp: 200,
    waf: 100,
    workloads: 170,
  },
  threats: [
    {
      id: "threat",
      org_id: "org",
      cluster_id: "cluster",
      platform_role: "",
      severity: 8,
      action: 2,
      threat_id: 1001,
      pkt_ingress: true,
      sess_ingress: false,
      reported_at: at,
      at,
    },
  ],
});
const threatRequest = { ...request, sort: "at" };
it("accepts full-cohort metadata beyond page500 with omitted unknown conversation roles", () => {
  expect(conversationsValid(conversation(), request)).toBe(true);
  expect(sessionsValid(session(), request)).toBe(true);
  expect(threatsValid(threat(), threatRequest)).toBe(true);
  expect(
    conversationsValid(
      {
        ...conversation(),
        conversations: [
          {
            ...conversation().conversations[0],
            from_platform_role: "",
            to_platform_role: "",
          },
        ],
      },
      request,
    ),
  ).toBe(true);
});
it("accepts exact normalized filters and numeric protocol aliases", () => {
  const data = conversation();
  Object.assign(data.filters!, {
    from: "Default/API",
    namespace: "Default",
    peer: "peer",
    application: "https",
    verdict: "deny",
  });
  expect(
    conversationsValid(data, {
      ...request,
      from: " Default/API ",
      namespace: " Default ",
      peer: " PEER ",
      application: " HTTPS ",
      verdict: " DENY ",
    }),
  ).toBe(true);
  for (const protocol of ["TCP", "6", "proto-6"]) {
    const data = session();
    Object.assign(data.filters!, {
      protocol: 6,
      port: 443,
      workload: "default/api",
      node: "node",
      application: "https",
      peer: "peer",
      q: "needle",
      hours: 1,
    });
    expect(
      sessionsValid(data, {
        ...request,
        protocol,
        port: 443,
        workload: "Default/API",
        node: "NODE",
        application: "HTTPS",
        peer: "PEER",
        q: "NEEDLE",
        hours: 1,
      }),
    ).toBe(true);
  }
  const dataThreat = threat();
  Object.assign(dataThreat.filters!, {
    workload_id: "Default/API",
    namespace: "Default",
    node: "NODE",
    peer: "peer",
    application: "https",
  });
  expect(
    threatsValid(dataThreat, {
      ...threatRequest,
      workload_id: " Default/API ",
      namespace: "Default",
      node: "NODE",
      peer: "PEER",
      application: "HTTPS",
    }),
  ).toBe(true);
});
it.each(["from", "to", "namespace", "group"])(
  "rejects changed case in exact conversation %s",
  (key) => {
    const data = conversation();
    data.filters![key] = "Mixed/Case";
    expect(conversationsValid(data, { ...request, [key]: "mixed/case" })).toBe(
      false,
    );
  },
);
it.each(["workload_id", "namespace", "node", "group"])(
  "rejects changed case in exact threat %s",
  (key) => {
    const data = threat();
    data.filters![key] = "Mixed/Case";
    expect(threatsValid(data, { ...threatRequest, [key]: "mixed/case" })).toBe(
      false,
    );
  },
);
it("rejects unexpected active default filters and unsupported predicates", () => {
  for (const key of ["from", "namespace", "verdict", "group"]) {
    const data = conversation();
    data.filters![key] = "unexpected";
    expect(conversationsValid(data, request)).toBe(false);
  }
  for (const key of ["protocol", "port", "workload", "node", "group"]) {
    const data = session();
    data.filters![key] =
      key === "protocol" ? 6 : key === "port" ? 443 : "unexpected";
    expect(sessionsValid(data, request)).toBe(false);
  }
  for (const key of ["workload_id", "namespace", "node", "category", "group"]) {
    const data = threat();
    data.filters![key] = "unexpected";
    expect(threatsValid(data, threatRequest)).toBe(false);
  }
  const data = conversation();
  data.filters!.unknown = "active";
  expect(conversationsValid(data, request)).toBe(false);
  expect(
    conversationsValid(conversation(), { ...request, unsupported: "active" }),
  ).toBe(false);
});
it.each(["conversations", "sessions", "threats"] as const)(
  "rejects wrong scope/page/sort/summary and hidden core in %s",
  (kind) => {
    const data =
      kind === "conversations"
        ? conversation()
        : kind === "sessions"
          ? session()
          : threat();
    const validate = (value: unknown, r = request) =>
      kind === "conversations"
        ? conversationsValid(value as NetworkConversations, r)
        : kind === "sessions"
          ? sessionsValid(value as NetworkSessionsResponse, r)
          : threatsValid(value as RuntimeThreatPage, {
              ...r,
              sort: r.sort === "bytes" ? "at" : r.sort,
            });
    for (const patch of [
      { cluster_id: "foreign" },
      { offset: 400 },
      { limit: 99 },
      { has_more: true },
      { summary: { ...data.summary, total: 500 } },
      { summary: { ...data.summary, bytes: -1, critical: -1 } },
      { sort: "wrong" },
      { order: "asc" },
    ])
      expect(validate({ ...data, ...patch })).toBe(false);
    const core = structuredClone(data);
    core.filters!.hide_platform = true;
    if (kind === "conversations")
      (core as NetworkConversations).conversations[0].to_platform_role = "core";
    else if (kind === "sessions")
      (core as NetworkSessionsResponse).sessions[0].platform_role = "core";
    else (core as RuntimeThreatPage).threats[0].platform_role = "core";
    expect(validate(core, { ...request, hide_platform: true })).toBe(false);
  },
);
it.each([
  ["bytes", null],
  ["packets", null],
  ["edges", null],
  ["packets", -1],
  ["edges", 1.2],
  ["bytes", Number.NaN],
  ["apps", "https"],
  ["apps", [{}]],
  ["last_seen", "invalid"],
  ["last_seen", null],
  ["from_platform_role", {}],
  ["from_platform_role", null],
  ["verdict", {}],
])("rejects malformed conversation %s=%j before rendering", (key, value) => {
  const data = conversation();
  Object.assign(data.conversations[0], { [key]: value });
  expect(conversationsValid(data, request)).toBe(false);
});
it.each([
  ["client_bytes", null],
  ["server_bytes", "12"],
  ["client_pkts", -1],
  ["client_port", 65536],
  ["node", {}],
  ["client_state", {}],
  ["application", null],
  ["workload_id", {}],
  ["updated_at", "invalid"],
  ["ingress", null],
  ["age", 1.2],
])(
  "rejects malformed session %s=%j before rendering or mutation",
  (key, value) => {
    const data = session();
    Object.assign(data.sessions[0], { [key]: value });
    expect(sessionsValid(data, request)).toBe(false);
  },
);
it.each([
  ["msg", {}],
  ["node", {}],
  ["threat_name", {}],
  ["workload_id", []],
  ["reported_at", "invalid"],
  ["severity", null],
  ["action", 1.2],
  ["threat_id", null],
  ["pkt_ingress", null],
  ["src_port", 65536],
])("rejects malformed threat %s=%j before rendering", (key, value) => {
  const data = threat();
  Object.assign(data.threats[0], { [key]: value });
  expect(threatsValid(data, threatRequest)).toBe(false);
});
it("rejects null rows and duplicate complete identities", () => {
  for (const rows of [[null], [{}, {}]])
    expect(
      conversationsValid(
        {
          ...conversation(),
          conversations: rows,
        } as unknown as NetworkConversations,
        request,
      ),
    ).toBe(false);
  const data = conversation();
  data.total = 502;
  data.summary!.total = 502;
  data.conversations.push({ ...data.conversations[0] });
  expect(conversationsValid(data, request)).toBe(false);
  const dataSession = session();
  dataSession.sessions[0].row_id = JSON.stringify([
    "cluster",
    "another-node",
    12,
  ]);
  expect(sessionsValid(dataSession, request)).toBe(false);
});
it("rejects live snapshots and wrong windows despite otherwise valid metadata", () => {
  for (const patch of [
    { source: "live" },
    { source_complete: false },
    { summary_scope: "live_snapshot" },
    { window_hours: 1 },
  ])
    expect(
      conversationsValid(
        { ...conversation(), ...patch } as NetworkConversations,
        request,
      ),
    ).toBe(false);
  const data = threat();
  data.window_hours = 1;
  expect(threatsValid(data, threatRequest)).toBe(false);
});

it("accepts numeric threat application IDs as the backend's canonical text echo", () => {
  const data = threat();
  data.filters!.application = "777";
  expect(threatsValid(data, { ...threatRequest, application: 777 })).toBe(true);
  data.filters!.application = "778";
  expect(threatsValid(data, { ...threatRequest, application: 777 })).toBe(
    false,
  );
});
