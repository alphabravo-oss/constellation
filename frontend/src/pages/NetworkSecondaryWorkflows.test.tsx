import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import {
  network,
  policies,
  type NetworkPolicyLifecycle,
  type NetworkPolicyActionResponse,
  type RuntimeThreat,
} from "@/api/client";
import { downloadCsv } from "@/lib/csv";
vi.mock("@/lib/csv", () => ({ downloadCsv: vi.fn() }));
import { NetworkActionFormPage } from "./NetworkActionFormPage";
import { NetworkDpiSettingsFormPage } from "./NetworkDpiSettingsFormPage";
import { NetworkRulesWorkspaceTab, NetworkThreatsWorkspaceTab, WeakTLSStatus } from "./NetworkMapPage";
const route = vi.hoisted(() => ({
  action: "apply-policy",
  search:
    "workload=team%2Fapi&hours=168&back=tab%3Drules%26hours%3D168%26workload%3Dteam%252Fapi",
  clusterId: "cluster" as string | undefined,
  cluster: { id: "cluster" } as { id: string } | undefined,
  isLoading: false,
  error: null as Error | null,
  navigate: vi.fn(),
}));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => route }));
vi.mock("@/lib/route-search", () => ({
  useRouteSearchParams: () => [new URLSearchParams(route.search), vi.fn()],
}));
vi.mock("@tanstack/react-router", () => ({
  useParams: () => ({ action: route.action }),
  useNavigate: () => route.navigate,
  useLocation: ({
    select,
  }: {
    select: (l: { searchStr: string }) => unknown;
  }) => select({ searchStr: "?tab=rules&hours=168&workload=team%2Fapi" }),
  useRouter: () => ({}),
}));
vi.mock("@/api/client", () => ({
  network: {
    lifecycle: vi.fn(),
    policyAction: vi.fn(),
    rollbackPolicy: vi.fn(),
    map: vi.fn(),
    enforcement: { create: vi.fn() },
  },
  policies: { dpiThreatSettings: vi.fn(), updateDpiThreatSettings: vi.fn() },
  quarantine: { create: vi.fn() },
}));
const candidate = (): NetworkPolicyLifecycle => ({
  id: "policy",
  cluster_id: "cluster",
  namespace: "team",
  workload: "team/api",
  current_mode: "discover",
  target_mode: "monitor",
  approval_status: "approved",
  candidate_hash: "hash",
  approved_candidate_hash: "hash",
  candidate_stale: false,
  rollback_available: true,
  rollback_ref: "prior-bundle",
  reason: "Observed policy",
  auto_applied: false,
  evaluated_at: "2026-10-12T00:00:00Z",
  summary: {
    total_flows: 2,
    unique_peers: 1,
    unique_port_protocol: 1,
    out_of_policy_alerts: 0,
    new_tuples_last_24h: 0,
    first_observation: "",
    last_observation: "",
  },
  tuple_preview: [],
  preview: { engine: "cilium", yaml: "current manifest", refs: {} },
  diff: {
    summary: "Current candidate diff",
    added: [],
    removed: [],
    changed: [],
  },
  audit_trail: [],
});
const response = (p = candidate()) => ({
  items: [p],
  summary: {
    selected_cluster_id: "cluster",
    total: 1,
    ready: 1,
    discover: 1,
    monitor: 0,
    protect: 0,
    rollback_ready: 1,
    pending_approval: 0,
  },
});
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
beforeEach(() => {
  (
    globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }
  ).IS_REACT_ACT_ENVIRONMENT = true;
  Object.assign(route, {
    action: "apply-policy",
    search:
      "workload=team%2Fapi&hours=168&back=tab%3Drules%26hours%3D168%26workload%3Dteam%252Fapi",
    clusterId: "cluster",
    cluster: { id: "cluster" },
    isLoading: false,
    error: null,
  });
  vi.mocked(network.lifecycle).mockResolvedValue(response());
  vi.mocked(policies.dpiThreatSettings).mockResolvedValue({
    cluster_id: "cluster",
    weak_tls_enabled: true,
  });
  vi.mocked(policies.updateDpiThreatSettings).mockImplementation(
    async (body) => ({
      cluster_id: "cluster",
      weak_tls_enabled: body.weak_tls_enabled,
    }),
  );
  vi.mocked(network.policyAction).mockImplementation(
    async (_w, action, body) =>
      ({
        policy: {
          ...candidate(),
          current_mode: action === "demote" ? "discover" : "monitor",
        },
        action,
        persists: true,
        applies_live: false,
        idempotency_key: body?.idempotency_key,
        next_mode: action === "demote" ? "discover" : "monitor",
        rollback_refs: {},
      }) as NetworkPolicyActionResponse,
  );
  vi.mocked(network.rollbackPolicy).mockImplementation(
    async (_w, body) =>
      ({
        policy: { ...candidate(), current_mode: "discover" },
        action: "rollback",
        persists: true,
        applies_live: false,
        idempotency_key: body?.idempotency_key,
        next_mode: "discover",
        rollback_refs: {},
      }) as NetworkPolicyActionResponse,
  );
});
afterEach(() => {
  act(() => root?.unmount());
  client?.clear();
  host?.remove();
  vi.resetAllMocks();
});
async function render(node: ReactNode = <NetworkActionFormPage />) {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () =>
    root.render(
      <QueryClientProvider client={client}>{node}</QueryClientProvider>,
    ),
  );
}
async function settled(check: () => void) {
  await vi.waitFor(async () => {
    await act(async () => {});
    check();
  });
}
async function editor() {
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
}
const button = (name: string) =>
  [...host.querySelectorAll("button")].find(
    (b) => b.textContent?.trim() === name,
  )!;
async function reason(text = "Reviewed action") {
  await act(async () => {
    const field = host.querySelector<HTMLTextAreaElement>(
      "#network-action-reason",
    )!;
    Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )!.set!.call(field, text);
    field.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
async function submit() {
  await act(async () =>
    host
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })),
  );
}
const writes = () => [
  network.policyAction,
  network.rollbackPolicy,
  policies.updateDpiThreatSettings,
];
it.each(["loading", "foreign", "error"])(
  "blocks all secondary reads and writes for %s cluster",
  async (state) => {
    if (state === "loading") route.isLoading = true;
    if (state === "foreign") route.cluster = { id: "other" };
    if (state === "error") route.error = new Error("unavailable");
    await render(
      <>
        <NetworkActionFormPage />
        <NetworkDpiSettingsFormPage />
      </>,
    );
    await settled(() =>
      expect(host.textContent).toContain(
        state === "error" ? "Could not resolve" : "Resolving cluster",
      ),
    );
    expect(network.lifecycle).not.toHaveBeenCalled();
    expect(policies.dpiThreatSettings).not.toHaveBeenCalled();
    for (const fn of writes()) expect(fn).not.toHaveBeenCalled();
  },
);
it.each(["apply-policy", "demote-policy", "rollback-policy"])(
  "records %s for exact scope and source window without claiming enforcement",
  async (action) => {
    route.action = action;
    if (action === "demote-policy")
      vi.mocked(network.lifecycle).mockResolvedValue(
        response({ ...candidate(), current_mode: "monitor" }),
      );
    await render();
    await editor();
    await reason();
    await submit();
    const fn =
      action === "rollback-policy"
        ? network.rollbackPolicy
        : network.policyAction;
    await settled(() => expect(fn).toHaveBeenCalledOnce());
    expect(network.lifecycle).toHaveBeenCalledWith(
      expect.objectContaining({ cluster_id: "cluster", hours: 168 }),
    );
    const args = vi.mocked(fn).mock.calls[0];
    expect(args[0]).toBe("team/api");
    expect(args.at(-1)).toEqual({ cluster_id: "cluster" });
    await settled(() =>
      expect(host.textContent).toContain("does not confirm enforcement"),
    );
    expect(
      [...host.querySelectorAll<HTMLAnchorElement>("a")].every(
        (a) =>
          a.getAttribute("href") ===
          "/clusters/cluster/network?tab=rules&hours=168&workload=team%2Fapi",
      ),
    ).toBe(true);
  },
);
it("retains reason on failed refetch and failed policy save", async () => {
  await render();
  await editor();
  await reason("Keep reason");
  vi.mocked(network.lifecycle).mockRejectedValue(new Error("offline"));
  await act(async () => {
    await client.invalidateQueries({ queryKey: ["network-lifecycle-action"] });
  });
  await settled(() => expect(button("Apply policy").disabled).toBe(true));
  expect(host.querySelector<HTMLTextAreaElement>("textarea")?.value).toBe(
    "Keep reason",
  );
  vi.mocked(network.lifecycle).mockResolvedValue(response());
  await act(async () => button("Retry").click());
  await settled(() => expect(button("Apply policy").disabled).toBe(false));
  vi.mocked(network.policyAction).mockRejectedValue(new Error("write failed"));
  await submit();
  await settled(() => expect(host.textContent).toContain("write failed"));
  expect(host.querySelector<HTMLTextAreaElement>("textarea")?.value).toBe(
    "Keep reason",
  );
});
it("retains reason when selected lifecycle disappears and never substitutes a sibling", async () => {
  await render();
  await editor();
  await reason("Keep target");
  vi.mocked(network.lifecycle).mockResolvedValue(
    response({ ...candidate(), workload: "team/sibling" }),
  );
  await act(async () => {
    await client.invalidateQueries({ queryKey: ["network-lifecycle-action"] });
  });
  await settled(() => expect(button("Apply policy").disabled).toBe(true));
  expect(host.querySelector<HTMLTextAreaElement>("textarea")?.value).toBe(
    "Keep target",
  );
  await submit();
  expect(network.policyAction).not.toHaveBeenCalled();
});
it.each(["registry", "invalidated", "fetching", "revision"])(
  "rechecks %s cache before lifecycle mutation",
  async (condition) => {
    await render();
    await editor();
    await reason();
    await act(async () => {
      const q = client
        .getQueryCache()
        .find({ queryKey: ["network-lifecycle-action"], exact: false })!;
      if (condition === "registry")
        client.setQueryData(["clusters"], { clusters: [{ id: "other" }] });
      if (condition === "invalidated") q.setState({ isInvalidated: true });
      if (condition === "fetching") q.setState({ fetchStatus: "fetching" });
      if (condition === "revision")
        client.setQueryData(
          q.queryKey,
          response({ ...candidate(), candidate_hash: "changed" }),
        );
      host
        .querySelector("form")!
        .dispatchEvent(
          new Event("submit", { bubbles: true, cancelable: true }),
        );
    });
    await settled(() =>
      expect(host.querySelector('[data-testid="error-state"]')).not.toBeNull(),
    );
    expect(network.policyAction).not.toHaveBeenCalled();
  },
);
it("rejects changed candidate during fresh preflight without writing", async () => {
  await render();
  await editor();
  await reason();
  vi.mocked(network.lifecycle).mockResolvedValue(
    response({ ...candidate(), candidate_hash: "changed" }),
  );
  await submit();
  await settled(() =>
    expect(host.textContent).toContain("changed before submission"),
  );
  expect(network.policyAction).not.toHaveBeenCalled();
  expect(host.querySelector<HTMLTextAreaElement>("textarea")?.value).toBe(
    "Reviewed action",
  );
});
it("blocks duplicate actions on an unconfirmed policy response", async () => {
  vi.mocked(network.policyAction).mockResolvedValue({
    action: "apply",
    persists: true,
    policy: { ...candidate(), cluster_id: "other" },
  } as NetworkPolicyActionResponse);
  await render();
  await editor();
  await reason();
  await submit();
  await settled(() => expect(host.textContent).toContain("did not confirm"));
  expect(button("Apply policy").disabled).toBe(true);
  await submit();
  expect(network.policyAction).toHaveBeenCalledTimes(1);
});
it("requires explicit evidence-removal acknowledgment and sends reviewed DPI precondition", async () => {
  await render(<NetworkDpiSettingsFormPage />);
  await editor();
  expect(button("Save").disabled).toBe(true);
  await act(async () =>
    host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click(),
  );
  expect(host.textContent).toContain("removes stored weak-TLS threat evidence");
  expect(button("Save").disabled).toBe(true);
  await act(async () =>
    host
      .querySelectorAll<HTMLInputElement>('input[type="checkbox"]')[1]
      .click(),
  );
  await submit();
  await settled(() =>
    expect(policies.updateDpiThreatSettings).toHaveBeenCalledWith(
      { weak_tls_enabled: false, expected_weak_tls_enabled: true },
      { cluster_id: "cluster" },
    ),
  );
  await settled(() =>
    expect(host.textContent).toContain(
      "Agent adoption and enforcement have not been confirmed",
    ),
  );
});
it("keeps a DPI draft after refetch failure and blocks unknown settings", async () => {
  await render(<NetworkDpiSettingsFormPage />);
  await editor();
  await act(async () =>
    host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click(),
  );
  vi.mocked(policies.dpiThreatSettings).mockRejectedValue(
    new Error("settings offline"),
  );
  await act(async () => {
    await client.invalidateQueries({ queryKey: ["dpi-threat-settings"] });
  });
  await settled(() => expect(host.textContent).toContain("draft is preserved"));
  expect(
    host.querySelector<HTMLInputElement>('input[type="checkbox"]')?.checked,
  ).toBe(false);
  expect(button("Save").disabled).toBe(true);
  expect(policies.updateDpiThreatSettings).not.toHaveBeenCalled();
});
it("requires review if configured DPI state changes during preflight", async () => {
  await render(<NetworkDpiSettingsFormPage />);
  await editor();
  await act(async () => {
    host
      .querySelectorAll<HTMLInputElement>('input[type="checkbox"]')[0]
      .click();
  });
  await act(async () =>
    host
      .querySelectorAll<HTMLInputElement>('input[type="checkbox"]')[1]
      .click(),
  );
  vi.mocked(policies.dpiThreatSettings).mockResolvedValue({
    cluster_id: "cluster",
    weak_tls_enabled: false,
  });
  await submit();
  await settled(() =>
    expect(host.textContent).toContain("configured setting changed"),
  );
  expect(policies.updateDpiThreatSettings).not.toHaveBeenCalled();
});
it("blocks repeated DPI writes after uncertain confirmation", async () => {
  vi.mocked(policies.dpiThreatSettings).mockResolvedValue({
    cluster_id: "cluster",
    weak_tls_enabled: false,
  });
  vi.mocked(policies.updateDpiThreatSettings).mockResolvedValue({
    cluster_id: "other",
    weak_tls_enabled: true,
  });
  await render(<NetworkDpiSettingsFormPage />);
  await editor();
  await act(async () =>
    host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click(),
  );
  await submit();
  await settled(() => expect(host.textContent).toContain("did not confirm"));
  expect(button("Save").disabled).toBe(true);
  await submit();
  expect(policies.updateDpiThreatSettings).toHaveBeenCalledTimes(1);
});
it("shows unknown weak-TLS configuration instead of an off toggle or adoption promise", async () => {
  await render(
    <WeakTLSStatus
      configured={undefined}
      unavailable
      loading={false}
      href="/review"
      testId="weak"
    />,
  );
  expect(host.textContent).toContain("unavailable");
  expect(host.querySelector("input")).toBeNull();
  expect(host.textContent).not.toContain("configured off");
  expect(host.textContent).not.toContain("15s");
});
it("keeps an unavailable URL-selected policy explicit without selecting first inventory row", async () => {
  await render(
    <NetworkRulesWorkspaceTab
      items={[candidate()]}
      selectedWorkload="team/missing"
      onSelect={vi.fn()}
      available
      loading={false}
      refreshing={false}
      onRetry={vi.fn()}
    />,
  );
  expect(host.textContent).toContain("selected workload policy is unavailable");
  expect(host.querySelector('a[href*="actions/"]')).toBeNull();
  expect(
    host.querySelector('[data-testid="network-lifecycle-table"]'),
  ).not.toBeNull();
});
it("retains the current YAML preview when the manifest dictionary is empty", async () => {
  const p = candidate();
  p.preview = {
    ...p.preview,
    manifests: {},
    yaml: "legacy YAML still supplied",
  };
  await render(
    <NetworkRulesWorkspaceTab
      items={[p]}
      selectedWorkload={p.workload}
      onSelect={vi.fn()}
      available
      loading={false}
      refreshing={false}
      onRetry={vi.fn()}
    />,
  );
  expect(
    host.querySelector('[data-testid="network-policy-preview"]')?.textContent,
  ).toContain("legacy YAML still supplied");
});

it("includes policy installation roles in returned lifecycle evidence exports", async () => {
 await render(<NetworkRulesWorkspaceTab items={[{ ...candidate(), platform_role: "core" }]} selectedWorkload={null} onSelect={vi.fn()} available loading={false} refreshing={false} onRetry={vi.fn()} />);
 await act(async () => [...host.querySelectorAll<HTMLButtonElement>("button")].find(button => button.textContent === "Export returned policy evidence")!.click());
 const [,headers,rows]=vi.mocked(downloadCsv).mock.calls.at(-1)!;
 expect(rows[0][headers.indexOf("platform_role")]).toBe("core");
});
it("exports the loaded threat page and real workload role without action controls", async () => {
 const threat = { id: "threat", workload_id: "operations/houston", platform_role: "core", threat_id: 2022, severity: 8, action: 2, at: "2026-10-12T00:00:00Z" } as RuntimeThreat;
 await render(<NetworkThreatsWorkspaceTab threats={[threat]} total={301} page={2} onPage={vi.fn()} weakTLS={true} settingsUnavailable={false} settingsLoading={false} settingsHref={undefined} onPivot={vi.fn()} />);
 expect(host.textContent).toContain("Metrics cover all matching threats.");
 await act(async () => [...host.querySelectorAll<HTMLButtonElement>("button")].find(button => button.textContent === "Export this page CSV")!.click());
 const [,headers,rows]=vi.mocked(downloadCsv).mock.calls.at(-1)!;
 expect(rows).toHaveLength(1); expect(rows[0][headers.indexOf("platform_role")]).toBe("core"); expect(rows[0][headers.indexOf("Workload")]).toBe("operations/houston"); expect(headers).not.toContain("Actions"); expect(headers).not.toContain(""); expect(rows.flat()).not.toContain("Pivot");
});
