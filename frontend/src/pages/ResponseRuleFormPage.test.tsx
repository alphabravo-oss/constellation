import { act } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createRoot, type Root } from "react-dom/client";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { groupsApi, responseRulesV2, type Group, type ResponseRuleV2 } from "@/api/client";
import { ResponseRuleFormPage } from "./ResponseRuleFormPage";

vi.mock("@/hooks/useCluster", () => ({
  useCluster: () => ({ clusterId: "cluster-1", isLoading: false }),
}));

const groups: Group[] = [
  {
    id: "group-api",
    name: "prod/api",
    kind: "learned",
    comment: "",
    criteria: [],
    members: ["prod/api-0"],
    learned_from: "",
    cfg_type: "user_created",
    policy_mode: "monitor",
    profile_mode: "discover",
  },
];

const rule: ResponseRuleV2 = {
  id: "rule-1",
  name: "Notify on runtime events",
  description: "",
  enabled: true,
  priority: 1,
  event_type: "runtime",
  conditions: [{ type: "name", value: ".*" }],
  actions: [{ kind: "notify", target: "slack" }],
  workload_match: {},
};

let root: Root | undefined;
let host: HTMLDivElement | undefined;
let queryClient: QueryClient | undefined;

afterEach(() => {
  act(() => root?.unmount());
  queryClient?.clear();
  host?.remove();
  root = undefined;
  host = undefined;
  queryClient = undefined;
  vi.restoreAllMocks();
});

describe("ResponseRuleFormPage group selector", () => {
  it("selects a cluster group through GroupPicker and saves its name", async () => {
    vi.spyOn(groupsApi, "list").mockResolvedValue({ groups });
    vi.spyOn(responseRulesV2, "list").mockResolvedValue({ rules: [rule] });
    vi.spyOn(responseRulesV2, "options").mockResolvedValue({
      event_types: [],
      condition_types: [],
      action_kinds: [],
      receivers: [],
      webhooks: [],
      response_rule_options: {},
    });
    const update = vi.spyOn(responseRulesV2, "update").mockResolvedValue({ id: rule.id });

    host = document.createElement("div");
    document.body.appendChild(host);
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    root = createRoot(host);
    await act(async () => {
      root?.render(
        <QueryClientProvider client={queryClient!}>
          <MemoryRouter initialEntries={["/clusters/cluster-1/response-rules/rule-1"]}>
            <Routes>
              <Route path="/clusters/:id/response-rules/:ruleId" element={<ResponseRuleFormPage />} />
              <Route path="/clusters/:id/response-rules" element={<div>Rules list</div>} />
            </Routes>
          </MemoryRouter>
        </QueryClientProvider>,
      );
    });

    await vi.waitFor(() => expect(host?.querySelector("[data-testid='response-rule-group-picker'] input")).not.toBeNull());
    const picker = host!.querySelector<HTMLInputElement>("[data-testid='response-rule-group-picker'] input")!;
    expect(groupsApi.list).toHaveBeenCalledWith({ cluster_id: "cluster-1" });

    await act(async () => picker.focus());
    await vi.waitFor(() => expect(host?.querySelector("[role='option']")?.textContent).toContain("prod/api"));
    await act(async () => host?.querySelector<HTMLButtonElement>("[role='option']")?.click());
    expect(picker.value).toBe("prod/api");

    const save = Array.from(host!.querySelectorAll<HTMLButtonElement>("button")).find((button) => button.textContent?.trim() === "Save");
    await act(async () => save?.click());
    await vi.waitFor(() => expect(update).toHaveBeenCalled());
    expect(update.mock.calls[0][1].workload_match).toEqual({ group: "prod/api" });
  });
});
