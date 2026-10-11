import { createBrowserHistory, type RouterHistory } from "@tanstack/react-router";
import { TestRouter } from "@/test/router";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DataRetentionPage } from "./DataRetentionPage";
import { systemConfigApi, type SystemConfigResponse } from "@/api/client";

vi.mock("@/api/client", () => ({ systemConfigApi: { get: vi.fn(), patch: vi.fn() } }));
vi.mock("sonner", () => ({ toast: { success: vi.fn() } }));
let root: Root;
let history: RouterHistory;
let host: HTMLDivElement;
let client: QueryClient;
const config = (revision = 1, flows = 14): SystemConfigResponse => ({ revision, config: { network_flow_retention_days: flows, events_retention_days: 30, scan_job_retention_days: 7 } });

beforeEach(() => {
  vi.clearAllMocks();
  window.history.replaceState({}, "", "/");
  history = createBrowserHistory();
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(["system-config"], config());
  vi.mocked(systemConfigApi.get).mockResolvedValue(config());
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); client.clear(); });
async function render() {
  await act(async () => { root.render(<QueryClientProvider client={client}><TestRouter history={history}><DataRetentionPage /></TestRouter></QueryClientProvider>); });
}
async function change(value: string) {
  const input = host.querySelector<HTMLInputElement>('input[name="network_flow_retention_days"]')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  });
}
async function submit() {
  await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
}

describe("retention form", () => {
  it.each(["-1", "1.5", "3651", ""])("rejects invalid day value %s without sending a request", async (value) => {
    await render();
    await change(value);
    await submit();
    expect(systemConfigApi.patch).not.toHaveBeenCalled();
    expect(host.querySelector('input[aria-invalid="true"]')).not.toBeNull();
  });
  it("saves explicit zero as a hold and clears the dirty warning", async () => {
    vi.mocked(systemConfigApi.patch).mockResolvedValue(config(2, 0));
    await render();
    await change("0");
    await submit();
    expect(systemConfigApi.patch).toHaveBeenCalledWith({ network_flow_retention_days: 0, events_retention_days: 30, scan_job_retention_days: 7 });
    expect(host.querySelector<HTMLInputElement>("input")!.value).toBe("0");
    const event = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(false);
  });
  it("preserves dirty inputs across refresh and allows an explicit reload", async () => {
    await render();
    await change("45");
    await act(async () => { client.setQueryData(["system-config"], config(2, 21)); await new Promise((resolve) => setTimeout(resolve, 10)); });
    expect(host.querySelector<HTMLInputElement>("input")!.value).toBe("45");
    expect(host.textContent).toContain("Your unsaved edits are preserved");
    const event = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(true);
    await act(async () => { Array.from(host.querySelectorAll("button")).find((button) => button.textContent === "Reload current settings")!.click(); });
    expect(host.querySelector<HTMLInputElement>("input")!.value).toBe("21");
  });
  it("preserves edits after a conflict", async () => {
    vi.mocked(systemConfigApi.patch).mockRejectedValue({ response: { status: 409 } });
    vi.mocked(systemConfigApi.get).mockResolvedValue(config(2, 21));
    await render();
    await change("45");
    await submit();
    expect(host.querySelector<HTMLInputElement>("input")!.value).toBe("45");
    expect(host.textContent).toContain("Config changed elsewhere. Your edits are preserved");
  });
});
