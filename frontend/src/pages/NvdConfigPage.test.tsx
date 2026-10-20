import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TestRouter } from "@/test/router";
import { NvdConfigPage } from "./NvdConfigPage";
import { systemConfigApi, type SystemConfigResponse } from "@/api/client";

vi.mock("@/api/client", () => ({ systemConfigApi: { get: vi.fn(), patch: vi.fn() } }));
vi.mock("sonner", () => ({ toast: { success: vi.fn() } }));
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
const config = (revision = 1, mirror = ""): SystemConfigResponse => ({ revision, config: {
  nvd_enabled: false, nvd_api_key: "***REDACTED***", nvd_mirror_url: mirror,
} });
beforeEach(() => {
  vi.clearAllMocks();
  client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["system-config"], config());
  vi.mocked(systemConfigApi.get).mockResolvedValue(config());
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); client.clear(); });
async function render() {
  await act(async () => { root.render(<QueryClientProvider client={client}><TestRouter><NvdConfigPage /></TestRouter></QueryClientProvider>); });
}
async function change(name: string, value: string) {
  const input = host.querySelector<HTMLInputElement>(`input[name="${name}"]`)!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  });
}
async function submit() {
  await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
}

describe("NVD settings form", () => {
  it.each(["not a URL", "file:///etc/passwd", "https://mirror.test/api?token=secret", "https://mirror.test/api#section"])("rejects invalid mirror %s inline", async (value) => {
    await render(); await change("nvd_mirror_url", value); await submit();
    expect(systemConfigApi.patch).not.toHaveBeenCalled();
    expect(host.querySelector('input[name="nvd_mirror_url"][aria-invalid="true"]')).not.toBeNull();
    expect(host.textContent).not.toContain(value);
  });
  it("never puts the stored key into a replacement field and omits a blank key", async () => {
    vi.mocked(systemConfigApi.patch).mockResolvedValue(config(2, "https://mirror.test/api"));
    await render();
    expect(host.querySelector<HTMLInputElement>('input[name="apiKey"]')!.value).toBe("");
    await change("nvd_mirror_url", "https://mirror.test/api"); await submit();
    expect(systemConfigApi.patch).toHaveBeenCalledWith({ nvd_enabled: false, nvd_mirror_url: "https://mirror.test/api" }, 1);
  });
  it("preserves edited key and mirror through a conflict without echoing backend errors", async () => {
    vi.mocked(systemConfigApi.patch).mockRejectedValue({ response: { status: 412, data: { error: "sensitive-backend-value" } } });
    vi.mocked(systemConfigApi.get).mockResolvedValue(config(2, "https://remote.test/api"));
    await render(); await change("apiKey", "replacement-test-value"); await change("nvd_mirror_url", "https://draft.test/api"); await submit();
    expect(systemConfigApi.patch).toHaveBeenCalledOnce();
    expect(host.querySelector<HTMLInputElement>('input[name="apiKey"]')!.value).toBe("replacement-test-value");
    expect(host.querySelector<HTMLInputElement>('input[name="nvd_mirror_url"]')!.value).toBe("https://draft.test/api");
    expect(host.textContent).toContain("Your edits are preserved");
    expect(host.textContent).not.toContain("sensitive-backend-value");
    expect(host.textContent).not.toContain("replacement-test-value");
  });
  it("does not silently save stale edits after a background refresh", async () => {
    await render(); await change("nvd_mirror_url", "https://draft.test/api");
    await act(async () => { client.setQueryData(["system-config"], config(2, "https://remote.test/api")); await new Promise((resolve) => setTimeout(resolve, 10)); });
    await submit();
    expect(systemConfigApi.patch).not.toHaveBeenCalled();
    expect(host.querySelector<HTMLInputElement>('input[name="nvd_mirror_url"]')!.value).toBe("https://draft.test/api");
    await act(async () => { Array.from(host.querySelectorAll("button")).find((button) => button.textContent === "Reload current settings" || button.getAttribute("aria-label") === "Reload current settings" || button.getAttribute("data-export-label") === "Reload current settings")!.click(); });
    expect(host.querySelector<HTMLInputElement>('input[name="nvd_mirror_url"]')!.value).toBe("https://remote.test/api");
  });
  it("does not render a writable default form after a failed initial load", async () => {
    client.clear(); vi.mocked(systemConfigApi.get).mockRejectedValue(new Error("unavailable"));
    await render();
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });
    expect(host.querySelector("form")).toBeNull();
    expect(host.textContent).toContain("Could not load NVD settings");
  });
  it("keeps the key draft mounted when a background refresh fails", async () => {
    await render(); await change("apiKey", "replacement-test-value");
    vi.mocked(systemConfigApi.get).mockRejectedValue(new Error("unavailable"));
    await act(async () => { await client.invalidateQueries({ queryKey: ["system-config"] }); await new Promise((resolve) => setTimeout(resolve, 10)); });
    expect(host.querySelector<HTMLInputElement>('input[name="apiKey"]')!.value).toBe("replacement-test-value");
    expect(host.textContent).not.toContain("replacement-test-value");
  });
});
