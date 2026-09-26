import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { backupsApi, type BackupManifestDTO } from "@/api/client";
import { BackupRestorePage } from "./BackupRestorePage";

vi.mock("@/api/client", () => ({ backupsApi: { verify: vi.fn(), restore: vi.fn() } }));

const manifest: BackupManifestDTO = {
  verified: true, format_version: "constellation-orgbackup/v1", org_id: "org", org_name: "Test",
  generated_at: "2026-09-26T00:00:00Z", tables: [], root_hash: "hash", signer_identity: "key:trusted",
};
let root: Root | undefined;
let host: HTMLDivElement;
let queryClient: QueryClient;

afterEach(() => {
  act(() => root?.unmount());
  host?.remove();
  queryClient?.clear();
  vi.resetAllMocks();
});

function render() {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  queryClient = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  act(() => root!.render(
    <QueryClientProvider client={queryClient}><MemoryRouter><BackupRestorePage /></MemoryRouter></QueryClientProvider>,
  ));
}

function applyButton() {
  return Array.from(host.querySelectorAll("button")).find((button) => button.textContent === "Apply restore")!;
}

async function selectFile(name: string) {
  const input = host.querySelector<HTMLInputElement>('input[type="file"]')!;
  const file = new File(["archive"], name);
  Object.defineProperty(input, "files", { configurable: true, value: [file] });
  await act(async () => input.dispatchEvent(new Event("change", { bubbles: true })));
}

async function flush() {
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 10)); });
}

it("requires successful validation and has no client trust override", async () => {
  vi.mocked(backupsApi.verify).mockRejectedValue(new Error("digest mismatch"));
  render();
  expect(applyButton().disabled).toBe(true);
  expect(host.textContent).not.toContain("Allow unverified");
  await selectFile("bad.tar.gz");
  await flush();
  expect(applyButton().disabled).toBe(true);
  expect(backupsApi.restore).not.toHaveBeenCalled();
});

it("shows cryptographic identity only when verified", async () => {
  vi.mocked(backupsApi.verify).mockResolvedValue({ ...manifest, verified: false, signer_identity: "untrusted-claim" });
  render();
  await selectFile("unsigned.tar.gz");
  await flush();
  expect(host.textContent).toContain("Signature unverified");
  expect(host.textContent).not.toContain("untrusted-claim");
  expect(applyButton().disabled).toBe(false);
});

it("does not apply stale validation to a newly selected file", async () => {
  let resolveFirst!: (value: BackupManifestDTO) => void;
  let rejectSecond!: (reason: Error) => void;
  vi.mocked(backupsApi.verify)
    .mockImplementationOnce(() => new Promise((resolve) => { resolveFirst = resolve; }))
    .mockImplementationOnce(() => new Promise((_resolve, reject) => { rejectSecond = reject; }));
  render();
  await selectFile("first.tar.gz");
  await selectFile("second.tar.gz");
  await act(async () => resolveFirst(manifest));
  await flush();
  expect(applyButton().disabled).toBe(true);
  expect(host.textContent).not.toContain("key:trusted");
  await act(async () => rejectSecond(new Error("invalid second archive")));
  await flush();
  expect(applyButton().disabled).toBe(true);
});
