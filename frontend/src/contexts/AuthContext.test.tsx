import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { auth } from "@/api/client";
import { AuthProvider, useAuth } from "./AuthContext";

vi.mock("@/api/client", () => ({ auth: { me: vi.fn(), login: vi.fn(), logout: vi.fn() } }));

let root: Root | undefined;
let host: HTMLDivElement;
let client: QueryClient;
let state: ReturnType<typeof useAuth>;

function Probe() {
  state = useAuth();
  return <div>{state.me?.email ?? "anonymous"}</div>;
}

afterEach(() => {
  act(() => root?.unmount());
  client?.clear();
  host?.remove();
  vi.resetAllMocks();
  vi.unstubAllGlobals();
});

it("clears identity-scoped query data when logging in or out without reading browser credentials", async () => {
  const postMessage = vi.fn();
  const Channel = vi.fn(function () { return { postMessage, close: vi.fn(), onmessage: null }; });
  vi.stubGlobal("BroadcastChannel", Channel);
  vi.mocked(auth.me).mockResolvedValue({ user_id: "first", org_id: "first-org", email: "first@test", roles: ["GlobalAdmin"] });
  vi.mocked(auth.login).mockResolvedValue({ expires_at: "later" });
  vi.mocked(auth.logout).mockResolvedValue({ status: "ok" });
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  client = new QueryClient();
  await act(async () => root!.render(<QueryClientProvider client={client}><AuthProvider><Probe /></AuthProvider></QueryClientProvider>));
  expect(host.textContent).toBe("first@test");
  client.setQueryData(["findings"], { private: "first-org data" });
  vi.mocked(auth.me).mockResolvedValue({ user_id: "second", org_id: "second-org", email: "second@test", roles: ["Auditor"] });
  await act(async () => state.login("second@test", "password"));
  expect(host.textContent).toBe("second@test");
  expect(client.getQueryData(["findings"])).toBeUndefined();
  client.setQueryData(["findings"], { private: "second-org data" });
  await act(async () => state.logout());
  expect(host.textContent).toBe("anonymous");
  expect(client.getQueryData(["findings"])).toBeUndefined();
  expect(Channel).toHaveBeenCalledTimes(1);
  expect(postMessage).toHaveBeenCalledTimes(2);
});
