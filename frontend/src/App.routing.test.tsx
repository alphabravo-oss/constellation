import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, Outlet, RouterProvider } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAppRouter } from "./app-router";

const identity = vi.hoisted(() => ({ me: { user_id: "test" } as { user_id: string } | null, loading: false }));
vi.mock("@/contexts/AuthContext", () => ({ useAuth: () => identity }));
vi.mock("./components/AppShell", () => ({ AppShell: () => <Outlet /> }));
vi.mock("./pages/ClusterRouter", () => ({ ClusterRouter: () => <Outlet /> }));
vi.mock("./pages/LoginPage", () => ({ LoginPage: () => <div>Sign in</div> }));
vi.mock("./pages/ClustersLandingPage", () => ({ ClustersLandingPage: () => <div>Clusters</div> }));
vi.mock("./components/SettingsShell", () => ({ SettingsShell: () => <Outlet /> }));
vi.mock("./api/client", () => ({ clusters: { list: async () => ({ clusters: [{ id: "cluster-1", name: "Cluster", last_seen: "2026-10-11T00:00:00Z" }] }) } }));

beforeEach(() => vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true));
let root: Root | undefined;
let host: HTMLDivElement;
let client: QueryClient;
afterEach(() => { act(() => root?.unmount()); host?.remove(); client?.clear(); identity.me = { user_id: "test" }; identity.loading = false; vi.unstubAllGlobals(); });

async function render(url: string) {
  const router = createAppRouter(createMemoryHistory({ initialEntries: [url] }));
  host = document.createElement("div"); document.body.appendChild(host);
  root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root!.render(<QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>));
  return router;
}

describe("route contract", () => {
  it.each([
    ["/clusters/cluster-1/findings/finding-1", "/_authenticated/clusters/$id/findings/$fid", { id: "cluster-1", fid: "finding-1" }],
    ["/clusters/cluster-1/runtime-dlp/new", "/_authenticated/clusters/$id/runtime-dlp/new", { id: "cluster-1" }],
    ["/settings/identity", "/_authenticated/settings/identity", {}],
    ["/hosts", "/_authenticated/hosts/$", {}],
    ["/hosts/node-a", "/_authenticated/hosts/$", { _splat: "node-a" }],
  ])("matches saved deep link %s", (url, id, params) => {
    const router = createAppRouter(createMemoryHistory({ initialEntries: [url as string] }));
    const match = router.matchRoutes(url as string).at(-1)!;
    expect(match.routeId).toBe(id);
    expect(match.params).toMatchObject(params);
  });
  it("keeps login aliases, repeated query values, and fragments", async () => {
    const router = await render("/login?returnTo=%2Fclusters%2Fcluster-1%2Fdashboard&tag=a&tag=b#signin");
    await vi.waitFor(() => expect(router.state.location.pathname).toBe("/auth/login"));
    expect(router.state.location.search).toMatchObject({ returnTo: "/clusters/cluster-1/dashboard", tag: ["a", "b"] });
    expect(router.state.location.hash).toBe("signin");
  });
  it("protects deep links and preserves the full login return URL", async () => {
    identity.me = null;
    const router = await render("/clusters/cluster-1/findings?severity=critical#evidence");
    await vi.waitFor(() => expect(router.state.location.pathname).toBe("/auth/login"));
    expect(router.state.location.search.returnTo).toBe("/clusters/cluster-1/findings?severity=critical#evidence");
    expect(host.textContent).toBe("Sign in");
  });
  it("does not redirect or render protected content while identity is loading", async () => {
    identity.loading = true;
    const router = await render("/settings/access");
    expect(router.state.location.pathname).toBe("/settings/access");
    expect(host.textContent).toContain("Loading");
    expect(host.textContent).not.toContain("Settings");
  });
  it("preserves push, replace, back and forward semantics", async () => {
    const router = await render("/clusters");
    await act(async () => { await router.navigate({ to: "/settings/access", search: { tab: "first" } }); });
    await act(async () => { await router.navigate({ to: "/settings/access", search: { tab: "second" }, replace: true }); });
    expect(router.history.length).toBe(2);
    await act(async () => { router.history.back(); });
    expect(router.state.location.pathname).toBe("/clusters");
    await act(async () => { router.history.forward(); });
    expect(router.state.location.search.tab).toBe("second");
  });
});
