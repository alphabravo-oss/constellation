import { act, lazy, Suspense } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider } from "@tanstack/react-router";
import { afterEach, expect, it, vi } from "vitest";
import { RouteErrorPage } from "./RouteErrorPage";

let host: HTMLDivElement;
let root: Root;
afterEach(() => { act(() => root?.unmount()); host?.remove(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

async function rejectedRoute(error: Error) {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  const page = lazy(() => Promise.reject(error));
  const Page = page;
  const parent = createRootRoute({ component: Outlet });
  const child = createRoute({ getParentRoute: () => parent, path: "/clusters/$id/findings", component: () => <Suspense fallback="Loading"><Page /></Suspense> });
  const router = createRouter({ routeTree: parent.addChildren([child]), history: createMemoryHistory({ initialEntries: ["/clusters/cluster-a/findings?severity=critical#evidence"] }), defaultErrorComponent: RouteErrorPage });
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
  await act(async () => { root.render(<RouterProvider router={router} />); });
  await vi.waitFor(() => expect(host.textContent).toContain("This page could not be loaded"));
  return router;
}

it("recovers a rejected lazy route with an explicit reload while preserving the requested URL", async () => {
  const router = await rejectedRoute(new TypeError("Failed to fetch dynamically imported module: /static/PrivatePage-old.js"));
  expect(host.textContent).toContain("console update or interrupted connection");
  expect(host.textContent).not.toContain("PrivatePage-old.js");
  expect(document.activeElement).toBe(host.querySelector("h1"));
  expect(router.state.location.href).toBe("/clusters/cluster-a/findings?severity=critical#evidence");
  const reload = vi.fn();
  vi.stubGlobal("location", { reload });
  expect(reload).not.toHaveBeenCalled();
  act(() => host.querySelector<HTMLButtonElement>("button")!.click());
  expect(reload).toHaveBeenCalledOnce();
  expect(host.querySelector("a")?.getAttribute("href")).toBe("/clusters");
});

it("gives unexpected render errors a recovery path without exposing error details", async () => {
  await rejectedRoute(new Error("Unexpected internal payload: private-detail"));
  expect(host.textContent).toContain("Something prevented this page from opening");
  expect(host.textContent).not.toContain("private-detail");
  expect(host.querySelector("button")?.textContent).toBe("Reload page");
});
