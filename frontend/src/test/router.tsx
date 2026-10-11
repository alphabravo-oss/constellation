import { useEffect, useState, type ReactNode } from "react";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider, type RouterHistory } from "@tanstack/react-router";
import { parseURLSearch, stringifyURLSearch } from "@/lib/route-search";

export function TestRouter({ children, initialEntries = ["/"], path = "$", next, history }: {
  children: ReactNode;
  history?: RouterHistory;
  initialEntries?: string[];
  path?: string;
  next?: { path: string; element: ReactNode };
}) {
  const [router] = useState(() => {
    const root = createRootRoute({ component: Outlet });
    const page = createRoute({ getParentRoute: () => root, path, component: () => children });
    const routes = [page];
    if (next) routes.push(createRoute({ getParentRoute: () => root, path: next.path, component: () => next.element }));
    return createRouter({ routeTree: root.addChildren(routes), history: history ?? createMemoryHistory({ initialEntries }), parseSearch: parseURLSearch, stringifySearch: stringifyURLSearch });
  });
  useEffect(() => () => router.history.destroy(), [router]);
  return <RouterProvider router={router} />;
}
