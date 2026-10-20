import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { auth } from "@/api/client";
import { LoginPage } from "./LoginPage";

vi.mock("@/api/client", () => ({ auth: { providers: vi.fn(), oidcStart: vi.fn() } }));
vi.mock("@/contexts/AuthContext", () => ({ useAuth: () => ({ login: vi.fn() }) }));
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => vi.fn() }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams()] }));

let root: Root;
let host: HTMLDivElement;
let client: QueryClient;

afterEach(() => {
  act(() => root?.unmount());
  client?.clear();
  host?.remove();
  vi.resetAllMocks();
});

async function renderLogin() {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><LoginPage /></QueryClientProvider>));
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 10)); });
}

it.each(["disabled", "unavailable", "loading"])("keeps password login available without SSO when providers are %s", async (state) => {
  if (state === "disabled") vi.mocked(auth.providers).mockResolvedValue({ oidc: false, saml: false });
  if (state === "unavailable") vi.mocked(auth.providers).mockRejectedValue(new Error("unavailable"));
  if (state === "loading") vi.mocked(auth.providers).mockReturnValue(new Promise(() => {}));
  await renderLogin();
  expect(host.textContent).not.toMatch(/SSO|continue with password/);
  expect(host.textContent).toContain("Enter your credentials to continue.");
  expect(host.querySelector('button[type="submit"]')).not.toBeNull();
});

it("shows and starts configured OIDC", async () => {
  vi.mocked(auth.providers).mockResolvedValue({ oidc: true, saml: false });
  vi.mocked(auth.oidcStart).mockReturnValue(new Promise(() => {}));
  await renderLogin();
  const button = [...host.querySelectorAll("button")].find((item) => item.textContent === "Continue with SSO" || item.getAttribute("aria-label") === "Continue with SSO");
  expect(button).toBeDefined();
  expect(host.textContent).toContain("continue with password");
  await act(async () => button!.click());
  expect(auth.oidcStart).toHaveBeenCalledOnce();
});

it.each([false, true])("links configured SAML with OIDC=%s", async (oidc) => {
  vi.mocked(auth.providers).mockResolvedValue({ oidc, saml: true });
  await renderLogin();
  const link = host.querySelector('a[href="/api/v1/auth/saml/login"]');
  expect(link?.textContent).toBe(oidc ? "Continue with SAML" : "Continue with SSO");
  if (oidc) expect(host.textContent).toContain("Continue with OIDC");
});
