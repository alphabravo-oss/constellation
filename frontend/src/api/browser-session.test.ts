import axios, { AxiosError, AxiosHeaders, type InternalAxiosRequestConfig } from "axios";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const originalAdapter = axios.defaults.adapter;

function result(config: InternalAxiosRequestConfig, status: number, data: unknown = {}) {
  const response = { config, status, data, statusText: String(status), headers: new AxiosHeaders() };
  if (status >= 400) throw new AxiosError("request rejected", "ERR_BAD_RESPONSE", config, undefined, response);
  return response;
}

beforeEach(() => {
  vi.resetModules();
  localStorage.clear();
  window.history.replaceState({}, "", "/auth/login");
  vi.stubGlobal("navigator", {});
});

afterEach(() => {
  axios.defaults.adapter = originalAdapter;
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("browser sessions", () => {
  it("removes legacy storage credentials and never sends them", async () => {
    localStorage.setItem("constellation.token", "old-exposed-token");
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => result(config, 200, { expires_at: "later" }));
    axios.defaults.adapter = adapter;
    const { auth } = await import("./client");
    await auth.login("admin@example.test", "password");
    expect(localStorage.getItem("constellation.token")).toBeNull();
    const request = adapter.mock.calls[0][0];
    expect(request.withCredentials).toBe(true);
    expect(request.headers.get("X-Constellation-Client")).toBe("browser");
    expect(request.headers.get("Authorization")).toBeUndefined();
  });

  it("coalesces simultaneous expired requests into one rotation and retries each once", async () => {
    let refreshed = false;
    let rotations = 0;
    axios.defaults.adapter = async (config) => {
      if (config.url === "/auth/refresh") {
        rotations += 1;
        await new Promise((resolve) => setTimeout(resolve, 5));
        refreshed = true;
        return result(config, 200);
      }
      return result(config, refreshed ? 200 : 401, { ok: true });
    };
    const { api } = await import("./client");
    const responses = await Promise.all(Array.from({ length: 12 }, () => api.get("/findings")));
    expect(responses.every((response) => response.status === 200)).toBe(true);
    expect(rotations).toBe(1);
  });

  it("does not refresh invalid login credentials or explicitly supplied bearer credentials", async () => {
    const requests: string[] = [];
    axios.defaults.adapter = async (config) => {
      requests.push(config.url ?? "");
      return result(config, 401);
    };
    const { auth, api } = await import("./client");
    await expect(auth.login("admin@example.test", "wrong")).rejects.toBeInstanceOf(AxiosError);
    await expect(api.get("/findings", { headers: { Authorization: "Bearer invalid" } })).rejects.toBeInstanceOf(AxiosError);
    expect(requests).toEqual(["/auth/login", "/findings"]);
  });

  it("stops after one retry when the rotated access session is also rejected", async () => {
    const requests: string[] = [];
    axios.defaults.adapter = async (config) => {
      requests.push(config.url ?? "");
      return result(config, config.url === "/auth/refresh" ? 200 : 401);
    };
    const { api } = await import("./client");
    await expect(api.get("/auth/me")).rejects.toBeInstanceOf(AxiosError);
    expect(requests).toEqual(["/auth/me", "/auth/refresh", "/auth/me"]);
  });

  it("checks shared cookies under a cross-tab lock before rotating again", async () => {
    const lock = vi.fn(async (_name: string, callback: () => Promise<void>) => callback());
    vi.stubGlobal("navigator", { locks: { request: lock } });
    const requests: string[] = [];
    axios.defaults.adapter = async (config) => {
      requests.push(config.url ?? "");
      return result(config, requests.length === 1 ? 401 : 200);
    };
    const { api } = await import("./client");
    await api.get("/findings");
    expect(lock).toHaveBeenCalledOnce();
    expect(requests).toEqual(["/findings", "/auth/me", "/findings"]);
  });
});
