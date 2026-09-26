import axios, { AxiosHeaders, type InternalAxiosRequestConfig } from "axios";
import { afterEach, expect, it, vi } from "vitest";

const originalAdapter = axios.defaults.adapter;

afterEach(() => {
  axios.defaults.adapter = originalAdapter;
  vi.resetModules();
});

it("uses persisted job endpoints and requests a bounded history page", async () => {
  vi.resetModules();
  const requests: InternalAxiosRequestConfig[] = [];
  axios.defaults.adapter = async (config) => {
    requests.push(config);
    return { config, status: config.method === "post" ? 202 : 200, statusText: "OK", headers: new AxiosHeaders(), data: config.url?.endsWith("/jobs") && config.method === "get" ? { items: [], next_cursor: null } : { id: "job" } };
  };
  const { supportBundles } = await import("./client");
  await supportBundles.createJob();
  await supportBundles.listJobs("next-page");
  await supportBundles.getJob("job/with slash");
  await supportBundles.downloadJob("job/with slash");
  expect(requests.map((request) => `${request.method} ${request.url}`)).toEqual([
    "post /support/bundle/jobs",
    "get /support/bundle/jobs",
    "get /support/bundle/jobs/job%2Fwith%20slash",
    "get /support/bundle/jobs/job%2Fwith%20slash/download",
  ]);
  expect(requests[1].params).toEqual({ limit: 50, cursor: "next-page" });
});
