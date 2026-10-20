import { AxiosHeaders } from "axios";
import { afterEach, expect, it } from "vitest";
import { api, dpiGroupBindings } from "./client";
const originalAdapter = api.defaults.adapter;
afterEach(() => { api.defaults.adapter = originalAdapter; });
it("treats the API's null binding collection as a loaded empty scope", async () => {
  api.defaults.adapter = async config => ({ config, status: 200, statusText: "OK", headers: new AxiosHeaders(), data: { bindings: null } });
  expect(await dpiGroupBindings.list()).toEqual([]);
});
it("retains existing scope bindings", async () => {
  const bindings = [{ id: "binding", group_id: "group", sensor_kind: "waf" }];
  api.defaults.adapter = async config => ({ config, status: 200, statusText: "OK", headers: new AxiosHeaders(), data: { bindings } });
  expect(await dpiGroupBindings.list()).toEqual(bindings);
});
