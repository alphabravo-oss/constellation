import { AxiosHeaders } from "axios";
import { afterEach, expect, it } from "vitest";
import { api, routing } from "./client";
const originalAdapter = api.defaults.adapter;
afterEach(() => { api.defaults.adapter = originalAdapter; });
it("sends loaded revisions as strong preconditions, including the first save", async () => {
  const requests: { match: unknown; body: unknown }[] = [];
  api.defaults.adapter = async config => {
    requests.push({ match: config.headers.get("If-Match"), body: JSON.parse(config.data) });
    return { config, status: 200, statusText: "OK", headers: new AxiosHeaders(), data: { status: "ok", revision: 1 } };
  };
  await routing.put("route: {}", 0);
  await routing.put("route: {receiver: ops}", 12);
  await routing.put("legacy");
  expect(requests).toEqual([
    { match: '"0"', body: { yaml: "route: {}" } },
    { match: '"12"', body: { yaml: "route: {receiver: ops}" } },
    { match: undefined, body: { yaml: "legacy" } },
  ]);
});
