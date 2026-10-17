// @ts-expect-error - js-yaml ships no type declarations in this project.
import yaml from "js-yaml";
import { expect, it } from "vitest";
import { parseRouting, routeIndex, routingRevision, routingYamlError, serializeRouting } from "./integration-routing";
const original = `global:\n  resolve_timeout: 5m\nroute:\n  receiver: external-default\n  group_by: [namespace]\n  group_wait: 30s\n  routes:\n    - receiver: external-sink\n      match: {severity: critical}\n      matchers: ['team=~"security|platform"']\n      continue: true\n      group_interval: 5m\n      mute_time_intervals: [overnight]\ninhibit_rules:\n  - source_match: {severity: critical}\nreceivers:\n  - name: external-sink\n    webhook_configs:\n      - url: https://external.example.test\n`;
it("preserves all unmanaged YAML fields, matchers and external receiver names when editing one route", () => {
  const parsed = parseRouting(original); expect(parsed.ok).toBe(true); if (!parsed.ok) throw new Error(parsed.reason);
  const edited = serializeRouting({ ...parsed.model, routes: parsed.model.routes.map((rule) => ({ ...rule, match: { ...rule.match, owner: "oncall" } })) });
  const expected = yaml.load(original); expected.route.routes[0].match.owner = "oncall"; expect(yaml.load(edited)).toEqual(expected);
});
it("preserves nested routing through the raw editor and refuses lossy flat editing", () => {
  const nested = "route:\n  receiver: default\n  routes:\n    - receiver: outer\n      routes:\n        - receiver: inner\n          matchers: ['severity=critical']\n";
  expect(routingYamlError(nested)).toBeNull(); expect(parseRouting(nested)).toMatchObject({ ok: false, reason: expect.stringContaining("Nested") });
});
it.each(["[not-a-document]", "route: [invalid]", "route: {receiver: sink\n"])("rejects invalid YAML shapes and syntax: %s", (value) => { expect(routingYamlError(value)).not.toBeNull(); expect(parseRouting(value).ok).toBe(false); });
it("does not coerce advanced match labels or matcher values into a lossy visual model", () => { expect(parseRouting("route:\n  routes:\n    - match: {port: 80}\n").ok).toBe(false); expect(parseRouting("route:\n  routes:\n    - matchers: [12]\n").ok).toBe(false); });
it("supports an unset document without inventing a receiver or dropping future advanced data", () => { expect(parseRouting("")).toMatchObject({ ok: true, model: { defaultReceiver: "", routes: [] } }); expect(routingYamlError("")).toBeNull(); });
it("binds numeric route indexes and revisions without coercing invalid deep links", () => { expect(routeIndex("0")).toBe(0); expect(routingRevision("0")).toBe(0); for (const invalid of ["-1", "1.5", "NaN", "1e2", "99999999999999999999"]) { expect(routeIndex(invalid)).toBeNull(); expect(routingRevision(invalid)).toBeNull(); } expect(routeIndex(undefined)).toBeNull(); expect(routingRevision(null)).toBeNull(); });
