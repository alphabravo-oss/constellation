import { describe, expect, it } from "vitest";

import { runtimeRuleOrigin } from "./runtime-rule-provenance";

describe("runtimeRuleOrigin", () => {
  it("maps runtime DLP/WAF provenance to operator-facing labels", () => {
    expect(runtimeRuleOrigin({ source: "neuvector", cfg_type: "imported" })).toEqual({ label: "NeuVector import", tone: "warning" });
    expect(runtimeRuleOrigin({ source: "user", cfg_type: "federated" })).toEqual({ label: "Federated", tone: "accent" });
    expect(runtimeRuleOrigin({ source: "builtin", cfg_type: "predefined" })).toEqual({ label: "Predefined", tone: "info" });
    expect(runtimeRuleOrigin({ source: "user", cfg_type: "user_created" })).toEqual({ label: "User-created", tone: "neutral" });
  });
});
