import { describe, expect, it } from "vitest";

import type { AdmissionCriterionOption } from "@/api/client";
import {
  ADMISSION_RISK_SHORTCUTS,
  admissionShortcutAvailable,
  admissionShortcutPayload,
} from "./admission-rule-shortcuts";

const catalog = (keys: string[]): AdmissionCriterionOption[] =>
  keys.map((key) => ({ key, label: key, value_type: "none", help: key }));

describe("admission rule shortcuts", () => {
  it("prefills supported criteria and mode for a shortcut", () => {
    const shortcut = ADMISSION_RISK_SHORTCUTS.find((item) => item.id === "mutable-image")!;
    const payload = admissionShortcutPayload(shortcut, catalog(["disallow_latest_tag", "require_digest"]));

    expect(payload).toEqual({
      name: "Require immutable images",
      mode: "enforce",
      rows: [
        { key: "disallow_latest_tag", value: "" },
        { key: "require_digest", value: "" },
      ],
    });
    expect(admissionShortcutAvailable(shortcut, catalog(["disallow_latest_tag", "require_digest"]))).toBe(true);
  });

  it("filters unavailable criteria and reports partial availability", () => {
    const shortcut = ADMISSION_RISK_SHORTCUTS.find((item) => item.id === "privileged-workload")!;

    expect(admissionShortcutPayload(shortcut, catalog(["run_as_root"])).rows).toEqual([
      { key: "run_as_root", value: "" },
    ]);
    expect(admissionShortcutAvailable(shortcut, catalog(["run_as_root"]))).toBe(false);
  });
});
