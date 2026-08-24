import { describe, expect, it } from "vitest";

import { patternLines, patternsFromText } from "@/lib/dlp-patterns";
import type { DLPRule } from "@/api/client";

describe("DLP pattern editing helpers", () => {
  it("renders legacy and structured patterns as editable lines", () => {
    const patterns: DLPRule["patterns"] = [
      "AKIA[0-9A-Z]{16}",
      { pattern: "/login", op: "regex", context: "uri" },
    ];

    expect(patternLines(patterns)).toBe("AKIA[0-9A-Z]{16}\n/login");
  });

  it("preserves op and context for unchanged imported structured patterns", () => {
    const original: DLPRule["patterns"] = [
      { pattern: "/admin", op: "regex", context: "uri" },
      "secret",
    ];

    expect(patternsFromText("/admin\nsecret", original)).toEqual([
      { pattern: "/admin", op: "regex", context: "uri" },
      "secret",
    ]);
  });

  it("drops metadata when the operator edits a structured pattern", () => {
    const original: DLPRule["patterns"] = [
      { pattern: "/admin", op: "regex", context: "uri" },
    ];

    expect(patternsFromText("/admin/v2", original)).toEqual(["/admin/v2"]);
  });
});
