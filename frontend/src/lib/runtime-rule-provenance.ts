import type { DLPRule } from "@/api/client";

type OriginTone = "neutral" | "warning" | "info" | "pending" | "accent";

export function runtimeRuleOrigin(rule: Pick<DLPRule, "source" | "cfg_type">): { label: string; tone: OriginTone } {
  const source = (rule.source || "").toLowerCase();
  const cfgType = (rule.cfg_type || "").toLowerCase();
  if (source === "federation" || cfgType === "federated") {
    return { label: "Federated", tone: "accent" };
  }
  if (source === "builtin" || cfgType === "predefined") {
    return { label: "Predefined", tone: "info" };
  }
  if (source === "neuvector") {
    return { label: "NeuVector import", tone: "warning" };
  }
  if (source === "import" || cfgType === "imported") {
    return { label: "Imported", tone: "warning" };
  }
  if (cfgType === "learned") {
    return { label: "Learned", tone: "pending" };
  }
  return { label: "User-created", tone: "neutral" };
}
