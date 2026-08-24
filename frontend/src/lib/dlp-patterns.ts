import type { DLPPatternSpec, DLPRule } from "@/api/client";

type EditablePattern = DLPRule["patterns"][number];

export function patternLines(patterns: DLPRule["patterns"] | undefined) {
  return (patterns ?? [])
    .map((pattern) => patternValue(pattern))
    .map((pattern) => pattern.trim())
    .filter(Boolean)
    .join("\n");
}

export function patternsFromText(text: string, original?: DLPRule["patterns"]) {
  const preserved = specsByPattern(original ?? []);
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line): string | DLPPatternSpec => {
      const specs = preserved.get(line);
      const spec = specs?.shift();
      if (!spec) return line;
      return copySpec(spec, line);
    });
}

function patternValue(pattern: EditablePattern) {
  return typeof pattern === "string" ? pattern : pattern.pattern;
}

function specsByPattern(patterns: DLPRule["patterns"]) {
  const out = new Map<string, DLPPatternSpec[]>();
  for (const pattern of patterns) {
    if (typeof pattern === "string") continue;
    const key = pattern.pattern.trim();
    if (!key) continue;
    const specs = out.get(key) ?? [];
    specs.push(pattern);
    out.set(key, specs);
  }
  return out;
}

function copySpec(spec: DLPPatternSpec, pattern: string): DLPPatternSpec {
  const out: DLPPatternSpec = { pattern };
  if (spec.op?.trim()) out.op = spec.op;
  if (spec.context?.trim()) out.context = spec.context;
  return out;
}
