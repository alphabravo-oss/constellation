import * as yaml from "js-yaml";

export interface RoutingRule {
  receiver: string;
  match: Record<string, string>;
  continue: boolean;
  matchers?: string[];
  raw: Record<string, unknown>;
}
export interface RoutingModel {
  defaultReceiver: string;
  routes: RoutingRule[];
  rootRaw: Record<string, unknown>;
  docRaw: Record<string, unknown>;
}
export type RoutingSnapshot = { yaml: string; revision: number; updated_at: string };
export type ParsedRouting = { ok: true; model: RoutingModel } | { ok: false; reason: string };
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);

/** Validate syntax without flattening, rewriting, or discarding nested trees. */
export function routingYamlError(text: string): string | null {
  if (!text.trim()) return null;
  try {
    const document = yaml.load(text);
    if (!object(document) || !object(document.route)) return "Routing YAML must contain a route object.";
    return null;
  } catch { return "Routing YAML is invalid. Correct the syntax before saving."; }
}

/** Only flat child routes are editable individually; other documents stay raw. */
export function parseRouting(text: string): ParsedRouting {
  const empty = { defaultReceiver: "", routes: [], rootRaw: {}, docRaw: {} };
  if (!text.trim()) return { ok: true, model: empty };
  const error = routingYamlError(text);
  if (error) return { ok: false, reason: error };
  const document = yaml.load(text) as Record<string, unknown>;
  const root = document.route as Record<string, unknown>;
  if (root.receiver !== undefined && typeof root.receiver !== "string") return { ok: false, reason: "The default receiver requires the complete YAML editor." };
  if (root.routes !== undefined && !Array.isArray(root.routes)) return { ok: false, reason: "This route structure requires the complete YAML editor." };
  const routes: RoutingRule[] = [];
  for (const child of (root.routes as unknown[]) ?? []) {
    if (!object(child) || child.routes !== undefined) return { ok: false, reason: "Nested routing trees are preserved in the complete YAML editor." };
    const { receiver, match, matchers, continue: continuing, ...raw } = child;
    if (receiver !== undefined && typeof receiver !== "string" || match !== undefined && !object(match) || matchers !== undefined && (!Array.isArray(matchers) || !matchers.every((value) => typeof value === "string")) || continuing !== undefined && typeof continuing !== "boolean") return { ok: false, reason: "This route shape requires the complete YAML editor." };
    const labels: Record<string, string> = {};
    for (const [key, value] of Object.entries((match as Record<string, unknown>) ?? {})) {
      if (typeof value !== "string") return { ok: false, reason: "Non-string match labels are preserved in the complete YAML editor." };
      labels[key] = value;
    }
    routes.push({ receiver: typeof receiver === "string" ? receiver : "", match: labels, matchers: matchers as string[] | undefined, continue: continuing === true, raw });
  }
  const { receiver: _receiver, routes: _routes, ...rootRaw } = root;
  const { route: _route, ...docRaw } = document;
  return { ok: true, model: { defaultReceiver: typeof root.receiver === "string" ? root.receiver : "", routes, rootRaw, docRaw } };
}

export function serializeRouting(model: RoutingModel): string {
  const route: Record<string, unknown> = { ...model.rootRaw };
  if (model.defaultReceiver) route.receiver = model.defaultReceiver;
  if (model.routes.length) route.routes = model.routes.map((rule) => ({
    ...rule.raw,
    ...(rule.receiver ? { receiver: rule.receiver } : {}),
    ...(Object.keys(rule.match).length ? { match: rule.match } : {}),
    ...(rule.matchers?.length ? { matchers: rule.matchers } : {}),
    ...(rule.continue ? { continue: true } : {}),
  }));
  return yaml.dump({ ...model.docRaw, route }, { noRefs: true, lineWidth: 120, sortKeys: false });
}

export function routeIndex(value: string | undefined): number | null {
  if (!value || !/^\d+$/.test(value)) return null;
  const index = Number(value);
  return Number.isSafeInteger(index) ? index : null;
}
export function routingRevision(value: string | null): number | null {
  if (value === null || !/^\d+$/.test(value)) return null;
  const revision = Number(value);
  return Number.isSafeInteger(revision) ? revision : null;
}
export function isRevisionConflict(error: unknown): boolean { return (error as { response?: { status?: number } } | null)?.response?.status === 412; }
export function validRoutingSnapshot(value: RoutingSnapshot | undefined): value is RoutingSnapshot { return !!value && typeof value.yaml === "string" && Number.isSafeInteger(value.revision) && value.revision >= 0; }
