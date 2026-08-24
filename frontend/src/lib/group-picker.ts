import type { Group } from "@/api/client";

export type GroupOption =
  | { type: "external"; name: "external" }
  | { type: "group"; group: Group; name: string };

export function filterGroupOptions(groups: Group[], query: string, allowExternal = true): GroupOption[] {
  const q = query.trim().toLowerCase();
  const matches = groups
    .filter((group) => !q || groupSearchText(group).includes(q))
    .sort((a, b) => groupSortScore(a, q) - groupSortScore(b, q) || a.name.localeCompare(b.name))
    .map<GroupOption>((group) => ({ type: "group", group, name: group.name }));

  if (!allowExternal) return matches;
  if (!q || "external".includes(q)) return [{ type: "external", name: "external" }, ...matches];
  return matches;
}

export function groupSearchText(group: Group): string {
  const criteria = (group.criteria ?? []).map((criterion) => `${criterion.key} ${criterion.op} ${criterion.value}`).join(" ");
  return [
    group.name,
    group.comment,
    group.kind,
    group.cfg_type,
    group.policy_mode,
    group.profile_mode,
    criteria,
    ...(group.members ?? []),
  ].filter(Boolean).join(" ").toLowerCase();
}

function groupSortScore(group: Group, query: string) {
  if (!query) return 10;
  const name = group.name.toLowerCase();
  if (name === query) return 0;
  if (name.startsWith(query)) return 1;
  if (name.includes(query)) return 2;
  return 10;
}
