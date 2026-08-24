import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link2, Trash2, UsersRound } from "lucide-react";
import { toast } from "sonner";

import { dpiGroupBindings, groupsApi, type DPISensorKind, type DPIGroupBinding, type Group } from "@/api/client";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { GroupPickerView } from "@/components/GroupPicker";

type DPIGroupBindingsPanelProps = {
  clusterId: string;
  kind: DPISensorKind;
  title: string;
  description: string;
  testId?: string;
};

const EMPTY_GROUPS: Group[] = [];
const EMPTY_BINDINGS: DPIGroupBinding[] = [];

export function DPIGroupBindingsPanel({
  clusterId,
  kind,
  title,
  description,
  testId = "dpi-group-bindings",
}: DPIGroupBindingsPanelProps) {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState("");

  const groupsQ = useQuery({
    queryKey: ["groups", clusterId],
    queryFn: () => groupsApi.list({ cluster_id: clusterId }),
    staleTime: 30_000,
  });
  const bindingsQ = useQuery({
    queryKey: ["dpi-group-bindings"],
    queryFn: () => dpiGroupBindings.list(),
    staleTime: 30_000,
  });

  const groups = groupsQ.data?.groups ?? EMPTY_GROUPS;
  const bindings = bindingsQ.data ?? EMPTY_BINDINGS;
  const bindingsForKind = useMemo(() => bindings.filter((binding) => binding.sensor_kind === kind), [bindings, kind]);
  const groupBindingMap = useMemo(() => bindingsByGroup(bindingsForKind), [bindingsForKind]);
  const boundGroups = useMemo(() => groups.filter((group) => groupBindingMap.has(group.id)), [groupBindingMap, groups]);
  const selectedGroup = groups.find((group) => group.name === selected);
  const selectedAlreadyBound = selectedGroup ? groupBindingMap.has(selectedGroup.id) : false;

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["dpi-group-bindings"] });
    void queryClient.invalidateQueries({ queryKey: ["group-usage"] });
  };

  const bind = useMutation({
    mutationFn: (group: Group) => dpiGroupBindings.bind({ group_id: group.id, sensor_kind: kind }),
    onSuccess: () => {
      setSelected("");
      invalidate();
      toast.success("Group scope updated");
    },
    onError: () => toast.error("Failed to update group scope"),
  });

  const unbind = useMutation({
    mutationFn: async (groupID: string) => {
      const rows = groupBindingMap.get(groupID) ?? [];
      await Promise.all(rows.map((row) => dpiGroupBindings.unbind(row.id)));
    },
    onSuccess: () => {
      invalidate();
      toast.success("Group scope removed");
    },
    onError: () => toast.error("Failed to remove group scope"),
  });

  const loading = groupsQ.isPending || bindingsQ.isPending;
  const error = groupsQ.isError || bindingsQ.isError;

  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card" data-testid={testId}>
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-3 py-2">
        <div>
          <h2 className="text-sm font-semibold">{title}</h2>
          <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>
        </div>
        <span className="rounded bg-muted px-2 py-0.5 text-[11px] uppercase text-muted-foreground">
          {boundGroups.length} group{boundGroups.length === 1 ? "" : "s"}
        </span>
      </header>

      <div className="grid gap-4 p-3 lg:grid-cols-[minmax(260px,360px)_1fr]">
        <form
          className="space-y-3 rounded-md border border-border bg-background p-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (selectedGroup && !selectedAlreadyBound) bind.mutate(selectedGroup);
          }}
        >
          <div>
            <label htmlFor={`${testId}-picker`} className="block text-xs font-medium text-foreground">
              Add group
            </label>
            <div className="mt-1.5">
              <GroupPickerView
                inputId={`${testId}-picker`}
                testId={`${testId}-picker`}
                value={selected}
                onChange={setSelected}
                groups={groups}
                isLoading={groupsQ.isPending}
                isError={groupsQ.isError}
                allowExternal={false}
                placeholder="Search group"
              />
            </div>
          </div>
          {selected && !selectedGroup ? (
            <p className="text-xs text-status-warning">Select an existing group from this cluster.</p>
          ) : selectedAlreadyBound ? (
            <p className="text-xs text-muted-foreground">This group is already scoped.</p>
          ) : null}
          <Button
            type="submit"
            size="sm"
            variant="outline"
            disabled={!selectedGroup || selectedAlreadyBound || bind.isPending}
            data-testid={`${testId}-add`}
          >
            <Link2 className="mr-1 h-3.5 w-3.5" />
            {bind.isPending ? "Adding..." : "Add group"}
          </Button>
        </form>

        <div className="min-w-0">
          {loading ? (
            <p className="px-3 py-4 text-sm text-muted-foreground">Loading group scope...</p>
          ) : error ? (
            <p className="px-3 py-4 text-sm text-status-error">Group scope could not be loaded.</p>
          ) : boundGroups.length === 0 ? (
            <EmptyState title="No scoped groups" hint="Add a group to opt matching workloads into this detector." />
          ) : (
            <div className="divide-y divide-border rounded-md border border-border" data-testid={`${testId}-rows`}>
              {boundGroups.map((group) => (
                <BoundGroupRow
                  key={group.id}
                  group={group}
                  clusterId={clusterId}
                  pending={unbind.isPending}
                  onRemove={() => unbind.mutate(group.id)}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function BoundGroupRow({
  group,
  clusterId,
  pending,
  onRemove,
}: {
  group: Group;
  clusterId: string;
  pending: boolean;
  onRemove: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 px-3 py-2">
      <div className="min-w-0">
        <Link to={`/clusters/${clusterId}/groups/${group.id}`} className="font-mono text-sm text-[color:var(--color-primary)] hover:underline">
          {group.name}
        </Link>
        <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
          <span className="capitalize">{group.kind}</span>
          <span className="inline-flex items-center gap-1">
            <UsersRound className="h-3 w-3" aria-hidden />
            {(group.members ?? []).length}
          </span>
          <span>network {group.policy_mode}</span>
          <span>profile {group.profile_mode}</span>
        </div>
      </div>
      <Button type="button" size="sm" variant="ghost" disabled={pending} onClick={onRemove}>
        <Trash2 className="mr-1 h-3.5 w-3.5" />
        Remove
      </Button>
    </div>
  );
}

function bindingsByGroup(bindings: DPIGroupBinding[]) {
  const out = new Map<string, DPIGroupBinding[]>();
  for (const binding of bindings) {
    const rows = out.get(binding.group_id) ?? [];
    rows.push(binding);
    out.set(binding.group_id, rows);
  }
  return out;
}
