import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, ArrowUpDown } from "lucide-react";
import { toast } from "sonner";

import { CrudPage } from "@/components/CrudPage";
import { ImportExportButtons } from "@/components/ImportExportButtons";
import { groupsApi, type Group, type GroupMode } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";

const GROUP_MODES: GroupMode[] = ["discover", "monitor", "protect"];

export function GroupsPage() {
  const { clusterId } = useCluster();
  const qc = useQueryClient();

  const headerActions = (
    <>
      <GroupModeBulkActions clusterId={clusterId} onChanged={() => {
        void qc.invalidateQueries({ queryKey: ["groups", clusterId] });
        void qc.invalidateQueries({ queryKey: ["dashboard", clusterId] });
      }} />
      <ImportExportButtons
        filename="constellation-groups.yaml"
        label="groups"
        exportYaml={() => groupsApi.exportYaml({ cluster_id: clusterId })}
        importYaml={(text) => groupsApi.importYaml(text, { cluster_id: clusterId })}
        onImported={() => void qc.invalidateQueries({ queryKey: ["groups", clusterId] })}
      />
    </>
  );

  return (
    <CrudPage<Group, Omit<Group, "id" | "created_at" | "updated_at">>
      title="Groups"
      description="Workload taxonomy: Learned (auto-synthesized), Ground (user-defined), Federated (synced from master)."
      headerActions={headerActions}
      queryKey="groups"
      api={{
        list: (p) => groupsApi.list(p).then((d) => ({ items: d.groups })),
        create: (body, p) => groupsApi.create(body, p),
        update: groupsApi.update,
        delete: groupsApi.delete,
      }}
      emptyBody={() => ({
        name: "",
        kind: "ground",
        comment: "",
        criteria: [{ key: "namespace", value: "prod", op: "eq" }],
        members: [],
        learned_from: "",
        cfg_type: "user",
        policy_mode: "monitor",
        profile_mode: "monitor",
      })}
      toBody={(g) => ({
        name: g.name,
        kind: g.kind,
        comment: g.comment,
        criteria: g.criteria,
        members: g.members,
        learned_from: g.learned_from,
        cfg_type: g.cfg_type,
        policy_mode: g.policy_mode,
        profile_mode: g.profile_mode,
      })}
      columns={[
        { header: "Name", render: (g) => <Link to={g.id} className="font-medium text-[color:var(--color-primary)] hover:underline">{g.name}</Link> },
        { header: "Kind", render: (g) => g.kind },
        { header: "Network mode", render: (g) => g.policy_mode ?? "monitor" },
        { header: "Process mode", render: (g) => g.profile_mode ?? "monitor" },
        { header: "Criteria", render: (g) => g.criteria.length },
        { header: "Members", render: (g) => g.members?.length ?? 0 },
      ]}
    />
  );
}

function GroupModeBulkActions({ clusterId, onChanged }: { clusterId?: string; onChanged: () => void }) {
  const [dimension, setDimension] = useState<"policy" | "profile">("policy");
  const [from, setFrom] = useState<GroupMode>("discover");
  const [to, setTo] = useState<GroupMode>("monitor");
  const mut = useMutation({
    mutationFn: () => groupsApi.promote({ dimension, from, to }, { cluster_id: clusterId }),
    onSuccess: (res) => {
      toast.success(res.changed > 0 ? `Changed ${res.changed} group${res.changed === 1 ? "" : "s"}: ${res.from} to ${res.to}` : `No ${res.from} groups changed`);
      onChanged();
    },
    onError: () => toast.error("Failed to change group modes"),
  });
  const invalid = from === to;
  return (
    <div className="inline-flex flex-wrap items-center gap-1.5 rounded-md border border-border bg-card px-2 py-1.5">
      <select
        aria-label="Mode dimension"
        className="rounded border border-border bg-background px-1.5 py-1 text-xs capitalize"
        value={dimension}
        disabled={mut.isPending}
        onChange={(e) => setDimension(e.target.value as "policy" | "profile")}
      >
        <option value="policy">Network</option>
        <option value="profile">Process/File</option>
      </select>
      <select
        aria-label="From mode"
        className="rounded border border-border bg-background px-1.5 py-1 text-xs capitalize"
        value={from}
        disabled={mut.isPending}
        onChange={(e) => setFrom(e.target.value as GroupMode)}
      >
        {GROUP_MODES.map((mode) => <option key={mode} value={mode}>{mode}</option>)}
      </select>
      <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
      <select
        aria-label="To mode"
        className="rounded border border-border bg-background px-1.5 py-1 text-xs capitalize"
        value={to}
        disabled={mut.isPending}
        onChange={(e) => setTo(e.target.value as GroupMode)}
      >
        {GROUP_MODES.map((mode) => <option key={mode} value={mode}>{mode}</option>)}
      </select>
      <button
        type="button"
        disabled={invalid || mut.isPending}
        onClick={() => mut.mutate()}
        className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs hover:bg-accent disabled:opacity-40"
      >
        <ArrowUpDown className="h-3.5 w-3.5" /> Apply
      </button>
    </div>
  );
}
