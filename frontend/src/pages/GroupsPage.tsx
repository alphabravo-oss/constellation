import { Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { CrudPage } from "@/components/CrudPage";
import { ImportExportButtons } from "@/components/ImportExportButtons";
import { groupsApi, type Group } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";

export function GroupsPage() {
  const { clusterId } = useCluster();
  const qc = useQueryClient();

  const headerActions = (
    <ImportExportButtons
      filename="constellation-groups.yaml"
      label="groups"
      exportYaml={() => groupsApi.exportYaml({ cluster_id: clusterId })}
      importYaml={(text) => groupsApi.importYaml(text, { cluster_id: clusterId })}
      onImported={() => void qc.invalidateQueries({ queryKey: ["groups", clusterId] })}
    />
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
