import { useRef } from "react";
import { Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Download, Upload } from "lucide-react";
import { CrudPage } from "@/components/CrudPage";
import { groupsApi, type Group } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";

export function GroupsPage() {
  const { clusterId } = useCluster();
  const qc = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);

  const doExport = async () => {
    try {
      const yaml = await groupsApi.exportYaml({ cluster_id: clusterId });
      const blob = new Blob([yaml], { type: "application/x-yaml" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "constellation-groups.yaml";
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      toast.error("Failed to export groups");
    }
  };
  const doImport = async (file: File) => {
    try {
      const text = await file.text();
      const res = await groupsApi.importYaml(text, { cluster_id: clusterId });
      const errs = res.results.filter((r) => r.status === "error");
      if (errs.length) toast.warning(`Imported ${res.created} new, ${res.updated} updated; ${errs.length} failed`);
      else toast.success(`Imported ${res.created} new, ${res.updated} updated`);
      void qc.invalidateQueries({ queryKey: ["groups", clusterId] });
    } catch {
      toast.error("Failed to import groups (invalid bundle?)");
    }
  };

  const headerActions = (
    <>
      <input ref={fileRef} type="file" accept=".yaml,.yml,application/x-yaml,text/yaml" className="hidden"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) doImport(f); e.target.value = ""; }} />
      <button type="button" onClick={() => fileRef.current?.click()} className="inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-1.5 text-xs font-medium hover:bg-accent">
        <Upload className="h-3.5 w-3.5" /> Import
      </button>
      <button type="button" onClick={doExport} className="inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-1.5 text-xs font-medium hover:bg-accent">
        <Download className="h-3.5 w-3.5" /> Export
      </button>
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
