import { useState } from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { dpiGroupBindings, groupsApi, type DPISensorKind, type DPIGroupBinding, type Group } from "@/api/client";
import { useRouteSearchParams } from "@/lib/route-search";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { LoadingState, ErrorState } from "@/components/ui/states";
import { GroupPickerView } from "@/components/GroupPicker";

export function DPIGroupBindingFormPage({ kind }: { kind: DPISensorKind }) {
  const { id } = useParams({ strict: false });
  const [search] = useRouteSearchParams();
  const clusterId = id ?? search.get("cluster_id") ?? "";
  const label = kind === "dlp" ? "DLP rules" : "WAF/DPI signatures";
  const listPath = clusterId ? `/clusters/${encodeURIComponent(clusterId)}/${kind === "dlp" ? "runtime-dlp" : "runtime-signatures"}${search.size ? `?${search}` : ""}` : "/clusters";
  const groupsQ = useQuery({ queryKey: ["groups", clusterId], queryFn: () => groupsApi.list({ cluster_id: clusterId }), enabled: !!clusterId });
  const bindingsQ = useQuery({ queryKey: ["dpi-group-bindings"], queryFn: () => dpiGroupBindings.list(), enabled: !!clusterId });
  const loaded = !!groupsQ.data && !!bindingsQ.data;
  const error = groupsQ.isError || bindingsQ.isError;
  return <div className="space-y-6">
    <PageHeader title="Add group scope" description={`Configure which group's workloads are inspected by ${label}. Saving scope does not confirm detector deployment.`}
      backLink={<Link to="." href={listPath} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> {label}</Link>} />
    {!clusterId ? <ErrorState title="Select a cluster to configure group scope." />
      : !loaded && error ? <ErrorState title="Groups and detector scope could not be loaded." action={<Button onClick={() => { void groupsQ.refetch(); void bindingsQ.refetch(); }}>Retry</Button>} />
      : !loaded ? <LoadingState label="Loading groups and scope…" />
      : <>
        {error && <p role="alert" className="text-sm text-status-error">Could not refresh group scope. Your draft is preserved. Retry before saving. <Button variant="outline" onClick={() => { void groupsQ.refetch(); void bindingsQ.refetch(); }}>Retry</Button></p>}
        <BindingEditor key={`${clusterId}:${kind}`} kind={kind} groups={groupsQ.data!.groups} bindings={bindingsQ.data!} listPath={listPath} refreshFailed={error} />
      </>}
  </div>;
}

function BindingEditor({ kind, groups, bindings, listPath, refreshFailed }: { kind: DPISensorKind; groups: Group[]; bindings: DPIGroupBinding[]; listPath: string; refreshFailed: boolean }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [selected, setSelected] = useState("");
  const selectedGroup = groups.find((group) => group.name === selected);
  const alreadyBound = bindings.some((binding) => binding.group_id === selectedGroup?.id && binding.sensor_kind === kind);
  const valid = !!selectedGroup && !alreadyBound && !refreshFailed;
  const save = useMutation({
    mutationFn: () => {
      if (!valid || !selectedGroup) throw new Error("Select an unscoped group");
      return dpiGroupBindings.bind({ group_id: selectedGroup.id, sensor_kind: kind });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["dpi-group-bindings"] });
      void qc.invalidateQueries({ queryKey: ["group-usage"] });
      navigate({ href: listPath });
    },
  });
  return <Card title="Group scope" description="Choose an existing group from this cluster. Rules remain shared across all configured groups for this detector.">
    <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); if (valid && !save.isPending) save.mutate(); }}>
      <fieldset disabled={save.isPending} className="space-y-5">
        <div><label htmlFor="dpi-scope-group" className="mb-2 block text-sm font-medium">Group</label><GroupPickerView inputId="dpi-scope-group" testId="dpi-scope-group" value={selected} onChange={setSelected} groups={groups} allowExternal={false} placeholder="Search groups" /></div>
        {selected && !selectedGroup && <p className="text-sm text-muted-foreground">Select an existing group from this cluster.</p>}
        {alreadyBound && <p className="text-sm text-muted-foreground">This group is already in the detector's scope.</p>}
        {save.isError && <p role="alert" className="text-sm text-status-error">Could not save group scope. Your draft is preserved. Try again.</p>}
        <div className="flex items-center gap-3"><Button type="submit" size="lg" disabled={!valid || save.isPending}>{save.isPending ? "Saving…" : "Save scope"}</Button><Button type="button" variant="ghost" size="lg" onClick={() => navigate({ href: listPath })}>Cancel</Button></div>
      </fieldset>
    </form>
  </Card>;
}
