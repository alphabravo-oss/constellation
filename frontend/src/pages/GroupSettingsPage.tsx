import { useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { policies, type GroupMode } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, Select } from "@/components/ui/form";
import { ErrorState, LoadingState } from "@/components/ui/states";

const MODES: GroupMode[] = ["discover", "monitor", "protect"];
type Defaults = Awaited<ReturnType<typeof policies.serviceModeDefaults>>;

export function GroupSettingsPage() {
  const { clusterId, isLoading, cluster, error } = useCluster();
  const listPath = clusterId ? `/clusters/${clusterId}/groups` : "/groups";
  return <div className="space-y-6" data-testid="group-settings-page">
    <PageHeader title="Group settings" description="Choose the network and process/file modes that newly discovered service groups start in."
      backLink={<Link to="." href={listPath} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Groups</Link>} />
    {isLoading ? <LoadingState label="Loading cluster…" /> : !clusterId || (error && !cluster) ? <ErrorState title="Select an available cluster to manage group settings." />
      : <GroupSettingsLoader key={clusterId} clusterId={clusterId} listPath={listPath} />}
  </div>;
}

function GroupSettingsLoader({ clusterId, listPath }: { clusterId: string; listPath: string }) {
  const q = useQuery({ queryKey: ["service-mode-defaults", clusterId], queryFn: () => policies.serviceModeDefaults({ cluster_id: clusterId }), gcTime: 0 });
  const validResponse = q.isSuccess && q.data.cluster_id === clusterId && MODES.includes(q.data.policy_mode as GroupMode) && MODES.includes(q.data.profile_mode as GroupMode);
  const [initial, setInitial] = useState<Defaults | null>(null);
  if (!initial && validResponse) setInitial(q.data);
  const saved = initial ?? (validResponse ? q.data : undefined);
  if (q.isPending && !saved) return <LoadingState label="Loading group settings…" />;
  if (!saved) return <ErrorState title="Group settings could not be loaded for the selected cluster." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />;
  return <>
    {!validResponse && <ErrorState title="Could not refresh group settings. Your draft is preserved; retry before saving." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />}
    <GroupSettingsEditor clusterId={clusterId} listPath={listPath} initial={saved} unavailable={!validResponse} />
  </>;
}

function GroupSettingsEditor({ clusterId, listPath, initial, unavailable }: { clusterId: string; listPath: string; initial: Defaults; unavailable: boolean }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [networkMode, setNetworkMode] = useState(initial.policy_mode);
  const [profileMode, setProfileMode] = useState(initial.profile_mode);
  const save = useMutation({
    mutationFn: async () => {
      const response = await policies.updateServiceModeDefaults({ policy_mode: networkMode, profile_mode: profileMode }, { cluster_id: clusterId });
      if (response.cluster_id !== clusterId) throw new Error("Unexpected cluster response");
      return response;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["service-mode-defaults", clusterId] });
      void qc.invalidateQueries({ queryKey: ["dashboard", clusterId] });
      void qc.invalidateQueries({ queryKey: ["security-risk", clusterId] });
      void navigate({ href: listPath });
    },
  });
  return <Card title="Default modes for new service groups" description="Discover learns behavior, Monitor reports violations, and Protect enforces policy. These defaults apply to new groups; change existing groups through their own configuration.">
    <form className="space-y-6" onSubmit={(event) => { event.preventDefault(); if (!unavailable && !save.isPending) save.mutate(); }}>
      <fieldset disabled={save.isPending} className="space-y-6">
        <div className="grid gap-5 sm:grid-cols-2">
          <Field label="Default network mode" htmlFor="default-network-mode"><Select id="default-network-mode" value={networkMode} onChange={(event) => setNetworkMode(event.target.value)}>{MODES.map((mode) => <option key={mode} value={mode}>{mode}</option>)}</Select></Field>
          <Field label="Default process/file mode" htmlFor="default-profile-mode"><Select id="default-profile-mode" value={profileMode} onChange={(event) => setProfileMode(event.target.value)}>{MODES.map((mode) => <option key={mode} value={mode}>{mode}</option>)}</Select></Field>
        </div>
        {save.isError && <p role="alert" className="text-sm text-status-error">Could not save group settings. Your draft is preserved. Try again.</p>}
        <div className="flex gap-3"><Button type="submit" variant="primary" size="lg" disabled={unavailable || save.isPending}>{save.isPending ? "Saving…" : "Save"}</Button><Button type="button" variant="ghost" size="lg" onClick={() => void navigate({ href: listPath })}>Cancel</Button></div>
      </fieldset>
    </form>
  </Card>;
}
