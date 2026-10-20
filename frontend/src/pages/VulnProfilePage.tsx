import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { ImportExportButtons } from "@/components/ImportExportButtons";
import { vulnProfiles } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { TextInput } from "@/components/ui/form";
import { PageHeader } from "@/components/ui/page";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { useRouteSearchParams } from "@/lib/route-search";

export function VulnProfilePage() {
  const { clusterId, isLoading, cluster, error } = useCluster();
  const qc = useQueryClient();
  const [tab, setTab] = useTabParam("tab", "profiles");
  const [params, setParams] = useRouteSearchParams();
  const search = params.get("q") ?? "";
  const [transferError, setTransferError] = useState<string | null>(null);
  const [transferResult, setTransferResult] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["vuln-profiles", clusterId], queryFn: () => vulnProfiles.list({ cluster_id: clusterId }), enabled: Boolean(clusterId) && !isLoading && !(error && !cluster) });
  const listPath = clusterId ? `/clusters/${clusterId}/vuln-profiles` : "/vuln-profiles";
  const invalidate = () => { void qc.invalidateQueries({ queryKey: ["vuln-profiles", clusterId] }); void qc.invalidateQueries({ queryKey: ["vuln-profile-editor", clusterId] }); };
  const del = useMutation({ mutationFn: (id: string) => vulnProfiles.delete(id), onSuccess: () => { toast.success("Vulnerability profile deleted"); invalidate(); } });
  const profiles = q.data?.profiles ?? [];
  const active = profiles.filter((profile) => profile.active);
  const activeWithoutRules = active.filter((profile) => !profile.entries?.length).length;
  const entries = profiles.flatMap((profile) => profile.entries ?? []);
  const filtered = profiles.filter((profile) => [profile.name, profile.description, profile.active ? "active" : "inactive", JSON.stringify(profile.entries), JSON.stringify(profile.domain_scope)].join(" ").toLowerCase().includes(search.trim().toLowerCase()));
  return <div className="space-y-6" data-testid="vuln-profiles-page" data-cluster-id={clusterId ?? ""}>
    <PageHeader title="Vulnerability profiles" description="Choose which vulnerabilities are acknowledged, deferred for a grace period, or escalated when scans complete."
      actions={<div className="flex gap-2"><Button variant="outline" disabled={!clusterId || q.isFetching} onClick={() => void q.refetch()}><RefreshCw className="h-4 w-4" /> Refresh</Button>{clusterId && <Button asChild variant="primary"><Link to="." href={`${listPath}/new`}><Plus className="h-4 w-4" /> Add profile</Link></Button>}</div>} />
    {isLoading ? <LoadingState label="Loading cluster…" /> : !clusterId || (error && !cluster) ? <ErrorState title="Select an available cluster to manage vulnerability profiles." />
      : q.isPending ? <LoadingState label="Loading vulnerability profiles…" /> : q.isError ? <ErrorState title="Vulnerability profiles could not be loaded. Existing configuration has not changed." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />
      : <>
        <VerdictBanner status={activeWithoutRules ? "degraded" : active.length ? "ok" : "info"}
          title={activeWithoutRules ? `${activeWithoutRules} active profile${activeWithoutRules === 1 ? " has" : "s have"} no rules` : active.length ? `${active.length} active vulnerability profile${active.length === 1 ? "" : "s"}` : "No vulnerability profiles are active"}
          detail="Active profiles evaluate ordered matching rules on future scan completion. The list includes profiles for this cluster and shared organization profiles." numbers={[{ label: "Visible profiles", value: profiles.length }, { label: "Active profiles", value: active.length }, { label: "Suppression rules", value: entries.filter((entry) => entry.action === "suppress").length }, { label: "Escalation rules", value: entries.filter((entry) => entry.action === "escalate").length }]} />
        
        <Tabs value={tab === "transfer" ? "transfer" : "profiles"} onValueChange={setTab} items={[
          { value: "profiles", label: "Profiles", count: profiles.length, content: <Card title="Vulnerability profiles" description="Search profiles, vulnerability expressions, images, and scope. Open a profile to edit its ordered rules.">
            <TextInput aria-label="Search vulnerability profiles" className="mb-4" value={search} placeholder="Search profiles, rules, or scope…" onChange={(event) => setParams((current) => { if (event.target.value) current.set("q", event.target.value); else current.delete("q"); return current; }, { replace: true })} />
            {del.isError && <p role="alert" className="mb-4 text-sm text-status-error">Could not delete this vulnerability profile. Its configuration is preserved; try again.</p>}
            <DataTable rows={filtered} rowKey={(profile) => profile.id} preferencesKey="vulnerability-profiles" exportFileName="constellation-vulnerability-profiles.csv" defaultSort={{ id: "name", dir: "asc" }} testId="vuln-profiles-table" columns={[
              { id: "name", kind: "name", grow: true, minSize: 200, header: "Name", hideable: false, cell: (profile) => <Link to="." href={`${listPath}/${profile.id}/edit`} className="font-medium text-primary hover:underline">{profile.name}</Link>, exportValue: (profile) => profile.name, sort: (a, b) => a.name.localeCompare(b.name) },
              { id: "status", kind: "status", header: "Status", cell: (profile) => profile.active ? "Active" : "Inactive", sort: (a, b) => Number(a.active) - Number(b.active) },
              { id: "rules", kind: "count", header: "Rules", numeric: true, cell: (profile) => profile.entries?.length ?? 0, sort: (a, b) => (a.entries?.length ?? 0) - (b.entries?.length ?? 0) },
              { id: "scope", kind: "text", size: 200, minSize: 176, wrap: true, header: "Scope", cell: (profile) => { const scope = profile.domain_scope; return scope?.clusters?.length || scope?.namespaces?.length ? [...(scope.clusters ?? []), ...(scope.namespaces ?? [])].join(", ") : "All domains within profile scope"; } },
              { id: "description", kind: "text", grow: true, minSize: 200, wrap: true, header: "Description", cell: (profile) => profile.description || "—" },
              { id: "actions", kind: "actions", size: 128, minSize: 120, header: "Actions", hideable: false, exportable: false, cell: (profile) => <div className="flex gap-2"><Button asChild variant="ghost" size="sm"><Link to="." href={`${listPath}/${profile.id}/edit`} aria-label={`Edit ${profile.name}`}><Pencil className="h-3.5 w-3.5" /> Edit</Link></Button><Button variant="ghost" size="sm" aria-label={`Delete ${profile.name}`} disabled={del.isPending} onClick={() => { if (window.confirm(`Delete vulnerability profile “${profile.name}”? Future scans will no longer use its rules.`)) del.mutate(profile.id); }}><Trash2 className="h-3.5 w-3.5" /></Button></div> },
            ]} emptyState={<EmptyState title={search ? "No matching profiles" : "No vulnerability profiles yet"} hint={search ? "Try another name, vulnerability expression, or scope." : "Add a profile to define how matching vulnerabilities are handled."} />} />
          </Card> },
          { value: "transfer", label: "Import / export", content: <Card title="Import or export vulnerability profiles" description="Transfer profile configuration, ordered rules, and scope using a YAML bundle.">
            <div className="flex flex-wrap gap-3"><ImportExportButtons filename="constellation-vuln-profiles.yaml" label="profiles"
              exportYaml={async () => { setTransferError(null); setTransferResult(null); try { return await vulnProfiles.exportYaml({ cluster_id: clusterId }); } catch (err) { setTransferError("Could not export vulnerability profiles. Try again."); throw err; } }}
              importYaml={async (text) => { setTransferError(null); setTransferResult(null); try { const result = await vulnProfiles.importYaml(text, { cluster_id: clusterId }); const failed = result.results.filter((item) => item.status === "error").length; setTransferResult(`Imported ${result.created} new and ${result.updated} updated profiles${failed ? `; ${failed} failed. Review the bundle and retry failed entries.` : "."}`); return result; } catch (err) { setTransferError("Could not import vulnerability profiles. Check the YAML bundle and try again."); throw err; } }} onImported={invalidate} /></div>
            {transferError && <p role="alert" className="mt-4 text-sm text-status-error">{transferError}</p>}{transferResult && <p role="status" className="mt-4 text-sm text-muted-foreground">{transferResult}</p>}
          </Card> },
        ]} />
      </>}
  </div>;
}
